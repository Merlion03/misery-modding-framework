// MiseryRuntime -- INTERNAL. Ownership of loaded mod assets, integrated with
// Unreal's garbage collector.
//
// MECHANISM AND WHY THIS ONE.
// UE's canonical "this object is a GC root" marker is
// EInternalObjectFlags::RootSet (1<<30, ObjectMacros.h:624). It is TEMPTING to
// conclude that setting that bit is the whole mechanism, because
// UObject::AddToRoot() is FORCEINLINE and appears to do exactly that
// (UObjectBaseUtility.h:196-199 -> UObjectArray.h:287-290).
//
// THAT IS FALSE, AND WE PROVED IT (LOG-0079): an asset with the bit set by a raw
// write was still collected ~60 s later. The real chain is
//   AddToRoot -> SetRootSet -> ThisThreadAtomicallySetFlag, which DISPATCHES on
//   EInternalObjectFlags_RootFlags (UObjectArray.h:205-210)
//   -> FUObjectItem::SetRootFlags -- an OUT-OF-LINE COREUOBJECT_API function
//      (UObjectArray.h:347, GarbageCollection.cpp:590)
// which, under GRootsCritical, (a) registers the object's index in the GRoots
// TSet, (b) sets the flag, and (c) issues a reachability barrier when incremental
// GC is pending. UE 5.4's collector marks roots from an array built out of GRoots
// (GarbageCollection.cpp:4166-4179), NOT by scanning the bit -- so a raw write
// sets a bit nobody reads and skips both the registration and the barrier.
//
// Therefore this store CALLS the engine's own SetRootFlags/ClearRootFlags and
// reimplements none of GRoots, GRootsCritical, the bit, or the barrier.
//
// Why this rather than FGCObject for an injected runtime: an FGCObject registers
// a C++ object whose vtable lives in OUR module and the collector calls back into
// it on every pass, so tearing the module down while registered kills the
// process. Going through the engine's root path leaves NO pointer into our memory
// acting as a GC reference source; the worst failure is a leaked root, not a
// crash. It is also process-global (unaffected by world/map transitions), needs
// no Blueprint VM, no per-asset special cases, and no disabling of GC. This is
// not a claim that FGCObject is unfit in general -- a resident production runtime
// may later be compared against a centralized FGCObject holder.
//
// The store adds the bookkeeping the engine call alone lacks: explicit ownership,
// a refcount so duplicate Acquire is well defined, tolerant Release, and
// ReleaseAll on shutdown so no runtime-owned root outlives this module.
#ifndef MISERY_RUNTIMEASSETSTORE_H
#define MISERY_RUNTIMEASSETSTORE_H

#include <cstdint>
#include <mutex>
#include <vector>

namespace Misery {
namespace Internal {

// EInternalObjectFlags::RootSet -- ObjectMacros.h:624
static constexpr int32_t kRootSetFlag = 1 << 30;
// FUObjectItem: UObjectBase* Object @0, int32 Flags @8 (re-confirmed by the
// 'lock cmpxchg dword ptr [rbx+8]' inside the engine's own ClearRootFlags).
static constexpr int kUObjectItemFlagsOffset = 8;

// The engine's own root-registration functions, resolved per run and handed in.
//   bool __fastcall FUObjectItem::SetRootFlags(FUObjectItem* this, EInternalObjectFlags)
//   bool __fastcall FUObjectItem::ClearRootFlags(FUObjectItem* this, EInternalObjectFlags)
// We CALL these; we never reimplement GRoots / GRootsCritical / the RootSet bit /
// the reachability barrier, all of which live inside them.
using RootFlagsFn = bool(__fastcall*)(void* item, int32_t flags);

class RuntimeAssetStore {
 public:
  // Must be called once before any Acquire; without it the store refuses to own.
  void SetRootPath(RootFlagsFn set_fn, RootFlagsFn clear_fn) {
    std::lock_guard<std::mutex> lk(mtx_);
    set_root_flags_ = set_fn;
    clear_root_flags_ = clear_fn;
  }
  bool HasRootPath() const { return set_root_flags_ && clear_root_flags_; }

  struct Entry {
    const void* asset = nullptr;     // UObject*
    void* item = nullptr;            // its FUObjectItem*
    uint32_t refcount = 0;
    uint64_t handle = 0;
  };

  // Acquire: set RootSet (idempotent at the flag level) and refcount here.
  // Returns the handle, or 0 if the inputs are unusable.
  uint64_t Acquire(const void* asset, void* item) {
    if (!asset || !item) return 0;
    if (!set_root_flags_ || !clear_root_flags_) return 0;  // fail closed
    std::lock_guard<std::mutex> lk(mtx_);
    for (Entry& e : entries_) {
      if (e.asset == asset) { ++e.refcount; return e.handle; }   // duplicate acquire
    }
    Entry e;
    e.asset = asset;
    e.item = item;
    e.refcount = 1;
    e.handle = ++next_handle_;
    SetRoot(item, true);
    entries_.push_back(e);
    return e.handle;
  }

  // Release one reference. Unknown/stale handles are a tolerated no-op (false).
  bool Release(uint64_t handle) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (size_t i = 0; i < entries_.size(); ++i) {
      if (entries_[i].handle != handle) continue;
      if (--entries_[i].refcount == 0) {
        SetRoot(entries_[i].item, false);      // normal GC eligibility restored
        entries_.erase(entries_.begin() + static_cast<long long>(i));
      }
      return true;
    }
    return false;
  }

  // Shutdown contract: clear EVERY root flag we set, so no runtime-owned GC root
  // can outlive this module. Returns how many were released.
  uint32_t ReleaseAll() {
    std::lock_guard<std::mutex> lk(mtx_);
    uint32_t n = 0;
    for (Entry& e : entries_) { SetRoot(e.item, false); ++n; }
    entries_.clear();
    return n;
  }

  uint32_t OwnedCount() {
    std::lock_guard<std::mutex> lk(mtx_);
    return static_cast<uint32_t>(entries_.size());
  }

  bool IsRooted(const void* asset) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (Entry& e : entries_) {
      if (e.asset == asset) return ReadFlags(e.item) & kRootSetFlag;
    }
    return false;
  }

 private:
  static volatile long* FlagsPtr(void* item) {
    return reinterpret_cast<volatile long*>(
        reinterpret_cast<unsigned char*>(item) + kUObjectItemFlagsOffset);
  }
  static int32_t ReadFlags(void* item) {
    return static_cast<int32_t>(*FlagsPtr(item));
  }
  // Delegate to the engine's own root path so GRoots registration and the
  // incremental-reachability barrier happen exactly as UE does them.
  void SetRoot(void* item, bool on) {
    if (on) { if (set_root_flags_) set_root_flags_(item, kRootSetFlag); }
    else    { if (clear_root_flags_) clear_root_flags_(item, kRootSetFlag); }
  }

  RootFlagsFn set_root_flags_ = nullptr;
  RootFlagsFn clear_root_flags_ = nullptr;
  std::mutex mtx_;
  std::vector<Entry> entries_;
  uint64_t next_handle_ = 0;
};

}  // namespace Internal
}  // namespace Misery

#endif  // MISERY_RUNTIMEASSETSTORE_H
