// MiseryRuntime -- INTERNAL. Ownership of loaded mod assets, integrated with
// Unreal's garbage collector.
//
// MECHANISM AND WHY THIS ONE.
// UE's canonical "this object is a GC root" marker is
// EInternalObjectFlags::RootSet (1<<30, ObjectMacros.h:624 -- "Object will not be
// garbage collected, even if unreferenced"). UObject::AddToRoot() is FORCEINLINE
// and does exactly one thing (UObjectBaseUtility.h:196-199):
//     GUObjectArray.IndexToObject(InternalIndex)->SetRootSet();
// and SetRootSet() is an atomic set of that flag on the object's FUObjectItem
// (UObjectArray.h:287-294). So the reference is a single atomic bit living in
// ENGINE-owned memory.
//
// That property is why this mechanism was chosen over FGCObject/
// AddReferencedObjects for an injected runtime: an FGCObject registers a C++
// object whose vtable lives in OUR module, and the collector calls back into it
// on every GC pass -- if the module is ever torn down while registered, GC calls
// into unmapped memory and the process dies. With the root-set flag there is NO
// pointer into our memory acting as a GC reference source at all: the worst
// possible failure is that a flag stays set and an object leaks, never a crash.
// It is also process-global, so it is unaffected by world/map transitions, needs
// no Blueprint VM, no per-asset special cases, and no disabling of GC.
//
// The store adds the bookkeeping the raw flag lacks: explicit ownership, refcount
// so duplicate Acquire is well defined, tolerant Release, and -- critically --
// ReleaseAll on shutdown so no root flag outlives the runtime.
#ifndef MISERY_RUNTIMEASSETSTORE_H
#define MISERY_RUNTIMEASSETSTORE_H

#include <cstdint>
#include <mutex>
#include <vector>

namespace Misery {
namespace Internal {

// EInternalObjectFlags::RootSet -- ObjectMacros.h:624
static constexpr int32_t kRootSetFlag = 1 << 30;
// FUObjectItem: UObjectBase* Object @0 (ERI-verified), int32 Flags @8 (declared
// immediately after an 8-byte pointer), sizeof 0x18 (ERI-verified).
static constexpr int kUObjectItemFlagsOffset = 8;

class RuntimeAssetStore {
 public:
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
  // Atomic set/clear, mirroring FUObjectItem::ThisThreadAtomicallySet/ClearedFlag.
  static void SetRoot(void* item, bool on) {
    volatile long* p = FlagsPtr(item);
    long old, want;
    do {
      old = *p;
      want = on ? (old | kRootSetFlag) : (old & ~kRootSetFlag);
      if (old == want) return;
    } while (_InterlockedCompareExchange(p, want, old) != old);
  }

  std::mutex mtx_;
  std::vector<Entry> entries_;
  uint64_t next_handle_ = 0;
};

}  // namespace Internal
}  // namespace Misery

#endif  // MISERY_RUNTIMEASSETSTORE_H
