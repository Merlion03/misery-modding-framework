// BridgeCore.h -- the native implementation of the Stage 4.5 ownership model.
//
// WHAT THIS IS
// ------------
// tools/modplatform is the REFERENCE implementation of these semantics: it is
// what the Stage 4.5 unit tests and both acceptances ran against, and it is
// what proved the model before any C++ existed. This is the same model in C++,
// behind MiseryBridge.h, and a host-side test asserts the two agree on the
// cases that decide the lifecycle guarantee.
//
// ONE LEDGER, NOT N REGISTRIES
// ----------------------------
// Every resource a mod acquires -- a subscription, an input action, a service,
// a published event, an item row -- is one entry in ONE array, threaded onto
// one intrusive list per mod. The design panel's adversarial judge named the
// alternative as a real flaw in one of the candidate designs: two ownership
// structures that can in principle disagree. They cannot disagree here because
// there is only one.
//
// REVOCATION IS ONE INCREMENT
// ---------------------------
// A mod record carries an epoch. Every slot records the epoch it was allocated
// under. Resolving a handle compares the two, so `record.epoch++` revokes every
// subscription, action, service and binding the mod owns -- simultaneously, in
// O(1), with no scan for stragglers anywhere in the process.
//
// That is what makes "no callback may target unloaded mod code" hold in the
// case that actually matters: a dispatch loop that captured its handler list
// BEFORE the unload began re-resolves each handle immediately before invoking
// it, and every one of them now fails to resolve. There is no window, because
// the check is on the calling side of every individual invocation rather than
// at the top of the loop.
//
// HANDLES ARE NOT ADDRESSES
// -------------------------
//      kind:8 | slot:24 | tag:32
// The tag is drawn per allocation and never reused for a slot, so a stale
// handle is DETECTED rather than dereferenced. Mod slots are never recycled at
// all: an id, once loaded, owns its slot for the process lifetime, which keeps
// diagnostics stable across an unload/reload cycle and removes mod-handle ABA
// entirely. A few bytes per mod ever loaded is a cheap price for never having
// to reason about it.
#pragma once

#include <stdint.h>

#include <atomic>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "../Public/MiseryBridge.h"

namespace misery {
namespace bridge {

// Handle kinds. The kind is in the handle so a mismatched handle is refused by
// TYPE before anything looks at the slot it names.
enum HandleKind : uint8_t {
  kKindNone = 0,
  kKindMod = 1,
  kKindEventDeclaration = 2,
  kKindSubscription = 3,
  kKindInputAction = 4,
  kKindService = 5,
  kKindServiceBinding = 6,
  kKindItem = 7,
  kKindCommand = 8,
  kKindSettingsSchema = 9,
};

// What a mod owns, for diagnostics. Mirrors the reference implementation's
// Releasable.kind strings so the two reports can be compared.
inline const char* KindName(uint8_t kind) {
  switch (kind) {
    case kKindMod: return "mod";
    case kKindEventDeclaration: return "event_declaration";
    case kKindSubscription: return "event_handler";
    case kKindInputAction: return "input_action";
    case kKindService: return "service";
    case kKindServiceBinding: return "service_binding";
    case kKindItem: return "item";
    case kKindCommand: return "console_command";
    case kKindSettingsSchema: return "settings_schema";
    default: return "unknown";
  }
}

inline MbHandle MakeHandle(uint8_t kind, uint32_t slot, uint32_t tag) {
  return (static_cast<uint64_t>(kind) << 56) |
         (static_cast<uint64_t>(slot & 0xFFFFFFu) << 32) |
         static_cast<uint64_t>(tag);
}

// A per-thread arena for OUT strings. The ABI rule is "valid until your next
// call on the same thread", and this is what implements it: each call resets
// the arena, so a caller that keeps a pointer across a call gets a defined,
// reproducible failure rather than an intermittent one.
class StringArena {
 public:
  void Reset() { used_ = 0; }

  MbStr Put(const std::string& text) {
    if (used_ + text.size() + 1 > kCapacity) {
      // Refusing to truncate silently: a half message is a misleading message.
      return MbStr{"<detail too long>", 17};
    }
    char* out = buffer_ + used_;
    memcpy(out, text.data(), text.size());
    out[text.size()] = '\0';
    used_ += text.size() + 1;
    return MbStr{out, static_cast<int32_t>(text.size())};
  }

 private:
  static const size_t kCapacity = 64 * 1024;
  char buffer_[kCapacity];
  size_t used_ = 0;
};

StringArena& ThreadArena();

// Fills an MbError and returns a non-zero status. Every failing path in the
// bridge goes through here, so no failure can leave the out-parameter stale.
inline MbStatus Fail(MbError* out_error, int32_t subsystem, int32_t code,
                     const std::string& detail, const std::string& mod_id = "") {
  if (out_error != nullptr) {
    out_error->subsystem = subsystem;
    out_error->code = code;
    out_error->detail = ThreadArena().Put(detail);
    out_error->mod_id = mod_id.empty() ? MbStr{"", 0} : ThreadArena().Put(mod_id);
  }
  return static_cast<MbStatus>((subsystem << 16) | code);
}

inline void ClearError(MbError* out_error) {
  if (out_error != nullptr) {
    out_error->subsystem = 0;
    out_error->code = 0;
    out_error->detail = MbStr{"", 0};
    out_error->mod_id = MbStr{"", 0};
  }
}

typedef void (*ReleaseFn)(void* body, uint64_t payload);

struct Slot {
  uint32_t tag = 0;              // 0 means free
  uint8_t kind = kKindNone;
  bool alive = false;
  bool released = false;
  uint32_t owner_slot = 0;       // index into mods_
  uint32_t owner_epoch = 0;      // the epoch this was allocated under
  ReleaseFn release = nullptr;
  void* body = nullptr;
  uint64_t payload = 0;
  uint32_t next_in_mod = kNone;  // intrusive list, most-recent-first
  std::string key;               // for diagnostics

  static const uint32_t kNone = 0xFFFFFFFFu;
};

struct ModRecord {
  std::string mod_id;
  uint32_t slot = 0;
  uint32_t epoch = 1;            // bumped on every unload; 0 is never valid
  int32_t state = MB_MODSTATE_DISCOVERED;
  uint32_t ledger_head = Slot::kNone;
  uint32_t owned_count = 0;
  uint32_t released_count = 0;
  uint32_t revoked_count = 0;
  uint32_t fault_count = 0;
  int32_t active_frames = 0;     // dispatch depth into this mod's code
  uint64_t granted_caps = 0;
  std::string last_error;
  std::vector<std::string> released_keys;   // teardown evidence
  std::vector<std::string> fault_keys;
};

// The whole platform state. One instance per process.
class Core {
 public:
  Core() {}

  // ---- mods ------------------------------------------------------------
  //
  // A mod slot is allocated once per mod_id, EVER. A reload reuses the same
  // slot with a fresh epoch, which is what makes "reload A -> new context,
  // works again" observable as a state transition rather than as a new
  // identity.
  ModRecord* FindMod(const std::string& mod_id) {
    auto it = by_id_.find(mod_id);
    return it == by_id_.end() ? nullptr : &mods_[it->second];
  }

  ModRecord* FindModBySlot(uint32_t slot) {
    return slot < mods_.size() ? &mods_[slot] : nullptr;
  }

  ModRecord& EnsureMod(const std::string& mod_id) {
    auto it = by_id_.find(mod_id);
    if (it != by_id_.end()) {
      return mods_[it->second];
    }
    ModRecord record;
    record.mod_id = mod_id;
    record.slot = static_cast<uint32_t>(mods_.size());
    by_id_[mod_id] = record.slot;
    mods_.push_back(record);
    return mods_.back();
  }

  MbHandle ModHandle(const ModRecord& record) const {
    return MakeHandle(kKindMod, record.slot, record.epoch);
  }

  // Resolve a mod handle. Fails when the epoch has moved, which is what makes
  // a handle held across an unload safe rather than dangerous.
  ModRecord* ResolveMod(MbHandle handle) {
    if (MB_HANDLE_KIND(handle) != kKindMod) {
      return nullptr;
    }
    uint32_t slot = MB_HANDLE_SLOT(handle);
    if (slot >= mods_.size()) {
      return nullptr;
    }
    ModRecord& record = mods_[slot];
    if (record.epoch != MB_HANDLE_TAG(handle)) {
      return nullptr;
    }
    return &record;
  }

  // ---- resources -------------------------------------------------------
  MbHandle Acquire(ModRecord& mod, uint8_t kind, const std::string& key,
                   ReleaseFn release, void* body, uint64_t payload) {
    uint32_t index = AllocateSlot();
    Slot& slot = slots_[index];
    slot.tag = NextTag();
    slot.kind = kind;
    slot.alive = true;
    slot.released = false;
    slot.owner_slot = mod.slot;
    slot.owner_epoch = mod.epoch;
    slot.release = release;
    slot.body = body;
    slot.payload = payload;
    slot.key = key;
    slot.next_in_mod = mod.ledger_head;
    mod.ledger_head = index;
    mod.owned_count += 1;
    return MakeHandle(kind, index, slot.tag);
  }

  // THE function every dispatch site calls immediately before invoking. Not at
  // the top of a loop -- immediately before each individual call.
  Slot* Resolve(MbHandle handle, uint8_t expect_kind) {
    if (handle == MB_INVALID_HANDLE) {
      return nullptr;
    }
    if (expect_kind != kKindNone && MB_HANDLE_KIND(handle) != expect_kind) {
      return nullptr;
    }
    uint32_t index = MB_HANDLE_SLOT(handle);
    if (index >= slots_.size()) {
      return nullptr;
    }
    Slot& slot = slots_[index];
    if (!slot.alive || slot.tag != MB_HANDLE_TAG(handle)) {
      return nullptr;
    }
    ModRecord* owner = FindModBySlot(slot.owner_slot);
    if (owner == nullptr || owner->epoch != slot.owner_epoch) {
      return nullptr;   // the owning mod was unloaded: revoked, retroactively
    }
    return &slot;
  }

  bool ReleaseOne(MbHandle handle) {
    Slot* slot = Resolve(handle, kKindNone);
    if (slot == nullptr) {
      return false;
    }
    ReleaseSlot(*slot);
    ModRecord* owner = FindModBySlot(slot->owner_slot);
    if (owner != nullptr) {
      owner->released_count += 1;
    }
    return true;
  }

  // ---- teardown --------------------------------------------------------
  //
  // Revoke FIRST, then release. The order is the whole point: anything the
  // release functions themselves do -- raising an event, unregistering an item,
  // touching a subsystem that notifies -- can no longer reach this mod's code.
  // Releasing first would leave a window in which a mod's handler runs while
  // its resources are half gone, which is worse than either end of it.
  struct TeardownReport {
    uint32_t revoked = 0;
    uint32_t released = 0;
    uint32_t faults = 0;
    uint32_t total = 0;
    bool reentered = false;
  };

  TeardownReport Dispose(ModRecord& mod) {
    TeardownReport report;
    if (mod.state == MB_MODSTATE_UNLOADING) {
      report.reentered = true;
      return report;
    }
    mod.state = MB_MODSTATE_UNLOADING;

    // ONE increment revokes everything this mod owns.
    mod.epoch += 1;
    if (mod.epoch == 0) {
      mod.epoch = 1;  // 0 is never a valid epoch
    }
    mod.released_keys.clear();
    mod.fault_keys.clear();

    // Walk the intrusive list from the head, which is the MOST RECENTLY
    // acquired: reverse acquisition order, because a later resource may depend
    // on an earlier one and releasing the earliest first is how a teardown
    // breaks.
    uint32_t index = mod.ledger_head;
    while (index != Slot::kNone) {
      Slot& slot = slots_[index];
      uint32_t next = slot.next_in_mod;
      report.total += 1;
      if (slot.alive && !slot.released) {
        report.revoked += 1;
        if (ReleaseSlot(slot)) {
          report.released += 1;
          mod.released_keys.push_back(std::string(KindName(slot.kind)) + "/" +
                                      slot.key);
        } else {
          report.faults += 1;
          mod.fault_keys.push_back(std::string(KindName(slot.kind)) + "/" +
                                   slot.key);
        }
      }
      FreeSlot(index);
      index = next;
    }
    mod.ledger_head = Slot::kNone;
    mod.owned_count = 0;
    mod.revoked_count += report.revoked;
    mod.fault_count += report.faults;
    mod.state = report.faults > 0 ? MB_MODSTATE_LEAKED : MB_MODSTATE_UNLOADED;
    return report;
  }

  // The predicate a managed host gates AssemblyLoadContext.Unload() on.
  //
  // Note what it does NOT do: it does not say the context WAS collected. Native
  // cannot know that. It says nothing on this side is still holding the mod --
  // which is the half a managed host cannot determine for itself, and the half
  // it must have before it is entitled to try.
  bool IsReclaimable(const ModRecord& mod, std::string* reason) const {
    if (mod.state != MB_MODSTATE_UNLOADED && mod.state != MB_MODSTATE_FAILED) {
      if (reason) *reason = "state is not unloaded";
      return false;
    }
    if (mod.owned_count != 0) {
      if (reason) *reason = "resources are still owned";
      return false;
    }
    if (mod.active_frames != 0) {
      if (reason) *reason = "a dispatch into this mod is still on the stack";
      return false;
    }
    if (reason) *reason = "";
    return true;
  }

  size_t LiveSlotCount() const {
    size_t live = 0;
    for (const Slot& slot : slots_) {
      if (slot.alive) {
        live += 1;
      }
    }
    return live;
  }

  size_t SlotCapacity() const { return slots_.size(); }

  size_t ModCount() const { return mods_.size(); }

  std::deque<ModRecord>& mods() { return mods_; }

  std::mutex& lock() { return lock_; }

 private:
  bool ReleaseSlot(Slot& slot) {
    if (slot.released) {
      return true;
    }
    slot.released = true;
    slot.alive = false;
    if (slot.release == nullptr) {
      return true;
    }
    // A release function that throws must not strand the rest of the ledger.
    // The bridge is compiled with exceptions enabled precisely so this can be
    // contained here rather than becoming a crash inside a game frame.
    try {
      slot.release(slot.body, slot.payload);
      return true;
    } catch (...) {
      return false;
    }
  }

  uint32_t AllocateSlot() {
    if (free_head_ != Slot::kNone) {
      uint32_t index = free_head_;
      free_head_ = slots_[index].next_in_mod;
      slots_[index] = Slot();
      return index;
    }
    slots_.push_back(Slot());
    return static_cast<uint32_t>(slots_.size() - 1);
  }

  void FreeSlot(uint32_t index) {
    Slot& slot = slots_[index];
    slot.alive = false;
    slot.release = nullptr;
    slot.body = nullptr;
    slot.key.clear();
    // The tag is NOT reset to something reusable: NextTag never repeats, so a
    // handle naming this slot with the old tag can never resolve again.
    slot.next_in_mod = free_head_;
    free_head_ = index;
  }

  uint32_t NextTag() {
    uint32_t tag = ++tag_counter_;
    if (tag == 0) {
      tag = ++tag_counter_;
    }
    return tag;
  }

  // DEQUES, NOT VECTORS, and this is not a preference.
  //
  // Both containers hand out references and pointers that callers hold across
  // subsequent calls -- EnsureMod returns a ModRecord&, Resolve returns a
  // Slot*. A vector reallocates on growth and invalidates every one of them,
  // which showed up immediately as a segfault the first time a second mod was
  // registered while a reference to the first was still live. A deque never
  // invalidates references to existing elements on push_back, so the API can
  // keep the shape that reads naturally at every call site.
  //
  // The cost is one indirection per access on a structure holding at most a few
  // thousand entries. The alternative -- returning indices everywhere and
  // re-looking-up at each use -- moves the same hazard into every caller, where
  // it is far easier to get wrong once and never notice.
  std::deque<Slot> slots_;
  std::deque<ModRecord> mods_;
  std::unordered_map<std::string, uint32_t> by_id_;
  uint32_t free_head_ = Slot::kNone;
  uint32_t tag_counter_ = 0;
  std::mutex lock_;
};

}  // namespace bridge
}  // namespace misery
