// RESEARCH ONLY -- NOT PRODUCTION. See ../README.md and plan.md 8.1/8.3/8.4.
//
// E-3c: ask the game to load the cooked child package, then construct one
// instance of the child class. On the game thread, through the game's own
// reflected functions, once.
//
// WHY A LOAD STEP EXISTS AT ALL
// -----------------------------
// Mounting is not loading, and the first live attempt proved it: the container
// was mounted (FPakFile::bIsMounted true) and its packages were registered
// (FIoContainerHeader non-null), and there was still no child class anywhere in
// the process -- because nothing had ever asked for the package. UE loads on
// demand. That is neither a mount failure nor an unresolved import, and reading
// it as either would have been wrong.
//
// So the probe asks, through UKismetSystemLibrary::LoadAsset_Blocking, which is
// the game's ordinary load path rather than a back door.
//
// EVERYTHING HERE IS REUSE
// ------------------------
// The FString construction, the Conv_StringToName interning, the soft-pointer
// layout and the SpawnObject parameter block are CR-01C5's, byte for byte, on
// this build. A probe rediscovering layouts the project already proved would be
// adding risk for nothing.
//
// WHAT IT DOES NOT DO
// -------------------
// It does not judge parentage. It records what it loaded and what it built; the
// controller walks the ancestry out of process, read-only. A probe that both
// constructs the thing and rules on its lineage is marking its own homework.
#include "Containers/Ticker.h"
#include "HAL/PlatformTLS.h"
#include "HAL/PlatformAtomics.h"

#include <cstdint>

using GetCoreTickerFn = void* (*)();
using AddTickerRaw = void(__fastcall*)(void* thisTicker, void* sretHandle,
                                       const wchar_t* name, float delay,
                                       void* fnPtr);
using MallocFn = void* (*)(size_t Count, uint32_t Alignment);
using FreeFn = void (*)(void*);
using ProcessEventFn = void(__fastcall*)(void* self, void* function,
                                         void* parms);

namespace {

constexpr uint64_t kMagic = 0x4950502D45334300ULL;   // "IPP-E3C\0"
constexpr uint32_t kProto = 1;
constexpr int kPathMax = 256;

// UE 5.4.4 layout, all established by prior work in this project.
constexpr uint32_t kOffClassPrivate = 0x10;      // UObjectBase
constexpr uint32_t kOffSuperStruct = 0x40;       // UStruct
constexpr uint32_t kOffChildProperties = 0x50;   // UStruct
constexpr uint32_t kOffPropertiesSize = 0x58;    // UStruct
constexpr uint32_t kOffFieldNext = 0x18;         // FField::Next
constexpr uint32_t kOffFieldName = 0x20;         // FField::NamePrivate
constexpr uint32_t kOffPropOffset = 0x44;        // FProperty::Offset_Internal
constexpr int kChainMax = 12;
// FString: Data / Num / Max.
constexpr int kStrData = 0, kStrNum = 8, kStrMax = 12;
// TSoftObjectPtr and LoadAsset_Blocking, as CR-01C5 established them.
constexpr int kSoftPtrSize = 40, kSoftPtrPath = 8;
constexpr int kSoftPathPkg = 0, kSoftPathAsset = 8;
constexpr int kLoadParms = 48, kLoadIn = 0, kLoadRet = 40;
// Conv_StringToName(FString) -> FName: 16-byte FString in, FName at +16.
constexpr int kConvParms = 24, kConvRet = 16;

#pragma pack(push, 1)
struct E3cIo {
    // ---- input ----
    uint64_t magic;
    uint32_t protocol_version;
    uint32_t reserved0;
    uint64_t add_ticker;
    uint64_t get_core_ticker;
    uint64_t fmemory_malloc;
    uint64_t fmemory_free;
    uint64_t process_event;
    uint64_t cdo_stringlib;
    uint64_t fn_conv_str_to_name;
    uint64_t cdo_syslib;
    uint64_t fn_load_asset_blocking;
    uint64_t cdo_gameplaystatics;
    uint64_t fn_spawn_object;
    uint64_t transient_package;
    uint16_t package_path[kPathMax];
    uint16_t asset_name[kPathMax];
    uint16_t inherited_member[kPathMax];   // the property to look for
    // ---- output ----
    uint64_t package_fname;
    uint64_t asset_fname;
    uint64_t loaded;
    uint64_t child_class;
    uint64_t constructed;
    uint64_t constructed_class;
    // ---- readings taken ON THE GAME THREAD, while everything is alive ----
    //
    // Taken here rather than out of process because nothing roots what this
    // probe creates: the first attempt read the addresses back seconds later
    // and found garbage, because UE had already collected an unreferenced
    // object in the transient package and the class with it. Rooting would fix
    // the lifetime but would mean manipulating it; reading immediately does
    // not, and the addendum's constraint is easier to honour by touching less.
    //
    // These are RECORDINGS. Nothing here decides whether inheritance worked --
    // the controller compares them against the parent address the production
    // resolver found on its own.
    uint64_t child_super_struct;
    uint64_t child_properties_size;
    uint64_t parent_properties_size;
    uint64_t member_fname;
    uint64_t member_owner;            // the struct whose chain held it
    uint64_t member_offset;
    uint64_t child_own_member_found;  // was it declared BY the child itself
    uint64_t chain[kChainMax];        // the constructed instance's ancestry
    uint32_t registered_ok;
    uint32_t worker_tid;
    uint32_t ran;
    uint32_t callback_tid;
    uint32_t callback_count;
    uint32_t step;                     // how far the callback got
};
#pragma pack(pop)
static_assert(sizeof(E3cIo) == 1872, "E3cIo layout must match the controller");

E3cIo* volatile g_io = nullptr;
MallocFn g_malloc = nullptr;
FreeFn g_free = nullptr;

int NameLen(const uint16_t* s) {
    int n = 0;
    while (n < kPathMax - 1 && s[n] != 0) {
        ++n;
    }
    return n;
}

bool MakeFString(unsigned char* dst, const uint16_t* src) {
    const int len = NameLen(src);
    uint16_t* buf = static_cast<uint16_t*>(
        g_malloc(static_cast<size_t>(len + 1) * sizeof(uint16_t), 0u));
    if (buf == nullptr) {
        return false;
    }
    for (int i = 0; i < len; ++i) {
        buf[i] = src[i];
    }
    buf[len] = 0;
    *reinterpret_cast<void**>(dst + kStrData) = buf;
    *reinterpret_cast<int32_t*>(dst + kStrNum) = len + 1;
    *reinterpret_cast<int32_t*>(dst + kStrMax) = len + 1;
    return true;
}

void FreeFString(unsigned char* fstr) {
    void* data = *reinterpret_cast<void**>(fstr + kStrData);
    if (data != nullptr) {
        g_free(data);
    }
    *reinterpret_cast<void**>(fstr + kStrData) = nullptr;
    *reinterpret_cast<int32_t*>(fstr + kStrNum) = 0;
    *reinterpret_cast<int32_t*>(fstr + kStrMax) = 0;
}

uint64_t InternName(const uint16_t* text) {
    E3cIo* io = g_io;
    alignas(8) unsigned char parms[kConvParms] = {};
    if (!MakeFString(parms, text)) {
        return 0;
    }
    reinterpret_cast<ProcessEventFn>(static_cast<uintptr_t>(io->process_event))(
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->cdo_stringlib)),
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->fn_conv_str_to_name)),
        parms);
    const uint64_t name = *reinterpret_cast<uint64_t*>(parms + kConvRet);
    FreeFString(parms);
    return name;
}

bool Callback(float /*DeltaTime*/) {
    E3cIo* io = g_io;
    if (io == nullptr || io->ran != 0u) {
        return false;
    }
    io->callback_tid = static_cast<uint32_t>(FPlatformTLS::GetCurrentThreadId());
    FPlatformAtomics::InterlockedIncrement(
        reinterpret_cast<volatile int32*>(&io->callback_count));
    io->ran = 1u;
    io->step = 1;

    auto process_event =
        reinterpret_cast<ProcessEventFn>(static_cast<uintptr_t>(io->process_event));

    io->package_fname = InternName(io->package_path);
    io->asset_fname = InternName(io->asset_name);
    if (io->package_fname == 0 || io->asset_fname == 0) {
        return false;
    }
    io->step = 2;

    // ---- ask for the package, the ordinary way --------------------------
    alignas(8) unsigned char soft[kSoftPtrSize] = {};
    *reinterpret_cast<uint64_t*>(soft + kSoftPtrPath + kSoftPathPkg) =
        io->package_fname;
    *reinterpret_cast<uint64_t*>(soft + kSoftPtrPath + kSoftPathAsset) =
        io->asset_fname;
    alignas(8) unsigned char load_parms[kLoadParms] = {};
    for (int i = 0; i < kSoftPtrSize; ++i) {
        load_parms[kLoadIn + i] = soft[i];
    }
    process_event(
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->cdo_syslib)),
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->fn_load_asset_blocking)),
        load_parms);
    io->loaded = *reinterpret_cast<uint64_t*>(load_parms + kLoadRet);
    if (io->loaded == 0) {
        return false;   // the controller reads `loaded` and `step`
    }
    // The soft path names the generated CLASS object, so what came back is the
    // class itself rather than an instance of it.
    io->child_class = io->loaded;
    io->step = 3;

    // ---- construct one instance -----------------------------------------
    // UGameplayStatics::SpawnObject(UClass* ObjectClass, UObject* Outer), into
    // the transient package: nothing is placed in a world, no BeginPlay runs,
    // and no gameplay state is touched.
    alignas(8) unsigned char parms[24] = {};
    *reinterpret_cast<uint64_t*>(parms + 0) = io->child_class;
    *reinterpret_cast<uint64_t*>(parms + 8) = io->transient_package;
    *reinterpret_cast<uint64_t*>(parms + 16) = 0;
    process_event(
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->cdo_gameplaystatics)),
        reinterpret_cast<void*>(static_cast<uintptr_t>(io->fn_spawn_object)),
        parms);
    const uint64_t object = *reinterpret_cast<uint64_t*>(parms + 16);
    io->constructed = object;
    if (object != 0) {
        io->constructed_class =
            *reinterpret_cast<uint64_t*>(object + kOffClassPrivate);
        io->step = 4;
    }

    // ---- 3. read everything, now, while it is all alive ------------------
    io->child_super_struct =
        *reinterpret_cast<uint64_t*>(io->child_class + kOffSuperStruct);
    io->child_properties_size =
        *reinterpret_cast<uint32_t*>(io->child_class + kOffPropertiesSize);
    if (io->child_super_struct != 0) {
        io->parent_properties_size = *reinterpret_cast<uint32_t*>(
            io->child_super_struct + kOffPropertiesSize);
    }

    // The inherited member, looked for through the CHILD's own chain. Which
    // struct's chain it is found on is recorded, not assumed: that is the fact
    // distinguishing "inherited from the real parent" from "declared by us".
    io->member_fname = InternName(io->inherited_member);
    if (io->member_fname != 0) {
        const uint32_t wanted =
            static_cast<uint32_t>(io->member_fname & 0xFFFFFFFFull);
        uint64_t owner = io->child_class;
        int depth = 0;
        while (owner != 0 && depth < kChainMax && io->member_owner == 0) {
            uint64_t field = *reinterpret_cast<uint64_t*>(
                owner + kOffChildProperties);
            int guard = 0;
            while (field != 0 && guard < 512) {
                const uint32_t name =
                    *reinterpret_cast<uint32_t*>(field + kOffFieldName);
                if (name == wanted) {
                    io->member_owner = owner;
                    io->member_offset =
                        *reinterpret_cast<uint32_t*>(field + kOffPropOffset);
                    if (owner == io->child_class) {
                        io->child_own_member_found = 1;
                    }
                    break;
                }
                field = *reinterpret_cast<uint64_t*>(field + kOffFieldNext);
                ++guard;
            }
            owner = *reinterpret_cast<uint64_t*>(owner + kOffSuperStruct);
            ++depth;
        }
    }

    // The constructed instance's ancestry, walked from its own class.
    uint64_t cursor = io->constructed_class;
    for (int i = 0; i < kChainMax && cursor != 0; ++i) {
        io->chain[i] = cursor;
        cursor = *reinterpret_cast<uint64_t*>(cursor + kOffSuperStruct);
    }
    io->step = 5;
    return false;   // one-shot
}

struct FTickerElementOpaque;

}  // namespace

void* FMemory::Malloc(SIZE_T Count, uint32 Alignment) {
    return g_malloc(static_cast<size_t>(Count), static_cast<uint32_t>(Alignment));
}

extern "C" __declspec(dllexport) unsigned long Init(void* lpParam) {
    E3cIo* io = reinterpret_cast<E3cIo*>(lpParam);
    if (io == nullptr || io->magic != kMagic || io->protocol_version != kProto) {
        return 0xFFFFFFFFu;
    }
    if (io->add_ticker == 0 || io->get_core_ticker == 0 ||
        io->fmemory_malloc == 0 || io->fmemory_free == 0 ||
        io->process_event == 0 || io->cdo_stringlib == 0 ||
        io->fn_conv_str_to_name == 0 || io->cdo_syslib == 0 ||
        io->fn_load_asset_blocking == 0 || io->cdo_gameplaystatics == 0 ||
        io->fn_spawn_object == 0 || io->transient_package == 0) {
        return 0xFFFFFFFEu;
    }
    g_malloc = reinterpret_cast<MallocFn>(static_cast<uintptr_t>(io->fmemory_malloc));
    g_free = reinterpret_cast<FreeFn>(static_cast<uintptr_t>(io->fmemory_free));
    g_io = io;
    return 0u;
}

extern "C" __declspec(dllexport) unsigned long Run(void* lpParam) {
    E3cIo* io = reinterpret_cast<E3cIo*>(lpParam);
    if (io == nullptr || io != g_io) {
        return 0xFFFFFFFFu;
    }
    io->worker_tid = static_cast<uint32_t>(FPlatformTLS::GetCurrentThreadId());
    auto get_core_ticker = reinterpret_cast<GetCoreTickerFn>(
        static_cast<uintptr_t>(io->get_core_ticker));
    auto add_ticker =
        reinterpret_cast<AddTickerRaw>(static_cast<uintptr_t>(io->add_ticker));
    void* ticker = get_core_ticker();
    if (ticker == nullptr) {
        return 0xFFFFFFFDu;
    }
    TFunction<bool(float)> fn = &Callback;
    TWeakPtr<FTickerElementOpaque> handle;
    add_ticker(ticker, &handle, L"MiseryE3cProbe", 0.0f, &fn);
    io->registered_ok = 1u;
    return 0u;
}
