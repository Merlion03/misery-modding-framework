// RESEARCH ONLY -- NOT PRODUCTION. See ../README.md and plan.md 8.1/8.3/8.4.
//
// Single-purpose, single-call research probe (capability P-04, plan.md 8.3;
// escalation ESC-02, research/decisions.md): loaded once into the running
// MISERY-Win64-Shipping.exe, makes EXACTLY ONE call to
//
//     LoadPackage(nullptr, L"/Game/ModKit/MK_Canary", 0, nullptr, nullptr)
//
// to trigger a load of our own cooked add-on package, reports what the call
// returned, and is unloaded again in the same session. Not a generic loader:
// the LoadPackage function pointer and the package-name string pointer are
// both resolved by the controller and handed in via LoadProbeIo; this file
// contains no address knowledge of its own.
//
// WHY THE RETURN IS EXPECTED TO BE NULL, AND WHY THAT IS NOT A FAILURE.
// This build runs the Zen loader (FAsyncLoadingThread2). Its
// ShouldAlwaysLoadPackageAsync() returns true unconditionally, so the
// synchronous LoadPackage the controller calls does, internally: a
// thread-safe async enqueue (TMpscQueue, the engine's own contract) then a
// FlushAsyncLoading that, off the game thread, RETURNS WITHOUT FLUSHING
// (AsyncLoading2.cpp:9342-9364, "just return in shipping build to avoid
// crashing as the side effect of missing flushes are not always fatal"),
// then a FindObjectFast that -- because the flush was skipped -- almost
// always sees nothing yet. So LoadPackage returns null on THIS thread while
// the real load completes a few frames later on the loader thread. Success
// is therefore observed by the controller polling GUObjectArray AFTER this
// probe returns, not by this return value. The returned pointer is reported
// only for completeness.
//
// THREAD SAFETY, in brief (full analysis in the RESEARCH_LOG entry for this
// run): the game-thread checkf(IsInGameThread()) on the legacy synchronous
// path is both compiled out here (DO_CHECK==0) and not on the taken path;
// the enqueue is thread-safe by the engine's own contract; the one surviving
// Fatal (LoadPackageAsync when !GAsyncLoadingAllowed) fires only during
// shutdown, so this probe must be run only in active gameplay. The single
// call is still wrapped in a Vectored Exception Handler + setjmp/longjmp, the
// same guard proven for the P-02 probe, so any hardware fault is contained
// and reported rather than crashing the game.

#include <windows.h>
#include <csetjmp>
#include <cstdint>

namespace {

constexpr uint64_t kLoadProbeMagic = 0x4950502D4C4F4144ULL;  // "IPP-LOAD"
constexpr uint32_t kProtocolVersion = 1;

constexpr uint32_t kStatusNotRun = 0;
constexpr uint32_t kStatusSuccess = 1;             // the call returned normally
constexpr uint32_t kStatusException = 2;
constexpr uint32_t kStatusSanityCheckFailed = 3;

#pragma pack(push, 1)
struct LoadProbeIo {
    // --- input, written by the controller before RunProbe is called ---
    uint64_t magic;
    uint32_t protocol_version;
    uint64_t load_package_ptr;     // resolved LoadPackage(const TCHAR*) address
    uint64_t package_name_ptr;     // target-space ptr to a UTF-16LE, NUL-terminated package path
    // --- output, written by RunProbe before it returns ---
    uint32_t status;
    uint64_t exception_code;       // valid only when status == kStatusException
    uint64_t returned_package_ptr; // UPackage* the call returned (expected null: async, see header)
    uint8_t reserved[4];           // unused, keeps the trailing field explicit
};
#pragma pack(pop)

static_assert(sizeof(LoadProbeIo) == 52, "LoadProbeIo must stay 52 bytes -- "
              "the controller's struct format is matched to this layout");

// Not thread_local -- the P-02 probe established that implicit TLS is
// unreliable for a DLL loaded late via LoadLibrary; RunProbe is only ever
// called from the one CreateRemoteThread, so a plain static is correct.
static jmp_buf g_jump_buf;
static volatile uint64_t g_last_exception_code = 0;
static volatile bool g_guard_armed = false;
static volatile DWORD g_guard_thread_id = 0;

LONG WINAPI VectoredHandler(PEXCEPTION_POINTERS info) {
    if (g_guard_armed && GetCurrentThreadId() == g_guard_thread_id) {
        const DWORD code = info->ExceptionRecord->ExceptionCode;
        if (code != EXCEPTION_BREAKPOINT && code != EXCEPTION_SINGLE_STEP) {
            g_last_exception_code = code;
            g_guard_armed = false;
            longjmp(g_jump_buf, 1);
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

}  // namespace

extern "C" __declspec(dllexport) DWORD WINAPI RunProbe(LPVOID lpParam) {
    LoadProbeIo* io = reinterpret_cast<LoadProbeIo*>(lpParam);
    if (io == nullptr) {
        return 0xFFFFFFFFu;
    }

    io->status = kStatusNotRun;
    io->exception_code = 0;
    io->returned_package_ptr = 0;
    io->reserved[0] = io->reserved[1] = io->reserved[2] = io->reserved[3] = 0;

    if (io->magic != kLoadProbeMagic || io->protocol_version != kProtocolVersion) {
        io->status = kStatusSanityCheckFailed;
        return io->status;
    }
    if (io->load_package_ptr == 0 || io->package_name_ptr == 0) {
        io->status = kStatusSanityCheckFailed;
        return io->status;
    }

    // UPackage* LoadPackage(UPackage* InOuter, const TCHAR* InLongPackageName,
    //                       uint32 LoadFlags, FArchive* InReaderOverride,
    //                       const FLinkerInstancingContext* InstancingContext)
    // Standard Microsoft x64: RCX, RDX, R8D, R9, then [RSP+0x20]. The compiler
    // places the 5th argument on the stack for us from this 5-parameter
    // signature; __fastcall is inert on x64 but names the intent.
    using LoadPackageFn = void* (__fastcall*)(void* outer, const wchar_t* name,
                                              uint32_t flags, void* reader, void* ctx);
    LoadPackageFn load_package =
        reinterpret_cast<LoadPackageFn>(static_cast<uintptr_t>(io->load_package_ptr));
    const wchar_t* name =
        reinterpret_cast<const wchar_t*>(static_cast<uintptr_t>(io->package_name_ptr));

    PVOID veh = AddVectoredExceptionHandler(1, VectoredHandler);
    if (veh == nullptr) {
        io->status = kStatusSanityCheckFailed;
        return io->status;
    }

    if (setjmp(g_jump_buf) == 0) {
        g_guard_thread_id = GetCurrentThreadId();
        g_guard_armed = true;
        void* result = load_package(nullptr, name, 0u, nullptr, nullptr);
        g_guard_armed = false;
        io->returned_package_ptr = reinterpret_cast<uint64_t>(result);
        io->status = kStatusSuccess;   // returned normally; null is expected (async)
    } else {
        io->exception_code = g_last_exception_code;
        io->status = kStatusException;
    }

    RemoveVectoredExceptionHandler(veh);
    return io->status;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    // Does nothing on any notification. All work is in RunProbe, called via a
    // second CreateRemoteThread after LoadLibraryW's own thread returned --
    // never from DllMain, which holds the loader lock.
    (void)reason;
    return TRUE;
}
