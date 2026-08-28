// RESEARCH ONLY -- harmless in-process rehearsal of the FTSTicker probe's novel
// thunk layer, BEFORE it is pointed at the live game (plan.md discipline).
//
// Loads ipp_ftsticker_probe.dll and drives Init + RegisterTicker with a FAKE
// AddTicker / GetCoreTicker / FMemory::Malloc, exercising exactly the pieces that
// differ from the already-proven injection: the member+sret AddTicker ABI
// marshalling, the genuine-TFunction construction+invocation across the DLL
// boundary, and the FMemory::Malloc forward (by copying the TFunction, which
// clones the owned object through the DLL's forwarded allocator).
#include "Containers/Ticker.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#pragma pack(push, 1)
struct FtsProbeIo {
    uint64_t magic; uint32_t protocol_version; uint32_t registered_ok;
    uint64_t add_ticker; uint64_t get_core_ticker; uint64_t fmemory_malloc;
    uint32_t marker; uint32_t callback_tid; uint32_t callback_count; uint32_t worker_tid;
    uint64_t reserved[2];
};
#pragma pack(pop)

// Fake game allocator (aligned), tracked for malloc/free consistency.
static int g_alloc_count = 0, g_free_count = 0;
static void* FakeMalloc(size_t n, uint32_t a) { g_alloc_count++; return _aligned_malloc(n, a ? a : 16); }
static void  FakeFree(void* p) { if (p) { g_free_count++; _aligned_free(p); } }

// The host's own FMemory symbols (the host copies/destructs a TFunction).
void* FMemory::Malloc(SIZE_T Count, uint32 Alignment) { return FakeMalloc((size_t)Count, (uint32_t)Alignment); }
void  FMemory::Free(void* Ptr) { FakeFree(Ptr); }

static int   g_addticker_called = 0, g_name_ok = 0, g_ticker_ok = 0;
static float g_delay_seen = -1.0f;
static bool  g_tfunc_result = true;
static int   g_dummy_ticker = 0;

// Exact raw ABI the DLL calls: RCX=this, RDX=&sret, R8=name, XMM3=delay, [stack]=&TFunction.
static void __fastcall FakeAddTicker(void* thisTicker, void* /*sret*/, const wchar_t* name,
                                     float delay, void* fnPtr) {
    g_addticker_called = 1;
    g_ticker_ok = (thisTicker == &g_dummy_ticker);
    g_name_ok = (name && wcscmp(name, L"MiseryCarrierProbe") == 0);
    g_delay_seen = delay;
    // COPY the TFunction (exercises CloneToEmptyStorage -> DLL's forwarded FMemory::Malloc),
    // then invoke it (exercises the owned-object Call vtable -> ProbeCallback).
    TFunction<bool(float)> copy = *reinterpret_cast<TFunction<bool(float)>*>(fnPtr);
    g_tfunc_result = copy(0.0f);
    // sret left untouched: the DLL passed a default-null TWeakPtr; nothing to fill.
}

static void* FakeGetCoreTicker() { return &g_dummy_ticker; }

int wmain(int argc, wchar_t** argv) {
    const wchar_t* dll = (argc > 1) ? argv[1] : L"ipp_ftsticker_probe.dll";
    HMODULE h = LoadLibraryW(dll);
    if (!h) { printf("REHEARSAL FAIL: LoadLibrary %ls err=%lu\n", dll, GetLastError()); return 1; }
    auto Init = reinterpret_cast<unsigned long(*)(void*)>(GetProcAddress(h, "Init"));
    auto Reg = reinterpret_cast<unsigned long(*)(void*)>(GetProcAddress(h, "RegisterTicker"));
    if (!Init || !Reg) { printf("REHEARSAL FAIL: missing exports\n"); return 1; }

    FtsProbeIo io = {};
    io.magic = 0x4950502D46545354ULL; io.protocol_version = 1;
    io.add_ticker = reinterpret_cast<uint64_t>(&FakeAddTicker);
    io.get_core_ticker = reinterpret_cast<uint64_t>(&FakeGetCoreTicker);
    io.fmemory_malloc = reinterpret_cast<uint64_t>(&FakeMalloc);

    unsigned long ir = Init(&io);
    unsigned long rr = Reg(&io);
    printf("Init rc=%lu  RegisterTicker rc=%lu\n", ir, rr);
    printf("addticker_called=%d ticker_ok=%d name_ok=%d delay=%.1f tfunc_result=%d\n",
           g_addticker_called, g_ticker_ok, g_name_ok, g_delay_seen, (int)g_tfunc_result);
    printf("marker=0x%x callback_tid=%u callback_count=%u worker_tid=%u\n",
           io.marker, io.callback_tid, io.callback_count, io.worker_tid);
    printf("fake_alloc=%d fake_free=%d\n", g_alloc_count, g_free_count);

    bool pass = ir == 0 && rr == 0 && g_addticker_called && g_ticker_ok && g_name_ok &&
                g_delay_seen == 0.0f && g_tfunc_result == false &&
                io.marker == 0x46495245u && io.callback_count == 1 &&
                io.registered_ok == 1;
    printf("\nREHEARSAL %s\n", pass ? "PASS" : "FAIL");
    FreeLibrary(h);
    return pass ? 0 : 1;
}
