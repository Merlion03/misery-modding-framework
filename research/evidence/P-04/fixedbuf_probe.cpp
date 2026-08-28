// Gate D3 (host validation): construct an exact FString for the P-04 target using
// ONLY a game-allocator buffer + the three proven FString/TArray fields, with no
// FString(const TCHAR*), no Realloc, no ResizeAllocation, no QuantizeSize, no
// OnInvalidArrayNum. Genuine UE types are used for the layout proof and for
// read-back validation through UE's own FORCEINLINE accessors.
#include "Containers/UnrealString.h"
#include <cstdio>
#include <cstdlib>

// --- stand-in for the game's allocator (live build forwards to FMemory::Malloc
//     0xfab790 and GMalloc slot 9 Free). CRT is used ONLY in this host harness. ---
static int g_alloc = 0, g_free = 0;
static void* GameMalloc(size_t n, unsigned a){ g_alloc++; return _aligned_malloc(n, a ? a : 16); }
static void  GameFree(void* p){ if (p) { g_free++; _aligned_free(p); } }
// The helper must never touch these; declared to prove they are not referenced.
void* FMemory::Malloc(SIZE_T c, uint32 a){ return GameMalloc(c, a); }
void  FMemory::Free(void* p){ GameFree(p); }

// ---- layout proof, from genuine UE declarations ----
static_assert(sizeof(FString) == 16, "FString must be 16 bytes");
static_assert(sizeof(TArray<TCHAR>) == 16, "FString's DataType must be 16 bytes");
// TArray declares exactly: ElementAllocatorType AllocatorInstance; SizeType ArrayNum; SizeType ArrayMax;
// (Array.h:3231-3233). Their sizes sum EXACTLY to sizeof, so there is no padding
// and the offsets are forced prefix sums: Data@0, ArrayNum@8, ArrayMax@12.
static_assert(sizeof(void*) + sizeof(int32) + sizeof(int32) == sizeof(TArray<TCHAR>),
              "no padding => offsets are forced");
static constexpr int OFF_DATA = 0, OFF_NUM = 8, OFF_MAX = 12;

static const TCHAR* kPath = TEXT("/Game/ModKit/MK_Canary.MK_Canary");
static int PathLen(const TCHAR* s){ int n = 0; while (s[n]) ++n; return n; }

// Build the FString value in `dst` (16 bytes). Returns the allocated buffer.
static void* BuildFixedFString(unsigned char* dst, const TCHAR* src)
{
    const int len = PathLen(src);
    const size_t bytes = (size_t)(len + 1) * sizeof(TCHAR);
    TCHAR* buf = (TCHAR*)GameMalloc(bytes, 0 /* DEFAULT_ALIGNMENT */);
    for (int i = 0; i < len; ++i) buf[i] = src[i];
    buf[len] = TEXT('\0');                       // invariant: last element is NUL
    *(void**)(dst + OFF_DATA) = buf;
    *(int32*)(dst + OFF_NUM)  = len + 1;         // Len() == Num()-1
    *(int32*)(dst + OFF_MAX)  = len + 1;         // GetSlack() == 0 (>= 0)
    return buf;
}

int main()
{
    alignas(8) unsigned char parms[48] = {};     // MakeSoftObjectPath Parms (48)
    const int len = PathLen(kPath);
    printf("target len = %d\n", len);

    void* buf = BuildFixedFString(parms, kPath);

    // Validate THROUGH genuine UE inline API (no object with a destructor exists).
    const FString& s = *reinterpret_cast<const FString*>(parms);
    const TCHAR* data = *s;                      // GetCharArray().GetData(), inline
    int match = 1;
    for (int i = 0; i <= len; ++i) if (data[i] != kPath[i]) { match = 0; break; }

    printf("Len()            = %d (expect %d)\n", s.Len(), len);
    printf("IsEmpty()        = %d (expect 0)\n", (int)s.IsEmpty());
    printf("content match    = %d\n", match);
    printf("NUL terminated   = %d\n", (int)(data[len] == TEXT('\0')));
    printf("ArrayNum         = %d\n", *(int32*)(parms + OFF_NUM));
    printf("ArrayMax         = %d\n", *(int32*)(parms + OFF_MAX));
    printf("slack (Max-Num)  = %d (must be >= 0)\n",
           *(int32*)(parms + OFF_MAX) - *(int32*)(parms + OFF_NUM));
    printf("alloc=%d free=%d (expect 1/0 before cleanup)\n", g_alloc, g_free);

    // snapshot the pre-cleanup facts (s aliases parms, which cleanup zeroes)
    const int len_before = s.Len();
    const bool empty_before = s.IsEmpty();

    // cleanup exactly as the live probe will: free the buffer, zero the fields
    GameFree(buf);
    *(void**)(parms + OFF_DATA) = nullptr;
    *(int32*)(parms + OFF_NUM) = 0;
    *(int32*)(parms + OFF_MAX) = 0;
    const FString& z = *reinterpret_cast<const FString*>(parms);
    printf("after cleanup: Len()=%d IsEmpty()=%d alloc=%d free=%d\n",
           z.Len(), (int)z.IsEmpty(), g_alloc, g_free);

    const bool pass = (len_before == len) && !empty_before && match &&
                      (g_alloc == 1) && (g_free == 1) && z.Len() == 0 && z.IsEmpty();
    printf("\nD3 HOST GATE: %s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
