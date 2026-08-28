// Host validation of the read-only RowMap traversal: build a REAL UE TMap with
// the same layout as UDataTable::RowMap, then walk it using ONLY the derived
// offsets (as the external read-only reader will) and compare against the real
// container's own iteration. Covers empty, one element, many, and sparse holes.
#include "Containers/Map.h"
#include "Containers/Set.h"
#include "UObject/NameTypes.h"
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <algorithm>

// ---- CRT-backed allocator for the harness only ----
void* FMemory::Malloc(SIZE_T c, uint32 a){ return _aligned_malloc(c, a?a:16); }
void* FMemory::Realloc(void* o, SIZE_T c, uint32 a){
    if(c==0){ if(o) _aligned_free(o); return nullptr; }
    return _aligned_realloc(o, c, a?a:16); }
void  FMemory::Free(void* p){ if(p) _aligned_free(p); }
SIZE_T FMemory::QuantizeSize(SIZE_T c, uint32){ return c; }
namespace UE { namespace Core { namespace Private {
void OnInvalidArrayNum(unsigned long long n){ printf("OnInvalidArrayNum %llu\n", n); abort(); }
}}}
void TSizedHeapAllocator<32, FMemory>::ForAnyElementType::ResizeAllocation(
    int32, int32 NumElements, SIZE_T NumBytesPerElement)
{ Data = (FScriptContainerElement*)FMemory::Realloc(Data, (SIZE_T)NumElements*NumBytesPerElement, 0); }
void TSizedHeapAllocator<32, FMemory>::ForAnyElementType::ResizeAllocation(
    int32, int32 NumElements, SIZE_T NumBytesPerElement, uint32 Align)
{ Data = (FScriptContainerElement*)FMemory::Realloc(Data, (SIZE_T)NumElements*NumBytesPerElement, Align); }

// key type is layout-identical to FName (8 bytes, 8-aligned)
using KeyT = uint64;
using MapT = TMap<KeyT, uint8*>;
static_assert(sizeof(TMap<FName, uint8*>) == 80, "RowMap layout");
static_assert(sizeof(MapT) == sizeof(TMap<FName, uint8*>), "stand-in must match RowMap layout");
static_assert(sizeof(TSetElement<TPair<KeyT, uint8*>>) ==
              sizeof(TSetElement<TPair<FName, uint8*>>), "element stride must match");

// ---- derived offsets (the ONLY knowledge the external reader will use) ----
static constexpr int SPARSE_DATA        = 0;    // TArray inside TSparseArray
static constexpr int ARR_PTR = 0, ARR_NUM = 8;  // inside that TArray
static constexpr int SPARSE_ALLOCFLAGS  = 16;   // TBitArray
static constexpr int BITS_INLINE = 0, BITS_SECONDARY = 16, BITS_NUMBITS = 24;
static constexpr int ELEM_STRIDE = 24, ELEM_KEY = 0, ELEM_VALUE = 8;

// Walk the map image exactly the way the external reader will.
static std::vector<std::pair<uint64, uint8*>> WalkExternally(const void* map_base)
{
    const unsigned char* m = (const unsigned char*)map_base;   // TMap == TSet == TSparseArray at +0
    const unsigned char* arr = m + SPARSE_DATA;
    const unsigned char* data = *(const unsigned char* const*)(arr + ARR_PTR);
    const int32 num = *(const int32*)(arr + ARR_NUM);
    const unsigned char* bits = m + SPARSE_ALLOCFLAGS;
    const int32 numbits = *(const int32*)(bits + BITS_NUMBITS);
    const uint32* words = (const uint32*)(bits + BITS_INLINE);
    if (numbits > 4 * 32) words = *(const uint32* const*)(bits + BITS_SECONDARY);

    std::vector<std::pair<uint64, uint8*>> out;
    if (!data) return out;
    for (int32 i = 0; i < num; ++i) {
        if (i < numbits) {
            const uint32 w = words[i >> 5];
            if (!((w >> (i & 31)) & 1u)) continue;      // unallocated slot: skip
        } else continue;
        const unsigned char* e = data + (size_t)i * ELEM_STRIDE;
        out.emplace_back(*(const uint64*)(e + ELEM_KEY), *(uint8* const*)(e + ELEM_VALUE));
    }
    return out;
}

static int g_fail = 0;
static void Compare(const char* label, MapT& map)
{
    std::vector<std::pair<uint64, uint8*>> truth;
    for (auto& kv : map) truth.emplace_back((uint64)kv.Key, kv.Value);
    auto got = WalkExternally(&map);
    std::sort(truth.begin(), truth.end());
    std::sort(got.begin(), got.end());
    const bool ok = (truth == got);
    printf("%-28s real=%-3zu walked=%-3zu %s\n", label, truth.size(), got.size(), ok ? "OK" : "MISMATCH");
    if (!ok) ++g_fail;
}

int main()
{
    printf("sizeof(TMap<FName,uint8*>)=%zu  element stride=%zu\n",
           sizeof(TMap<FName, uint8*>), sizeof(TSetElement<TPair<FName, uint8*>>));
    { MapT m; Compare("empty map", m); }
    { MapT m; m.Add(1, (uint8*)0x1111); Compare("one element", m); }
    {
        MapT m;
        for (uint64 i = 1; i <= 50; ++i) m.Add(i, (uint8*)(0x1000 + i));
        Compare("fifty elements", m);
        for (uint64 i = 2; i <= 50; i += 2) m.Remove(i);   // sparse holes
        Compare("after removing evens", m);
        m.Add(1000, (uint8*)0xABCD);                        // reuse a free slot
        Compare("after reuse of free slot", m);
    }
    {
        MapT m;                                             // force secondary bit storage
        for (uint64 i = 1; i <= 400; ++i) m.Add(i, (uint8*)(0x2000 + i));
        for (uint64 i = 1; i <= 400; i += 3) m.Remove(i);
        Compare("400 with holes (secondary)", m);
    }
    printf("\nTMAP HOST GATE: %s (%d failure(s))\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
