// Feasibility: construct a REAL FTickerDelegate with MSVC + genuine UE headers.
#include "Delegates/Delegate.h"

static bool ProbeTick(float /*dt*/) { return false; }  // one-shot: return false

extern "C" __declspec(dllexport) void MakeTickerDelegate(void* out)
{
    // FTickerDelegate == TDelegate<bool(float)>
    using FTickerDelegate = TDelegate<bool(float)>;
    FTickerDelegate d = FTickerDelegate::CreateStatic(&ProbeTick);
    *reinterpret_cast<FTickerDelegate*>(out) = d;
}
