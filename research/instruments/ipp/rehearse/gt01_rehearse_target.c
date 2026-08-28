/* RESEARCH ONLY -- harmless rehearsal target for the GT-01 probe mechanism.
 *
 * Prints, on stdout, the runtime address of HotSpot() and the id of the thread
 * that will execute it, then spins that thread calling HotSpot() forever with a
 * small sleep. The GT-01 rehearsal driver injects the SAME probe DLL used
 * against the game, arms an execute hardware breakpoint (Dr0) on HotSpot for
 * that thread, and checks that the probe's VEH catches the one-shot #DB,
 * records the thread identity, and clears the breakpoint -- exactly the
 * mechanism used against MISERY, exercised end-to-end against a process we own.
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

static volatile uint64_t g_counter = 0;

__attribute__((noinline)) void HotSpot(void) {
    g_counter += 1;               /* real work so the call is not optimized away */
    _ReadWriteBarrier();
}

static DWORD WINAPI HotThread(LPVOID p) {
    (void)p;
    for (;;) {
        HotSpot();
        Sleep(5);
    }
    return 0;
}

int main(void) {
    DWORD tid = 0;
    HANDLE h = CreateThread(NULL, 0, HotThread, NULL, 0, &tid);
    if (!h) {
        printf("ERROR CreateThread\n");
        fflush(stdout);
        return 1;
    }
    printf("HOTSPOT=0x%llx TID=%lu\n",
           (unsigned long long)(uintptr_t)&HotSpot, (unsigned long)tid);
    fflush(stdout);
    /* stay alive for the driver; the driver kills us when done */
    for (;;) {
        Sleep(1000);
    }
    return 0;
}
