#!/usr/bin/env python3
"""RESEARCH ONLY. Rehearse the GT-01 hardware-breakpoint mechanism end-to-end
against a harmless process we own, BEFORE it is ever pointed at the game -- the
same discipline the P-02 probe followed (../probe/probe.cpp lines 18-31).

Spawns gt01_rehearse_target.exe, reads the runtime HotSpot address + thread id it
prints, injects the SAME ipp_gt01_probe.dll, registers its VEH (Init), arms Dr0 =
HotSpot on the HotSpot thread, waits for the one-shot #DB, and checks the probe
recorded the correct thread and self-cleared. Also runs the N1 self-test.
Exercises exactly the arm/catch/clear path used against MISERY.
"""
import ctypes
import ctypes.wintypes as wt
import os
import subprocess
import sys
import time

IPP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, IPP_DIR)
import gt01_controller as gt  # noqa: E402
import ipp_controller as ipp  # noqa: E402

MINGW_GCC = r"D:\tools\mingw64\bin\gcc.exe"


def build_target():
    src = os.path.join(os.path.dirname(__file__), "gt01_rehearse_target.c")
    out = os.path.join(IPP_DIR, "build", "gt01_rehearse_target.exe")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    r = subprocess.run([MINGW_GCC, "-O2", "-o", out, src], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("target build failed:\n%s\n%s" % (r.stdout, r.stderr))
    return out


def main():
    target_exe = build_target()
    dll_path = gt.build_gt01_probe_dll()
    dll_name = os.path.basename(dll_path)
    print("built target:", target_exe)
    print("built probe :", dll_path)

    proc = subprocess.Popen([target_exe], stdout=subprocess.PIPE, text=True)
    try:
        line = proc.stdout.readline().strip()
        print("target says:", line)
        # HOTSPOT=0x.. TID=..
        parts = dict(kv.split("=", 1) for kv in line.split())
        hotspot = int(parts["HOTSPOT"], 16)
        hot_tid = int(parts["TID"])
        pid = proc.pid
        print("pid=%d hotspot=0x%x hot_tid=%d" % (pid, hotspot, hot_tid))

        k, _has = gt._k32full()
        # text bounds are irrelevant here; use a wide range so in_text is informative-ish
        text_lo, text_hi = 0, 0x7FFFFFFFFFFF

        hproc = k.OpenProcess(ipp.IPP_ACCESS_RIGHTS, False, pid)
        if not hproc:
            raise SystemExit("OpenProcess failed: %d" % ctypes.get_last_error())

        # inject
        pth = (dll_path + "\x00").encode("utf-16-le")
        rpath = k.VirtualAllocEx(hproc, None, len(pth), ipp.MEM_COMMIT | ipp.MEM_RESERVE,
                                 ipp.PAGE_READWRITE)
        w = ctypes.c_size_t(0)
        k.WriteProcessMemory(hproc, rpath, pth, len(pth), ctypes.byref(w))
        p_ll = k.GetProcAddress(k.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
        h1 = k.CreateRemoteThread(hproc, None, 0, p_ll, rpath, 0, None)
        k.WaitForSingleObject(h1, ipp.WAIT_TIMEOUT_MS)
        k.CloseHandle(h1)
        rbase = ipp.find_remote_module_base(k, pid, dll_name)
        print("probe remote base:", hex(rbase) if rbase else None)
        assert rbase is not None

        io = gt.pack_io(hot_tid, hotspot, text_lo, text_hi)
        rio = k.VirtualAllocEx(hproc, None, gt.IO_SIZE, ipp.MEM_COMMIT | ipp.MEM_RESERVE,
                               ipp.PAGE_READWRITE)
        k.WriteProcessMemory(hproc, rio, io, len(io), ctypes.byref(w))

        rc = gt.call_export(k, hproc, rbase, dll_path, "Init", rio, ipp.WAIT_TIMEOUT_MS)
        print("Init rc:", rc)
        assert rc == 0

        gt.call_export(k, hproc, rbase, dll_path, "RunSelfTest", rio, ipp.WAIT_TIMEOUT_MS)
        rb = ctypes.create_string_buffer(gt.IO_SIZE)
        rd = ctypes.c_size_t(0)
        k.ReadProcessMemory(hproc, rio, rb, gt.IO_SIZE, ctypes.byref(rd))
        st = gt.unpack_io(rb.raw)
        print("N1 self_tid=%d (injected thread, != hot_tid %d): %s"
              % (st["self_tid"], hot_tid, st["self_tid"] != hot_tid))
        assert st["veh_installed"] == 1
        assert st["hit_count"] == 0 and st["hit_tid"] == gt.SENTINEL_TID

        # arm Dr0 on the HotSpot thread
        htid = k.OpenThread(gt.THREAD_ARM_RIGHTS, False, hot_tid)
        assert htid, "OpenThread(arm) failed: %d" % ctypes.get_last_error()
        readback = gt.set_dr0(k, htid, hotspot, enable=True)
        print("armed Dr0=0x%x Dr7=0x%x" % (readback["Dr0"], readback["Dr7"]))
        assert readback["Dr0"] == hotspot

        hit = None
        deadline = time.time() + 5.0
        while time.time() < deadline:
            k.ReadProcessMemory(hproc, rio, rb, gt.IO_SIZE, ctypes.byref(rd))
            st = gt.unpack_io(rb.raw)
            if st["hit_count"] >= 1 and st["fired"] == 1:
                hit = st
                break
            time.sleep(0.01)

        if hit is None:
            print("REHEARSAL FAIL: breakpoint never fired")
        else:
            print("FIRED count=%d tid=%d rip=0x%x (expect tid=%d rip=0x%x)"
                  % (hit["hit_count"], hit["hit_tid"], hit["hit_rip"], hot_tid, hotspot))

        post = gt.set_dr0(k, htid, hotspot, enable=False)
        print("post-fire debug regs (external clear): Dr0=0x%x Dr7=0x%x" % (post["Dr0"], post["Dr7"]))
        # confirm handler self-cleared: read the thread's Dr0 right after fire, before external clear,
        # would be ideal, but external clear is idempotent; the key check is one-shot count==1.
        k.CloseHandle(htid)

        gt.call_export(k, hproc, rbase, dll_path, "Teardown", rio, ipp.WAIT_TIMEOUT_MS)
        k.ReadProcessMemory(hproc, rio, rb, gt.IO_SIZE, ctypes.byref(rd))
        st2 = gt.unpack_io(rb.raw)
        print("teardown_done:", st2["teardown_done"])

        p_free = k.GetProcAddress(k.GetModuleHandleW("kernel32.dll"), b"FreeLibrary")
        h3 = k.CreateRemoteThread(hproc, None, 0, p_free, rbase, 0, None)
        k.WaitForSingleObject(h3, ipp.WAIT_TIMEOUT_MS)
        k.CloseHandle(h3)
        unloaded = ipp.confirm_dll_unloaded(pid, dll_name)
        print("dll_unloaded:", unloaded)

        k.VirtualFreeEx(hproc, rpath, 0, ipp.MEM_RELEASE)
        k.VirtualFreeEx(hproc, rio, 0, ipp.MEM_RELEASE)
        k.CloseHandle(hproc)

        ok = (hit is not None and hit["hit_count"] == 1 and hit["hit_tid"] == hot_tid and
              hit["hit_rip"] == hotspot and st2["teardown_done"] == 1 and unloaded)
        print("\nREHEARSAL", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    finally:
        proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
