#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Read-only protection-surface scanner (plan.md questions Q-8.2 and Q-8.3).

WHAT THIS TOOL IS FOR
---------------------
Two questions have to be answered before section 8 of the plan (runtime
instrumentation) is admissible at all:

  Q-8.3  does this build carry an anti-cheat?
  Q-8.2  does this build carry anti-debug / anti-instrumentation logic?

Both are Tier A claims. The failure mode they invite is a specific one, named in
plan.md and in research/unknowns.md as the forbidden inference:

    "there are no EasyAntiCheat or BattlEye files in the game folder,
     therefore there is no anti-cheat"

That is one observation on one surface. This tool exists so the answer rests on
SEVERAL surfaces, so each surface is named, and so a reader can re-run the
surface instead of trusting a hand inspection. The tool does not decide whether
protection exists; it produces per-surface observations plus a verdict computed
from an explicit, printed rule, and it prints the surfaces it did NOT test with
the same prominence as the ones it did.

THE INTERPRETIVE PROBLEM, STATED UP FRONT
-----------------------------------------
Nearly every Windows API that appears on an anti-debug checklist has a routine,
boring explanation inside an Unreal Engine game:

  * SetUnhandledExceptionFilter, AddVectoredExceptionHandler, MiniDumpWriteDump
    and the whole of dbghelp.dll are what UE's crash reporter is built out of;
  * IsDebuggerPresent gates whether a log line also goes to the debugger;
  * OutputDebugString*/DebugBreak are the debug-output and assert paths;
  * CreateToolhelp32Snapshot appears in module and thread enumeration, which the
    same crash reporter needs to symbolise a stack;
  * VirtualProtect is used by every JIT, every trampoline-free hot patch, and by
    the engine's own page-protection helpers.

So the PRESENCE of the kit is not evidence of protection, and this tool never
reports it as such. Every entry in the API table below carries the benign
explanation next to it, and the JSON document repeats that explanation on every
occurrence, so the fact cannot be quoted without its counter-reading.

What would actually distinguish protection from a crash reporter is: where these
functions are CALLED FROM, whether a TLS callback reaches them, whether the
result feeds a branch that changes behaviour, and whether anything in the image
obfuscates or self-checks. All four are disassembly questions and therefore M2's
work, not this tool's. The tool says so per finding rather than pretending the
import table settles it.

WHY A NEGATIVE RESULT HERE MEANS ANYTHING
-----------------------------------------
A scanner that finds nothing is indistinguishable from a scanner that looks for
nothing. Three things are built in to close that gap:

  * a needle SELF-TEST: before the run, every middleware and API needle is
    matched against a synthetic in-memory buffer that contains it, in both
    encodings. If any needle fails to fire, the run reports the detector as
    broken instead of reporting a clean result;
  * POSITIVE CONTROLS on real files: dbghelp.dll must yield the string
    "NtQueryInformationProcess", and the D-04 oracle must yield its dynamic
    ntdll-resolution table. Both are modules in this very installation, so the
    string surface is demonstrated to work on the same disks and the same code
    path that produced the negative answers;
  * a NEGATIVE CONTROL on a real file: tbbmalloc.dll, a small allocator with no
    business touching any of this, must come back empty.

SURFACES
--------
  filesystem-inventory  every file the install inventory lists, by name, path
                        and extension, against the middleware name table and
                        against the kernel-driver / service file shapes
  pe-sections           the section table of every PE module, against known
                        packer and protector section names, plus W+X and
                        high-entropy-without-imports shapes
  pe-imports            the import AND delay-import symbol tables of every PE
                        module -- not only the three executables, because a
                        protection layer usually lives in a module
  pe-exports            export tables. A bundled SDK that EXPORTS a protection
                        API is recorded as an available capability, separately
                        from anything that actually IMPORTS one of those
                        symbols -- the two are different facts and only the
                        second says anything about this build
  pe-tls                the TLS directory and the callback array of every
                        module: the section each callback lands in, its entry in
                        .pdata, its UNWIND_INFO, its first bytes, and a census
                        of how many OTHER modules of the installation carry a
                        byte-identical callback with the same unwind shape. A
                        TLS callback runs before the entry point, which is the
                        classic anti-debug hook site
  pe-headers            Authenticode presence, overlay size, load-config guard
                        flags, DLL characteristics
  strings               a streaming literal scan, ASCII and UTF-16LE, for
                        middleware names, the anti-debug API kit as text (the
                        form a GetProcAddress-resolved call leaves behind), the
                        detection constants, the kernel-mode routine names, the
                        GPU-driver-enumeration idiom that explains a
                        service-control hit, the debugger/hypervisor vocabulary
                        and the bare words the brief names ("debugger",
                        "cheat", "tamper", "integrity", "hook") which are
                        counted and never interpreted. Every hit records file
                        offset, length, containing section and whether that
                        section is executable. A separate short-needle pass
                        covers EVERY byte of EVERY file in the installation,
                        containers included

WHAT THIS TOOL DELIBERATELY DOES NOT DO
---------------------------------------
It does not disassemble, so it cannot say what a TLS callback does. It does not
run anything. It does not decrypt (decision D-02) and it never attempts to
bypass, disable, evade or fingerprint around anything -- circumvention is out of
scope by project rule (plan.md), not by preference, and if protection had been
found the correct output would have been a recorded gate, not a workaround.

Read-only, standard library only, deterministic output (sorted keys, indent 2,
LF, UTF-8 without BOM). Every write goes through pathguard, so no output path
can land inside a game installation (decision D-01).

Usage:
    python tools/static/protection_scan.py <install-root> [--out FILE]
    python tools/static/protection_scan.py <install-root> --json
    python tools/static/protection_scan.py <single-pe-file> --module-only
    python tools/static/protection_scan.py <install-root> --self-test-only
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
from datetime import datetime, timezone

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.path.dirname(_HERE)
for _extra in (os.path.join(_TOOLS, "inventory"), os.path.join(_TOOLS, "fingerprint")):
    if _extra not in sys.path:
        sys.path.insert(0, _extra)

# Shared output-path guard -- plan.md 1.5 layer 1 / D-01. Imported, never
# reimplemented.
import pathguard  # noqa: E402

# The PE layer belongs to F-01. Re-deriving section tables, RVA translation or
# import walking here would give this tool a second, differently-buggy opinion
# about where .rdata is.
import pe_info  # noqa: E402

GENERATOR_NAME = "tools/static/protection_scan.py"
GENERATOR_VERSION = "1.0.0"

PEFormatError = pe_info.PEFormatError


# --------------------------------------------------------------------------- #
# hard limits. Each one bounds a number that comes from a file and must
# therefore never be believed.
# --------------------------------------------------------------------------- #

SCAN_CHUNK = 32 << 20             # streaming window; large enough that the
                                  # per-key find loop is amortised
MAX_NEEDLE_BYTES = 128            # longest needle, sets the overlap
SCAN_OVERLAP = MAX_NEEDLE_BYTES * 2 + 8
MAX_HITS_PER_NEEDLE_PER_FILE = 16  # recorded; the total count is always exact
CONTEXT_BYTES = 40                # printable context kept either side of a hit
MAX_LITERAL_READS = 64
HIGH_ENTROPY_THRESHOLD = 7.2      # bits/byte; a packed or encrypted section
TLS_MIN_INDEPENDENT_TWINS = 2     # how many OTHER modules must carry the
                                  # same callback before "it is the CRT
                                  # pair" counts as corroborated
PE_EXTENSIONS = (".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".drv", ".efi")

# Confidence ceiling is 0.99 (plan.md 10.2); 1.00 is forbidden anywhere.
CONFIDENCE_LITERAL = 0.99

RERUN_CONFIRMED = (
    "Method re-run and reproduced within this run: every range in this group was read "
    "a second time through a second, independently opened file handle and the two "
    "reads agree byte for byte. The limit of that attestation, stated plainly: it is a "
    "re-read of the same file on the same machine, so it catches a transient read, a "
    "seek error and a bookkeeping mistake -- it does not catch reading the wrong file."
)
RERUN_NOT_CONFIRMED = (
    "Method NOT reproduced: the second read of this range disagreed with the first, or "
    "could not be performed. plan.md 10.3 criterion 2 is therefore unmet and this "
    "reading must not be relied on until it is explained."
)

VERDICT_FOUND = "FOUND"
VERDICT_NOT_FOUND_IN_SURFACE = "NOT_FOUND_WITHIN_TESTED_SURFACE"
VERDICT_UNKNOWN = "UNKNOWN"

VERDICT_DISPLAY = {
    VERDICT_FOUND: "FOUND",
    VERDICT_NOT_FOUND_IN_SURFACE: "NOT FOUND WITHIN TESTED SURFACE",
    VERDICT_UNKNOWN: "UNKNOWN",
}


# --------------------------------------------------------------------------- #
# signature table 1: protection middleware, by name
#
# `files` are matched case-insensitively against every path component AND
# against the whole relative path, so a directory called EasyAntiCheat is caught
# as well as a file. `strings` are the byte needles searched in every file in
# scope. `sections` are section names the product is known to add. `exports` are
# export names its runtime module carries.
#
# The list is the one named in the task brief plus the products that share the
# same deployment shape. It is a list of NAMES, and a name table can only ever
# find a product that did not rename itself -- which is exactly why it is one
# surface among several and never the whole answer.
# --------------------------------------------------------------------------- #

MIDDLEWARE = (
    {
        "id": "easyanticheat",
        "display": "Easy Anti-Cheat (Epic Online Services)",
        "family": "anti-cheat",
        "files": ("easyanticheat", "eac_", "easyanticheat_x64", "start_protected_game"),
        "strings": ("EasyAntiCheat", "EasyAntiCheat_x64", "EAntiCheat",
                    "EasyAntiCheat_EOS", "eac_server", "EOS_AntiCheat"),
        "sections": (),
        "exports": ("EAC_Client_Initialize", "EOS_AntiCheatClient_BeginSession"),
        "symbol_prefixes": ("EOS_AntiCheatClient_", "EOS_AntiCheatServer_",
                            "EAC_Client_", "EAC_Server_"),
        "deployment_note": (
            "ships as EasyAntiCheat/ subdirectory with a launcher executable, a "
            "service and a kernel driver, or as the EOS AntiCheat client library "
            "linked against EOSSDK"),
    },
    {
        "id": "battleye",
        "display": "BattlEye",
        "family": "anti-cheat",
        "files": ("battleye", "beclient", "beservice", "bedaisy", "belauncher"),
        "strings": ("BattlEye", "BEClient", "BEClient_x64", "BEService",
                    "BEDaisy", "BELauncher"),
        "sections": (),
        "exports": ("BEClient_Init",),
        "symbol_prefixes": ("BEClient_", "BEService_"),
        "deployment_note": (
            "ships as BattlEye/ with BEClient_x64.dll, BEService_x64.exe and the "
            "BEDaisy.sys driver; the game loader is normally replaced"),
    },
    {
        "id": "gameguard",
        "display": "nProtect GameGuard",
        "family": "anti-cheat",
        "files": ("gameguard", "gameguard.des", "npgg", "npggnt", "gamemon"),
        "strings": ("GameGuard", "nProtect GameGuard", "npggNT", "GameMon",
                    "INCA Internet"),
        "sections": (),
        "exports": (),
        "symbol_prefixes": (),
        "deployment_note": ("ships as a GameGuard/ subdirectory with "
                            "npggNT.des, a kernel driver and a replaced "
                            "launcher"),
    },
    {
        "id": "xigncode",
        "display": "XIGNCODE3",
        "family": "anti-cheat",
        "files": ("xigncode", "xhunter", "x3.xem", "xigncode3"),
        "strings": ("XignCode", "XIGNCODE", "xhunter1", "Wellbia"),
        "sections": (),
        "exports": (),
        "symbol_prefixes": (),
        "deployment_note": ("ships as an xigncode/ subdirectory with x3.xem "
                            "and the xhunter1.sys kernel driver"),
    },
    {
        "id": "vanguard",
        "display": "Riot Vanguard",
        "family": "anti-cheat",
        "files": ("vanguard", "vgk.sys", "vgc.exe", "vgtray"),
        "strings": ("Riot Vanguard", "vgk.sys", "vgc.exe"),
        "sections": (),
        "exports": (),
        "symbol_prefixes": (),
        "deployment_note": ("a boot-start kernel driver vgk.sys plus the vgc "
                            "user-mode service, installed outside the game "
                            "folder"),
    },
    {
        "id": "denuvo",
        "display": "Denuvo Anti-Tamper / Anti-Cheat",
        "family": "drm-anti-tamper",
        "files": ("denuvo", "denuvo64",),
        "strings": ("Denuvo", "DenuvoAntiCheat", "denuvo_", "Irdeto"),
        "sections": (".denuvo",),
        "exports": (),
        "symbol_prefixes": (),
        "deployment_note": (
            "normally leaves no separate file: the protected executable grows by "
            "tens of megabytes, gains high-entropy sections and loses a normal "
            "entry-point prologue. Detected here by section shape and strings, "
            "not by file name alone"),
    },
    {
        "id": "vmprotect",
        "display": "VMProtect",
        "family": "obfuscator",
        "files": ("vmprotect",),
        "strings": ("VMProtect", "vmp.dll", ".vmp0"),
        "sections": (".vmp0", ".vmp1", ".vmp2", ".vmp"),
        "exports": (),
        "symbol_prefixes": (),
        "deployment_note": ("adds .vmp0/.vmp1 sections, virtualises selected "
                            "functions and rewrites the entry point"),
    },
    {
        "id": "themida",
        "display": "Themida / WinLicense (Oreans)",
        "family": "obfuscator",
        "files": ("themida", "winlicense", "securengine"),
        "strings": ("Themida", "WinLicense", "Oreans Technologies",
                    "SecureEngine"),
        "sections": (".themida", ".winlice", ".Themida", ".boot"),
        "exports": (),
        "symbol_prefixes": (),
        "deployment_note": ("adds .themida/.winlice sections and wraps the "
                            "entry point in a virtual machine"),
    },
    {
        "id": "enigma",
        "display": "Enigma Protector",
        "family": "obfuscator",
        "files": ("enigma",),
        "strings": ("Enigma Protector", "EnigmaProtector", "The Enigma Protector"),
        "sections": (".enigma1", ".enigma2", ".enigma"),
        "exports": (),
        "symbol_prefixes": (),
        "deployment_note": ("adds .enigma1/.enigma2 sections and moves the "
                            "original entry point into the stub"),
    },
    {
        "id": "arxan",
        "display": "Arxan / Digital.ai GuardIT",
        "family": "anti-tamper",
        "files": ("arxan", "guardit"),
        "strings": ("Arxan", "GuardIT", "Digital.ai", "ARXAN_"),
        "sections": (),
        "exports": (),
        "symbol_prefixes": (),
        "deployment_note": (
            "no separate file and no distinctive section: guards are woven into "
            ".text. Only the strings surface can see it, and it can be built "
            "without any. Treat a negative as weak for this product specifically"),
    },
    {
        "id": "steam-ceg",
        "display": "Steam CEG / SteamStub DRM wrapper",
        "family": "drm",
        "files": (),
        "strings": ("SteamStub", "Steam CEG", "CEGVerify", "SteamDRMP",
                    "steam_drm", "SteamAppId.txt"),
        "sections": (".bind",),
        "exports": (),
        "symbol_prefixes": (),
        "deployment_note": (
            "a CEG-wrapped executable is re-linked by Valve: it gains a .bind "
            "section holding the stub, an Authenticode signature from Valve, and "
            "usually an overlay. Ordinary Steamworks integration (steam_api64.dll "
            "plus SteamAPI_Init) is NOT CEG and must not be reported as DRM"),
    },
    {
        "id": "securom",
        "display": "SecuROM",
        "family": "drm",
        "files": ("securom", "paul.dll", "sintf32.dll"),
        "strings": ("SecuROM", "Sony DADC", "securom_"),
        "sections": (".securom", ".cms_t", ".cms_d"),
        "exports": (),
        "symbol_prefixes": (),
        "deployment_note": ("adds .cms_t/.cms_d sections and, in later "
                            "versions, a user-mode service"),
    },
    {
        "id": "starforce",
        "display": "StarForce",
        "family": "drm",
        "files": ("starforce", "sfdrv", "protect.dll"),
        "strings": ("StarForce", "Protection Technology", "sfdrv01"),
        "sections": (".sforce", ".ps4"),
        "exports": (),
        "symbol_prefixes": (),
        "deployment_note": ("installs the sfdrv/sfhlp kernel driver family "
                            "outside the game folder"),
    },
    {
        "id": "safedisc",
        "display": "SafeDisc",
        "family": "drm",
        "files": ("safedisc", "secdrv", "clcd16", "clcd32", "dplayerx"),
        "strings": ("SafeDisc", "secdrv.sys", "C-Dilla"),
        "sections": (".txt2", ".txt"),
        "exports": (),
        "symbol_prefixes": (),
        "deployment_note": ("installs the secdrv.sys kernel driver and ships "
                            "C-Dilla support files beside the executable"),
    },
    {
        "id": "sentinel-hasp",
        "display": "Sentinel HASP / Aladdin",
        "family": "licensing",
        "files": ("hasp", "sentinel", "hardlock", "aksusb"),
        "strings": ("Sentinel HASP", "Sentinel LDK", "hasp_login",
                    "Aladdin Knowledge", "HASPHL"),
        "sections": (),
        "exports": ("hasp_login",),
        "symbol_prefixes": ("hasp_", "sntl_"),
        "deployment_note": ("dongle licensing: a kernel driver plus a runtime "
                            "service, and a vendor DLL beside the "
                            "executable"),
    },
    {
        "id": "obsidium-asprotect",
        "display": "Obsidium / ASProtect / ASPack",
        "family": "obfuscator",
        "files": ("obsidium", "asprotect"),
        "strings": ("Obsidium", "ASProtect", "ASPack"),
        "sections": (".obsidium", ".aspack", ".adata", ".asprote"),
        "exports": (),
        "symbol_prefixes": (),
        "deployment_note": ("classic compressing packers with distinctive "
                            "section names and a stub at the entry point"),
    },
    {
        "id": "upx",
        "display": "UPX",
        "family": "packer",
        "files": (),
        "strings": ("UPX!", "$Info: This file is packed with the UPX"),
        "sections": ("UPX0", "UPX1", "UPX2", ".UPX0"),
        "exports": (),
        "symbol_prefixes": (),
        "deployment_note": (
            "not a protection product, but its presence would mean the image on "
            "disk is not the image that executes, which changes every static "
            "conclusion in this repository"),
    },
)


# --------------------------------------------------------------------------- #
# signature table 2: the Windows API detection kit
#
# `benign` is not decoration. plan.md forbids presenting these imports as
# evidence of protection, and the only way to keep that promise mechanically is
# to attach the counter-reading to the datum so the two cannot be separated.
# `distinguishes` states what observation WOULD settle the question, and every
# one of them is a disassembly question -- which is the point.
# --------------------------------------------------------------------------- #

_BENIGN_CRASH_REPORTER = (
    "UE's crash reporter is built out of exactly these calls: it installs a "
    "handler, walks the faulting stack with dbghelp and writes a minidump. Any "
    "UE game has them")
_BENIGN_MODULE_ENUM = (
    "module and thread enumeration is what a symboliser needs in order to turn "
    "a return address into module+offset in the crash report")
_BENIGN_LOGGING = (
    "UE routes log output to the debugger when one is attached; the check gates "
    "a printf, not a policy")

_DISTINGUISH_CALLSITE = (
    "where it is called from, and whether the result reaches a branch that "
    "changes behaviour. Requires disassembly (M2)")
_DISTINGUISH_NOTHING = (
    "nothing needs distinguishing: this is the crash reporter, and shipping "
    "a crash reporter is what an engine does")
_DISTINGUISH_NOTHING_FINDING = (
    "nothing needs distinguishing: the presence of this call in a shipped "
    "game would itself be the finding, and would trigger the stop condition")
_DISTINGUISH_BLACKLIST = (
    "whether the enumerated names are compared against a blacklist rather "
    "than merely symbolised. Requires disassembly (M2)")
_BENIGN_NO_SERVICE_INSTALL = (
    "no benign explanation inside a shipped game: installing or starting a service "
    "needs administrator rights, and it is how a kernel-mode anti-cheat gets "
    "loaded")
API_KIT = (
    # --- the classic anti-debug probes ---------------------------------------
    {"name": "IsDebuggerPresent", "category": "anti-debug-probe",
     "weight": "low",
     "benign": _BENIGN_LOGGING,
     "distinguishes": _DISTINGUISH_CALLSITE},
    {"name": "CheckRemoteDebuggerPresent", "category": "anti-debug-probe",
     "weight": "high",
     "benign": (
         "has a legitimate use in a crash handler that wants to re-raise into an "
         "attached debugger, but UE does not call it; its presence would be "
         "unusual enough to be worth explaining"),
     "distinguishes": _DISTINGUISH_CALLSITE},
    {"name": "NtQueryInformationProcess", "category": "anti-debug-probe",
     "weight": "high",
     "benign": (
         "the documented way to read a process's PEB address, its exit status or "
         "its working-set watch; also used by symbolisers and by Microsoft's own "
         "dbghelp.dll. Becomes a detection primitive only with the "
         "ProcessDebugPort/ProcessDebugFlags/ProcessDebugObjectHandle classes"),
     "distinguishes": (
         "which ProcessInformationClass constant is passed. Requires "
         "disassembly (M2)")},
    {"name": "ZwQueryInformationProcess", "category": "anti-debug-probe",
     "weight": "high",
     "benign": ("the Zw alias of NtQueryInformationProcess; the identical "
                "routine reached under its other exported name"),
     "distinguishes": (
         "which ProcessInformationClass constant is passed. Requires "
         "disassembly (M2)")},
    {"name": "NtSetInformationThread", "category": "anti-debug-active",
     "weight": "high",
     "benign": (
         "sets thread affinity, ideal processor and impersonation; becomes an "
         "anti-debug primitive only with ThreadHideFromDebugger"),
     "distinguishes": (
         "which ThreadInformationClass constant is passed. Requires "
         "disassembly (M2)")},
    {"name": "DebugActiveProcess", "category": "anti-debug-active",
     "weight": "high",
     "benign": (
         "attaching a debugger to a child; the self-debugging trick uses it to "
         "occupy the debug port so no other debugger can attach"),
     "distinguishes": _DISTINGUISH_CALLSITE},
    {"name": "DebugActiveProcessStop", "category": "anti-debug-active",
     "weight": "high",
     "benign": ("the counterpart of DebugActiveProcess; a debugger that "
                "attaches has to be able to detach"),
     "distinguishes": _DISTINGUISH_CALLSITE},
    {"name": "NtQuerySystemInformation", "category": "anti-debug-probe",
     "weight": "medium",
     "benign": (
         "the documented route to process lists, handle tables and CPU counts; "
         "profilers and task-manager-like code use it constantly"),
     "distinguishes": (
         "which SystemInformationClass constant is passed -- "
         "SystemKernelDebuggerInformation is the detection case. Requires "
         "disassembly (M2)")},
    {"name": "OutputDebugStringA", "category": "debug-output",
     "weight": "low", "benign": _BENIGN_LOGGING,
     "distinguishes": _DISTINGUISH_CALLSITE},
    {"name": "OutputDebugStringW", "category": "debug-output",
     "weight": "low", "benign": _BENIGN_LOGGING,
     "distinguishes": _DISTINGUISH_CALLSITE},
    {"name": "DebugBreak", "category": "debug-output",
     "weight": "low",
     "benign": ("the assert path: UE_DEBUG_BREAK() compiles to it, and a "
                "failed check() in a debug-capable build lands here"),
     "distinguishes": _DISTINGUISH_CALLSITE},
    {"name": "DbgUiRemoteBreakin", "category": "anti-debug-active",
     "weight": "high",
     "benign": (
         "no ordinary use in application code; patching or hooking it is a "
         "documented way to make a remote debugger's break-in thread die"),
     "distinguishes": _DISTINGUISH_CALLSITE},
    {"name": "DbgBreakPoint", "category": "anti-debug-active",
     "weight": "medium",
     "benign": ("the ntdll breakpoint DbgUiRemoteBreakin calls; a debugger "
                "attach lands here and an assert can reach it too"),
     "distinguishes": _DISTINGUISH_CALLSITE},
    {"name": "NtSetDebugFilterState", "category": "anti-debug-probe",
     "weight": "high",
     "benign": ("no ordinary application use: it adjusts kernel debug-print "
                "filtering and needs debug privilege"),
     "distinguishes": _DISTINGUISH_CALLSITE},

    # --- exception machinery -------------------------------------------------
    {"name": "SetUnhandledExceptionFilter", "category": "exception-handling",
     "weight": "low", "benign": _BENIGN_CRASH_REPORTER,
     "distinguishes": (
         "whether the installed filter does anything except report. Requires "
         "disassembly (M2)")},
    {"name": "AddVectoredExceptionHandler", "category": "exception-handling",
     "weight": "low",
     "benign": (
         "UE installs a vectored handler for its own crash pipeline; it is also "
         "the standard way to implement a page-guard-based memory tracker"),
     "distinguishes": (
         "whether the handler inspects EXCEPTION_SINGLE_STEP or "
         "EXCEPTION_BREAKPOINT and reacts to it. Requires disassembly (M2)")},
    {"name": "RemoveVectoredExceptionHandler", "category": "exception-handling",
     "weight": "low",
     "benign": ("the counterpart of AddVectoredExceptionHandler; a handler "
                "that is installed has to be removable"),
     "distinguishes": _DISTINGUISH_CALLSITE},

    # --- crash reporting ----------------------------------------------------
    {"name": "MiniDumpWriteDump", "category": "crash-reporting",
     "weight": "low", "benign": _BENIGN_CRASH_REPORTER,
     "distinguishes": _DISTINGUISH_NOTHING},
    {"name": "SymInitialize", "category": "crash-reporting",
     "weight": "low", "benign": _BENIGN_CRASH_REPORTER,
     "distinguishes": _DISTINGUISH_NOTHING},
    {"name": "SymInitializeW", "category": "crash-reporting",
     "weight": "low", "benign": _BENIGN_CRASH_REPORTER,
     "distinguishes": _DISTINGUISH_NOTHING},
    {"name": "StackWalk64", "category": "crash-reporting",
     "weight": "low", "benign": _BENIGN_CRASH_REPORTER,
     "distinguishes": _DISTINGUISH_NOTHING},

    # --- process and thread inspection --------------------------------------
    {"name": "CreateToolhelp32Snapshot", "category": "process-inspection",
     "weight": "low", "benign": _BENIGN_MODULE_ENUM,
     "distinguishes": _DISTINGUISH_BLACKLIST},
    {"name": "Process32FirstW", "category": "process-inspection",
     "weight": "low", "benign": _BENIGN_MODULE_ENUM,
     "distinguishes": _DISTINGUISH_BLACKLIST},
    {"name": "Module32FirstW", "category": "process-inspection",
     "weight": "low", "benign": _BENIGN_MODULE_ENUM,
     "distinguishes": _DISTINGUISH_BLACKLIST},
    {"name": "K32EnumProcessModules", "category": "process-inspection",
     "weight": "low", "benign": _BENIGN_MODULE_ENUM,
     "distinguishes": _DISTINGUISH_BLACKLIST},
    {"name": "OpenProcess", "category": "process-inspection",
     "weight": "low",
     "benign": (
         "needed to read another process's modules; UE opens its own process "
         "handle for the crash reporter and for memory statistics"),
     "distinguishes": (
         "which process is opened and with which access mask. Requires "
         "disassembly (M2)")},
    {"name": "OpenThread", "category": "process-inspection",
     "weight": "low",
     "benign": ("a handle to each of the other threads is what the crash "
                "reporter needs before it can suspend and walk them"),
     "distinguishes": _DISTINGUISH_CALLSITE},
    {"name": "GetThreadContext", "category": "process-inspection",
     "weight": "medium",
     "benign": (
         "a minidump of a non-faulting thread needs its register context; this "
         "is how UE gets it"),
     "distinguishes": (
         "whether CONTEXT_DEBUG_REGISTERS is requested and Dr0-Dr7 examined -- "
         "that is the hardware-breakpoint check. Requires disassembly (M2)")},
    {"name": "SetThreadContext", "category": "anti-debug-active",
     "weight": "high",
     "benign": (
         "legitimate in a fibre or coroutine implementation and in a debugger; "
         "clearing Dr0-Dr7 through it is the hardware-breakpoint wipe"),
     "distinguishes": (
         "whether the written context clears the debug registers. Requires "
         "disassembly (M2)")},
    {"name": "SuspendThread", "category": "process-inspection",
     "weight": "low",
     "benign": ("a minidump has to freeze the other threads first, or the "
                "stacks it captures are mutually inconsistent"),
     "distinguishes": _DISTINGUISH_CALLSITE},

    # --- memory manipulation ------------------------------------------------
    {"name": "VirtualProtect", "category": "memory-manipulation",
     "weight": "low",
     "benign": (
         "every JIT, every executable-page allocator and UE's own "
         "FPlatformMemory page helpers need it"),
     "distinguishes": (
         "whether it is used to make .text writable and then patch it -- a "
         "self-modifying integrity or unpacking step. Requires disassembly (M2)")},
    {"name": "VirtualProtectEx", "category": "memory-manipulation",
     "weight": "medium",
     "benign": ("the cross-process form of VirtualProtect; profilers, "
                "debuggers, injectors and a parent setting up a child all "
                "use it"),
     "distinguishes": _DISTINGUISH_CALLSITE},
    {"name": "VirtualAllocEx", "category": "memory-manipulation",
     "weight": "medium",
     "benign": ("the cross-process form of VirtualAlloc; also how a profiler "
                "or a helper process places a buffer in a child"),
     "distinguishes": _DISTINGUISH_CALLSITE},
    {"name": "WriteProcessMemory", "category": "memory-manipulation",
     "weight": "high",
     "benign": (
         "used by legitimate tooling; in a game process it is the primitive an "
         "injector or a patcher needs"),
     "distinguishes": _DISTINGUISH_CALLSITE},
    {"name": "ReadProcessMemory", "category": "memory-manipulation",
     "weight": "medium",
     "benign": ("reading another process, and also the documented way to "
                "read one's own image through a handle rather than a raw "
                "pointer"),
     "distinguishes": _DISTINGUISH_CALLSITE},
    {"name": "NtProtectVirtualMemory", "category": "memory-manipulation",
     "weight": "high",
     "benign": "the ntdll form of VirtualProtect, reached by name only when the "
               "caller deliberately bypasses kernel32",
     "distinguishes": _DISTINGUISH_CALLSITE},
    {"name": "NtReadVirtualMemory", "category": "memory-manipulation",
     "weight": "high",
     "benign": ("the ntdll form of ReadProcessMemory, reached by name only "
                "when the caller deliberately bypasses kernel32"),
     "distinguishes": _DISTINGUISH_CALLSITE},
    {"name": "NtWriteVirtualMemory", "category": "memory-manipulation",
     "weight": "high",
     "benign": ("the ntdll form of WriteProcessMemory, reached by name only "
                "when the caller deliberately bypasses kernel32"),
     "distinguishes": _DISTINGUISH_CALLSITE},
    {"name": "FlushInstructionCache", "category": "memory-manipulation",
     "weight": "low",
     "benign": ("required after any legitimate code write, a JIT and a "
                "trampoline included; on x64 it is often a no-op kept for "
                "portability"),
     "distinguishes": _DISTINGUISH_CALLSITE},

    # --- injection / hooking ------------------------------------------------
    {"name": "SetWindowsHookEx", "category": "injection",
     "weight": "medium",
     "benign": (
         "the documented way to observe keyboard and mouse input globally; also "
         "a system-wide DLL injection route"),
     "distinguishes": _DISTINGUISH_CALLSITE},
    {"name": "NtCreateThreadEx", "category": "injection",
     "weight": "high",
     "benign": ("the ntdll form of CreateRemoteThread; also how some thread "
                "pools create a thread with a non-default stack"),
     "distinguishes": _DISTINGUISH_CALLSITE},
    {"name": "CreateRemoteThread", "category": "injection",
     "weight": "high",
     "benign": ("no ordinary in-game use: it is the classic DLL-injection "
                "primitive, and also how a debugger forces a break-in"),
     "distinguishes": _DISTINGUISH_CALLSITE},
    {"name": "LdrRegisterDllNotification", "category": "injection",
     "weight": "high",
     "benign": (
         "a documented way to observe module loads; also how a protection layer "
         "vetoes an injected module"),
     "distinguishes": _DISTINGUISH_CALLSITE},

    # --- kernel driver / service surface ------------------------------------
    {"name": "OpenSCManagerW", "category": "service-control",
     "weight": "medium",
     "benign": (
         "opening the service database is also required merely to QUERY a "
         "service; UE and several vendor SDKs query driver services to report "
         "GPU and audio driver versions"),
     "distinguishes": (
         "whether the access mask is read-only and whether CreateService or "
         "StartService follows. Requires disassembly (M2)")},
    {"name": "OpenServiceW", "category": "service-control",
     "weight": "medium",
     "benign": ("a handle to a named service is required to read its status "
                "or its binary path; a driver-version query needs exactly "
                "this and nothing more"),
     "distinguishes": (
         "whether the access mask is read-only and whether CreateService or "
         "StartService follows. Requires disassembly (M2)")},
    {"name": "QueryServiceConfigW", "category": "service-control",
     "weight": "low",
     "benign": ("reads a service's configuration, including the ImagePath of a "
                "driver. Asking the display driver's service where its binary "
                "lives is how a renderer reports the driver version"),
     "distinguishes": ("nothing needs distinguishing: a configuration query "
                       "cannot install, start or load anything")},
    {"name": "CloseServiceHandle", "category": "service-control",
     "weight": "low",
     "benign": ("closes what OpenSCManager or OpenService returned; its presence "
                "says only that a service handle was opened somewhere"),
     "distinguishes": ("nothing needs distinguishing: closing a handle is not an "
                       "operation on a service")},
    {"name": "QueryServiceStatus", "category": "service-control",
     "weight": "low", "benign": "read-only; consistent with a version query",
     "distinguishes": ("nothing needs distinguishing: a status query cannot "
                       "install, start or load anything")},
    {"name": "CreateServiceW", "category": "service-install",
     "weight": "high", "benign": _BENIGN_NO_SERVICE_INSTALL,
     "distinguishes": _DISTINGUISH_NOTHING_FINDING},
    {"name": "CreateServiceA", "category": "service-install",
     "weight": "high", "benign": _BENIGN_NO_SERVICE_INSTALL,
     "distinguishes": _DISTINGUISH_NOTHING_FINDING},
    {"name": "StartServiceW", "category": "service-install",
     "weight": "high", "benign": _BENIGN_NO_SERVICE_INSTALL,
     "distinguishes": _DISTINGUISH_NOTHING_FINDING},
    {"name": "NtLoadDriver", "category": "service-install",
     "weight": "high",
     "benign": ("none in user-mode application code: loading a driver is a "
                "privileged operation a shipped game has no reason to "
                "perform"),
     "distinguishes": _DISTINGUISH_NOTHING_FINDING},
    {"name": "ZwLoadDriver", "category": "service-install",
     "weight": "high",
     "benign": ("the Zw alias of NtLoadDriver: the same privileged operation "
                "under its other exported name"),
     "distinguishes": _DISTINGUISH_NOTHING_FINDING},
    {"name": "DeviceIoControl", "category": "driver-communication",
     "weight": "medium",
     "benign": (
         "the ordinary route to any device: volume geometry, HID, GPU, audio. "
         "Only meaningful together with a device path that names a protection "
         "driver"),
     "distinguishes": (
         "which device is opened. Requires disassembly (M2) or a runtime handle "
         "listing")},
)

# Kernel-mode-only routines. If any of these names appears in a user-mode image
# in this install, something is very wrong with the reading -- they can only
# occur inside a .sys file. They are searched precisely so that their absence is
# an explicit, recorded observation rather than an assumption.
KERNEL_ONLY_NEEDLES = (
    "ObRegisterCallbacks",
    "PsSetCreateProcessNotifyRoutine",
    "PsSetCreateProcessNotifyRoutineEx",
    "PsSetLoadImageNotifyRoutine",
    "PsSetCreateThreadNotifyRoutine",
    "CmRegisterCallbackEx",
    "IoCreateDevice",
    "MmGetSystemRoutineAddress",
    "KeStackAttachProcess",
    "DriverEntry",
)

# The information classes and register names that turn an ambiguous API into a
# detection primitive. Searched as text because a build that resolves them by
# name leaves the name behind.
DETECTION_CONSTANT_NEEDLES = (
    "ProcessDebugPort",
    "ProcessDebugFlags",
    "ProcessDebugObjectHandle",
    "ThreadHideFromDebugger",
    "SystemKernelDebuggerInformation",
    "CONTEXT_DEBUG_REGISTERS",
    "BeingDebugged",
    "NtGlobalFlag",
    "HeapValidate",
)

# The GPU-driver enumeration idiom. These are NOT protection indicators -- they
# are the neighbourhood that EXPLAINS a service-control hit, and they exist in
# this table so that the explanation is re-testable instead of asserted.
#
# Reading a display driver's version on Windows means: enumerate adapters
# (D3DKMTEnumAdapters*), find the device (SetupDi*), read the driver's service
# configuration to get its ImagePath (OpenSCManager -> OpenService ->
# QueryServiceConfig -> CloseServiceHandle), and look at the registry keys the
# ICD loaders use. A service-control hit surrounded by these is a version query;
# a service-control hit surrounded by CreateService and StartService is
# something else entirely, and the tool reports which neighbourhood it found.
SERVICE_CONTEXT_NEEDLES = (
    "nvapi_QueryInterface",
    "D3DKMTEnumAdapters2",
    "D3DKMTEnumAdapters3",
    "D3DKMTQueryAdapterInfo",
    "SetupDiGetClassDevsW",
    "SetupDiGetDeviceRegistryPropertyW",
    "SetupGetInfDriverStoreLocationW",
    "DriverSupportModules",
    "SOFTWARE\\Khronos\\Vulkan\\Drivers",
    "SYSTEM\\CurrentControlSet\\Control\\Class\\",
)

# Debugger, hypervisor and sandbox vocabulary. Matched case-insensitively but
# still delimiter-checked, because "frida" inside "Friday" and "vac" inside
# "evacuate" are exactly the false positives a naive scan produces.
VM_AND_TOOL_NEEDLES = (
    "VMware", "VirtualBox", "VBoxGuest", "VBoxService", "QEMU", "Xen",
    "Hyper-V", "hypervisor", "SbieDll", "Sandboxie",
    "x64dbg", "x32dbg", "OllyDbg", "WinDbg", "ImmunityDebugger",
    "ScyllaHide", "TitanEngine", "Cheat Engine", "CheatEngine", "cheatengine",
    "Frida", "frida-agent", "MinHook", "Detours", "DetourFunction",
    "ida64", "idaq", "HxD", "ProcessHacker", "Process Hacker",
    "debugger detected", "debugger present", "kernel debugger",
    "anti-tamper", "antitamper", "tamper detected", "integrity violation",
    "cheat detected", "hack detected",
)


# The bare vocabulary the task brief asks for by name: "debugger", "cheat",
# "tamper", "integrity", "hook" and their neighbours. These are HIGH-NOISE in an
# Unreal Engine image -- "hook" appears in delegate and mesh identifiers, "patch"
# in streaming and in mesh patches, "integrity" in the net package-map CVar
# descriptions -- so they are COUNTED and SAMPLED and never interpreted. They
# earn their place because a count of zero is informative and cheap, and because
# "we looked for the obvious words" should be a checkable claim rather than an
# assurance. Delimited, so "hook" does not match "hookup" and "cheat" does not
# match "cheatsheet".
BROAD_VOCABULARY_NEEDLES = (
    "debugger", "debuggers", "debugging",
    "cheat", "cheats", "cheater", "cheating",
    "tamper", "tampered", "tampering",
    "integrity",
    "hook", "hooks", "hooked", "hooking",
    "inject", "injected", "injection",
    "bypass", "bypassed",
    "crack", "cracked",
    "banned", "ban",
    "detected", "violation",
)


PACKER_SECTION_NAMES = {}
for _entry in MIDDLEWARE:
    for _name in _entry["sections"]:
        PACKER_SECTION_NAMES.setdefault(_name.lower(), []).append(_entry["display"])


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #

def now_iso_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hex_bytes(raw: bytes) -> str:
    return raw.hex()


def dump_json(document: dict) -> str:
    """Deterministic serialization: sorted keys, indent 2, LF, trailing newline."""
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _printable(raw: bytes) -> str:
    """A bounded, printable rendering. Non-printables become '.', never dropped."""
    return "".join(chr(byte) if 32 <= byte < 127 else "." for byte in raw)


# --------------------------------------------------------------------------- #
# the string matcher
# --------------------------------------------------------------------------- #

_IDENTIFIER_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")


class Needle:
    """One byte pattern to look for, plus everything needed to judge a hit.

    ``delimited`` is the part that matters. A raw substring search for a short
    token produces nonsense: "frida" occurs inside "Friday", "vac" inside
    "evacuate", "nprotect" inside "unprotectedAttrs", "ceg" inside dozens of
    words. Requiring a non-identifier byte on both sides of the match removes
    that whole class of error, and the number of candidates it rejects is
    reported so a reader can see the filter doing work.
    """

    __slots__ = ("text", "group", "category", "case_sensitive", "delimited",
                 "detail")

    def __init__(self, text: str, group: str, category: str, *,
                 case_sensitive: bool = True, delimited: bool = True,
                 detail: dict | None = None) -> None:
        self.text = text
        self.group = group
        self.category = category
        self.case_sensitive = case_sensitive
        self.delimited = delimited
        self.detail = detail or {}


class NeedleSet:
    """A compiled group of needles, searchable in ASCII and UTF-16LE.

    Three design points, each forced by measurement rather than taste, because
    this matcher has to cover gigabytes:

    1. ``bytes.find`` per key, NOT one big regex. Measured on a 16 MiB window of
       the real Shipping image with a 356-key table: a regex alternation with one
       capture group per branch runs at 0.3 MB/s -- the group bookkeeping defeats
       the engine's literal scan -- the same alternation without capture groups
       at 3.1 MB/s, and a plain ``find`` loop per key at 7.4 MB/s. ``find`` is a
       memchr-based scan in C, and paying for it once per key beats paying for a
       several-hundred-branch alternation at every byte position. The table has
       grown since that measurement; the ordering of the three has not.
    2. NO re.IGNORECASE. Keys are lowered once at construction and searched in a
       lowered COPY of the buffer. ``bytes.lower()`` is a C-speed byte map that
       only touches ASCII A-Z, so offsets are preserved exactly and UTF-16LE
       high bytes are untouched. Case-SENSITIVE needles are then verified
       against the original buffer, and a wrong-case match is counted and
       dropped. Both encodings share one key space; a UTF-16LE key cannot
       collide with an ASCII one because it is full of NUL bytes.
    3. The DELIMITER test. A raw substring search for a short token produces
       nonsense: "frida" occurs inside "Friday", "vac" inside "evacuate",
       "nprotect" inside "unprotectedAttrs", "ceg" inside dozens of words.
       Requiring a non-identifier code unit on both sides of the match removes
       that whole class of error, and the number of candidates it rejects is
       reported so a reader can see the filter doing work. It also resolves
       nesting for free: "EasyAntiCheat" inside "EasyAntiCheat_x64" is rejected
       because "_" is an identifier byte, while the longer needle is kept.
    """

    def __init__(self, needles) -> None:
        self.needles = list(needles)
        too_long = [needle.text for needle in self.needles
                    if len(needle.text.encode("utf-16-le")) > MAX_NEEDLE_BYTES]
        if too_long:
            raise ValueError("needle longer than the scan overlap allows: %s"
                             % ", ".join(sorted(too_long)))
        # key (lowered, encoded) -> {"stride", "needles", "exact"}
        self._by_key: dict[bytes, dict] = {}
        for needle in self.needles:
            for encoding, stride in (("ascii", 1), ("utf-16-le", 2)):
                lowered = needle.text.lower().encode(encoding, "ignore")
                if not lowered:
                    continue
                entry = self._by_key.setdefault(lowered, {
                    "stride": stride, "needles": [], "exact": {}})
                entry["needles"].append(needle)
                if needle.case_sensitive:
                    # The exact bytes this needle demands, for the case check.
                    entry["exact"][needle.text] = needle.text.encode(encoding)
        # Deterministic key order: longest first, then bytewise. The order does
        # not change WHICH hits are found -- every key is searched -- it fixes
        # the order in which they reach the sink, and this tool promises
        # byte-identical output across runs.
        self._order = sorted(self._by_key, key=lambda item: (-len(item), item))

    # -- delimiter test ----------------------------------------------------- #

    @staticmethod
    def _unit_is_identifier(buffer: bytes, index: int, stride: int) -> bool:
        """Is the code unit starting at *index* an ASCII identifier character?

        For UTF-16LE a unit is two bytes and only counts as an identifier
        character when the high byte is zero, so ``\x41\x04`` (Cyrillic A) is
        correctly treated as a delimiter rather than as a letter.
        """
        if index < 0 or index + stride > len(buffer):
            return False
        if stride == 2 and buffer[index + 1] != 0:
            return False
        return buffer[index] in _IDENTIFIER_BYTES

    def search(self, buffer: bytes, base_offset: int, sink) -> dict:
        """Run the pattern over *buffer*; call ``sink(hit)`` per accepted match.

        Returns the counters, including how many candidates the delimiter and
        case tests rejected -- the numbers that show those filters are real.
        """
        stats = {"candidates": 0, "rejected_undelimited": 0,
                 "rejected_wrong_case": 0, "accepted": 0}
        if not self._order:
            return stats
        lowered = buffer.lower()
        found: list[tuple[int, bytes]] = []
        for key in self._order:
            position = lowered.find(key)
            while position >= 0:
                found.append((position, key))
                position = lowered.find(key, position + 1)
        # Emitted in data order, not dict order, so the document is stable.
        found.sort(key=lambda item: (item[0], -len(item[1]), item[1]))
        for start, key in found:
            stats["candidates"] += 1
            entry = self._by_key[key]
            stride = entry["stride"]
            end = start + len(key)
            original = buffer[start:end]

            candidates = []
            wrong_case = False
            for needle in entry["needles"]:
                if needle.case_sensitive:
                    if entry["exact"].get(needle.text) != original:
                        wrong_case = True
                        continue
                candidates.append(needle)
            if not candidates:
                if wrong_case:
                    stats["rejected_wrong_case"] += 1
                continue

            if any(needle.delimited for needle in candidates):
                before = self._unit_is_identifier(buffer, start - stride, stride)
                after = self._unit_is_identifier(buffer, end, stride)
                if before or after:
                    stats["rejected_undelimited"] += 1
                    continue

            stats["accepted"] += 1
            context_start = max(0, start - CONTEXT_BYTES)
            context_end = min(len(buffer), end + CONTEXT_BYTES)
            for needle in candidates:
                sink({
                    "needle": needle.text,
                    "group": needle.group,
                    "category": needle.category,
                    "encoding": "utf-16le" if stride == 2 else "ascii",
                    "offset": base_offset + start,
                    "length": end - start,
                    # From the ORIGINAL buffer, never the lowered copy: the
                    # document should show the casing the file actually uses.
                    "matched_text": original.decode(
                        "utf-16-le" if stride == 2 else "latin-1", "replace"),
                    "context": _printable(buffer[context_start:context_end]),
                    "detail": needle.detail,
                })
        return stats



def build_needle_set() -> NeedleSet:
    """Every needle this tool knows, in one set. Used for PE modules and text."""
    needles: list[Needle] = []
    for entry in MIDDLEWARE:
        for text in entry["strings"]:
            needles.append(Needle(
                text, "middleware", entry["family"], case_sensitive=False,
                detail={"middleware_id": entry["id"],
                        "middleware": entry["display"]}))
        for text in entry["exports"]:
            needles.append(Needle(
                text, "middleware-export", entry["family"],
                detail={"middleware_id": entry["id"],
                        "middleware": entry["display"]}))
    for entry in API_KIT:
        needles.append(Needle(
            entry["name"], "api-kit", entry["category"],
            detail={"weight": entry["weight"], "benign": entry["benign"],
                    "distinguishes": entry["distinguishes"]}))
    for text in KERNEL_ONLY_NEEDLES:
        needles.append(Needle(text, "kernel-only", "kernel-mode-routine"))
    for text in DETECTION_CONSTANT_NEEDLES:
        needles.append(Needle(text, "detection-constant", "detection-primitive"))
    for text in SERVICE_CONTEXT_NEEDLES:
        needles.append(Needle(text, "service-context", "gpu-driver-enumeration"))
    for text in VM_AND_TOOL_NEEDLES:
        needles.append(Needle(text, "vm-and-tool-vocabulary", "vocabulary",
                              case_sensitive=False))
    for text in BROAD_VOCABULARY_NEEDLES:
        needles.append(Needle(text, "broad-vocabulary", "counted-not-interpreted",
                              case_sensitive=False))
    return NeedleSet(needles)


def build_wide_needle_set() -> NeedleSet:
    """The small subset applied to EVERY file, containers included.

    Kept deliberately short: this set is run over gigabytes of container data,
    and the whole-install pass is only worth having if it finishes. It holds the
    middleware product names and the kernel-mode routine names -- the two things
    whose presence anywhere in the installation would matter regardless of which
    file held them.
    """
    needles: list[Needle] = []
    for entry in MIDDLEWARE:
        for text in entry["strings"]:
            needles.append(Needle(
                text, "middleware", entry["family"], case_sensitive=False,
                detail={"middleware_id": entry["id"],
                        "middleware": entry["display"]}))
    for text in KERNEL_ONLY_NEEDLES:
        needles.append(Needle(text, "kernel-only", "kernel-mode-routine"))
    return NeedleSet(needles)


def self_test_needle_set(needle_set: NeedleSet) -> dict:
    """Prove the matcher fires, before believing anything it did not find.

    Each needle is embedded in a synthetic buffer, delimited by spaces, in both
    encodings, and the set is run over it. A needle that does not come back is
    reported by name. Without this, "found nothing" and "looked for nothing"
    produce the same document.
    """
    missing: list[str] = []
    for needle in needle_set.needles:
        found = False

        def sink(hit, wanted=needle.text):
            nonlocal found
            if hit["needle"] == wanted:
                found = True

        for encoding in ("ascii", "utf-16-le"):
            try:
                payload = (" " + needle.text + " ").encode(encoding)
            except UnicodeEncodeError:      # pragma: no cover - table is ASCII
                continue
            needle_set.search(b"\x00\x00" + payload + b"\x00\x00", 0, sink)
        if not found:
            missing.append(needle.text)
    return {
        "needles_declared": len(needle_set.needles),
        "needles_that_fired": len(needle_set.needles) - len(missing),
        "needles_that_did_not_fire": sorted(set(missing)),
        "passed": not missing,
        "what_it_proves": (
            "the matcher, the encodings and the delimiter test are live for every "
            "declared needle. It does NOT prove the needle table is complete -- "
            "a product that renamed itself, or one built without any of these "
            "strings, is invisible to a name table by construction"),
    }


def scan_file(path: str, needle_set: NeedleSet, *,
              section_lookup=None) -> dict:
    """Stream *path* and collect every needle hit. Read-only, bounded memory.

    Chunks overlap by twice the longest needle so a hit that straddles a read
    boundary is still found exactly once: matches whose start lies inside the
    carried-over prefix of a later chunk are discarded, because the previous
    chunk already had the whole match in view.
    """
    hits: dict[tuple, dict] = {}
    stats = {"candidates": 0, "rejected_undelimited": 0,
             "rejected_wrong_case": 0, "accepted": 0, "bytes_scanned": 0}
    seen: set[tuple] = set()

    def sink(hit):
        key = (hit["needle"], hit["encoding"], hit["offset"])
        if key in seen:
            return
        seen.add(key)
        bucket = hits.setdefault((hit["needle"], hit["encoding"]), {
            "needle": hit["needle"],
            "group": hit["group"],
            "category": hit["category"],
            "encoding": hit["encoding"],
            "detail": hit["detail"],
            "count": 0,
            "occurrences": [],
        })
        bucket["count"] += 1
        if len(bucket["occurrences"]) < MAX_HITS_PER_NEEDLE_PER_FILE:
            record = {
                "offset": hit["offset"],
                "length": hit["length"],
                "matched_text": hit["matched_text"],
                "context": hit["context"],
            }
            if section_lookup is not None:
                section = section_lookup(hit["offset"])
                record["section"] = section["name"] if section else None
                record["section_is_executable"] = (
                    bool(section["executable"]) if section else None)
            bucket["occurrences"].append(record)

    with open(path, "rb", buffering=0) as handle:
        carried = b""
        position = 0
        while True:
            chunk = handle.read(SCAN_CHUNK)
            if not chunk:
                break
            buffer = carried + chunk
            base = position - len(carried)
            chunk_stats = needle_set.search(buffer, base, sink)
            for key in ("candidates", "rejected_undelimited",
                        "rejected_wrong_case", "accepted"):
                stats[key] += chunk_stats[key]
            position += len(chunk)
            stats["bytes_scanned"] = position
            carried = buffer[-SCAN_OVERLAP:] if len(buffer) > SCAN_OVERLAP else buffer

    ordered = sorted(hits.values(),
                     key=lambda item: (item["needle"], item["encoding"]))
    for bucket in ordered:
        bucket["occurrences"].sort(key=lambda item: item["offset"])
        bucket["occurrences_truncated"] = (
            bucket["count"] > len(bucket["occurrences"]))
    return {"hits": ordered, "stats": stats}


# --------------------------------------------------------------------------- #
# the PE surfaces
# --------------------------------------------------------------------------- #

def make_section_lookup(sections: list[dict]):
    """file offset -> the section whose RAW range contains it, or None."""
    rows = []
    for section in sections:
        pointer = section.get("raw_pointer") or 0
        size = section.get("rsize") or 0
        if size <= 0:
            continue
        rows.append({
            "name": section.get("name"),
            "start": pointer,
            "end": pointer + size,
            "executable": bool(int(section.get("characteristics", "0x0"), 16)
                               & 0x20000000)
            if isinstance(section.get("characteristics"), str)
            else False,
        })
    rows.sort(key=lambda item: item["start"])

    def lookup(offset: int):
        for row in rows:
            if row["start"] <= offset < row["end"]:
                return row
        return None

    return lookup


def rva_section(sections: list[dict], rva: int):
    for section in sections:
        start = section.get("rva") or 0
        span = max(section.get("vsize") or 0, section.get("rsize") or 0)
        if start <= rva < start + span:
            return section
    return None


def rva_to_offset(sections: list[dict], rva: int) -> int | None:
    for section in sections:
        start = section.get("rva") or 0
        raw = section.get("rsize") or 0
        if raw and start <= rva < start + raw:
            return (section.get("raw_pointer") or 0) + (rva - start)
    return None


def flatten_imports(pe: dict) -> list[dict]:
    """Every imported symbol of a module, normal and delay-load, in one list."""
    rows: list[dict] = []
    for kind, key in (("import", "imports"), ("delay-import", "delay_imports")):
        for module in (pe.get(key) or []):
            dll = (module.get("dll") or "").lower()
            for function in module.get("functions") or []:
                rows.append({
                    "kind": kind,
                    "dll": dll,
                    "name": function.get("name"),
                    "ordinal": function.get("ordinal"),
                })
    rows.sort(key=lambda item: (item["dll"], item["name"] or "",
                               item["ordinal"] if item["ordinal"] is not None else -1))
    return rows


def module_section_findings(pe: dict) -> list[dict]:
    """Packer section names, W+X sections and high-entropy sections.

    High entropy alone is never a finding: compressed textures, embedded
    archives and signature blobs all look the same to an entropy meter. It is
    reported together with the two facts that would make it suspicious -- the
    section being executable, and the module having no readable import table.
    """
    findings: list[dict] = []
    imports = pe.get("imports")
    has_imports = bool(imports)
    for section in pe.get("sections") or []:
        name = (section.get("name") or "")
        lowered = name.lower()
        if lowered in PACKER_SECTION_NAMES:
            findings.append({
                "kind": "known-protector-section-name",
                "section": name,
                "attributed_to": sorted(PACKER_SECTION_NAMES[lowered]),
                "rva": section.get("rva"),
                "raw_pointer": section.get("raw_pointer"),
                "rsize": section.get("rsize"),
                "severity": "high",
            })
        characteristics = section.get("characteristics")
        flags = int(characteristics, 16) if isinstance(characteristics, str) else 0
        executable = bool(flags & 0x20000000)
        writable = bool(flags & 0x80000000)
        if executable and writable:
            findings.append({
                "kind": "writable-executable-section",
                "section": name,
                "rva": section.get("rva"),
                "raw_pointer": section.get("raw_pointer"),
                "rsize": section.get("rsize"),
                "severity": "medium",
                "note": ("W+X is what a self-modifying or self-decrypting image "
                         "needs; it is also what some link configurations produce "
                         "for a tiny data section"),
            })
        entropy = section.get("entropy")
        if entropy is not None and entropy >= HIGH_ENTROPY_THRESHOLD \
                and (section.get("rsize") or 0) >= 4096:
            findings.append({
                "kind": "high-entropy-section",
                "section": name,
                "entropy": entropy,
                "executable": executable,
                "module_has_import_table": has_imports,
                "rsize": section.get("rsize"),
                "severity": ("medium" if executable or not has_imports else "low"),
                "note": ("entropy alone means nothing: compressed data, encrypted "
                         "data and a signature blob are indistinguishable to this "
                         "measure. It matters only if the section is executable or "
                         "the module has no import table"),
            })
    findings.sort(key=lambda item: (item["kind"], item["section"] or ""))
    return findings


UNW_FLAG_EHANDLER = 0x1
UNW_FLAG_UHANDLER = 0x2
UNW_FLAG_CHAININFO = 0x4


def runtime_function_at(headers, rva: int) -> dict | None:
    """The RUNTIME_FUNCTION whose range contains *rva*, found by binary search.

    The .pdata array is sorted by BeginAddress -- that is what makes the OS able
    to unwind at all -- so a bounded binary search is exact and costs about
    twenty 12-byte reads even in an image with 900 000 entries.
    """
    directory_rva, size = headers.directory(pe_info.DIR_EXCEPTION)
    if not directory_rva or not size:
        return None
    available = headers.rva_available(directory_rva)
    count = min(size, available) // 12
    if count <= 0:
        return None
    low, high = 0, count - 1
    while low <= high:
        middle = (low + high) // 2
        try:
            raw = headers.read_rva(directory_rva + middle * 12, 12,
                                   "RUNTIME_FUNCTION")
        except PEFormatError:
            return None
        begin, end, unwind = struct.unpack("<III", raw)
        if rva < begin:
            high = middle - 1
        elif rva >= end:
            low = middle + 1
        else:
            return {"index": middle, "begin_address": begin, "end_address": end,
                    "unwind_info_address": unwind}
    return None


def unwind_info_at(headers, unwind_rva: int) -> dict | None:
    """UNWIND_INFO as fields, read literally. Not a disassembly.

    This is the closest a header-level tool can get to "what kind of code is
    this". It cannot say what the function does. It CAN say the function was
    emitted by a compiler with a normal prologue and no exception handler --
    which is exactly the shape a hand-written anti-debug stub does not have, and
    exactly what a CRT helper does.
    """
    if not unwind_rva:
        return None
    try:
        raw = headers.read_rva(unwind_rva, 4, "UNWIND_INFO")
    except PEFormatError:
        return None
    first, prolog, code_count, frame = struct.unpack("<BBBB", raw)
    version = first & 0x07
    flags = first >> 3
    info = {
        "unwind_info_rva": unwind_rva,
        "version": version,
        "flags": flags,
        "flag_names": sorted(
            name for bit, name in ((UNW_FLAG_EHANDLER, "EHANDLER"),
                                   (UNW_FLAG_UHANDLER, "UHANDLER"),
                                   (UNW_FLAG_CHAININFO, "CHAININFO"))
            if flags & bit),
        "size_of_prolog": prolog,
        "count_of_unwind_codes": code_count,
        "frame_register": frame & 0x0F,
        "frame_offset": (frame >> 4) * 16,
        "exception_handler_rva": None,
    }
    if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER):
        padded = code_count + (code_count & 1)
        try:
            handler = headers.read_rva(unwind_rva + 4 + padded * 2, 4,
                                       "UNWIND_INFO handler")
            info["exception_handler_rva"] = struct.unpack("<I", handler)[0]
        except PEFormatError:
            pass
    return info


def tls_callback_code_probe(path: str, callbacks: list[dict]) -> list[dict]:
    """For each TLS callback: is it a function start with normal unwind data?

    Deliberately bounded. It answers "what are these NOT" -- not a stub, not
    code without unwind data, not something outside the function table -- and it
    stops exactly where disassembly would have to begin.
    """
    if not callbacks:
        return []
    rows: list[dict] = []
    try:
        with pe_info.Image.open(path) as image:
            headers = pe_info.PEHeaders(image)
            for callback in callbacks:
                rva = callback["rva"]
                function = runtime_function_at(headers, rva)
                row = {
                    "index": callback["index"],
                    "rva": rva,
                    "rva_hex": "0x%x" % rva,
                    "has_runtime_function": function is not None,
                    "is_function_start": bool(
                        function and function["begin_address"] == rva),
                    "runtime_function": function,
                    "function_length": (function["end_address"]
                                        - function["begin_address"])
                    if function else None,
                    "unwind": None,
                    "first_bytes_hex": None,
                }
                if function:
                    row["unwind"] = unwind_info_at(
                        headers, function["unwind_info_address"])
                offset = callback.get("file_offset")
                if offset is not None:
                    try:
                        row["first_bytes_hex"] = hex_bytes(
                            image.read_at(offset, 16, "TLS callback head"))
                    except PEFormatError:
                        pass
                rows.append(row)
    except PEFormatError:
        return []
    return rows


def module_tls_surface(document: dict, path: str) -> dict:
    """The TLS directory and callback array, with a section per callback.

    A TLS callback runs BEFORE the image entry point, so it is the earliest code
    the process can execute and therefore the classic anti-debug hook site. What
    the callbacks DO cannot be read off the directory; what they ARE NOT can.
    Every field below is a literal reading plus a section attribution.
    """
    pe = document["pe"]
    extended = document["pe_extended"]
    sections = pe.get("sections") or []
    tls = pe.get("tls") or {}
    detail = extended.get("tls_detail") or {}
    image_base = pe.get("image_base") or 0

    callbacks = []
    for index, virtual_address in enumerate(tls.get("callbacks") or []):
        rva = virtual_address - image_base if virtual_address >= image_base \
            else virtual_address
        section = rva_section(sections, rva)
        callbacks.append({
            "index": index,
            "virtual_address": virtual_address,
            "virtual_address_hex": "0x%x" % virtual_address,
            "rva": rva,
            "rva_hex": "0x%x" % rva,
            "file_offset": rva_to_offset(sections, rva),
            "section": section.get("name") if section else None,
            "in_executable_section": bool(
                section and isinstance(section.get("characteristics"), str)
                and int(section["characteristics"], 16) & 0x20000000),
        })

    code = tls_callback_code_probe(path, callbacks)
    by_index = {row["index"]: row for row in code}
    for callback in callbacks:
        callback["code"] = by_index.get(callback["index"])
        callback["distance_to_entry_point"] = (
            (pe.get("entry_point") or 0) - callback["rva"])

    array_rva = detail.get("callbacks_rva")
    array_section = rva_section(sections, array_rva) if array_rva else None
    entry_point = pe.get("entry_point") or 0
    entry_section = rva_section(sections, entry_point)

    return {
        "present": bool(tls.get("present")),
        "directory_rva": detail.get("directory_rva"),
        "directory_size": detail.get("directory_size"),
        "callback_count": tls.get("callback_count"),
        "callback_array_rva": array_rva,
        "callback_array_file_offset": (rva_to_offset(sections, array_rva)
                                       if array_rva else None),
        "callback_array_section": array_section.get("name") if array_section else None,
        "callbacks": callbacks,
        "entry_point_rva": entry_point,
        "entry_point_section": entry_section.get("name") if entry_section else None,
        "what_this_settles": (
            "that the callbacks exist, how many there are, that they point into "
            "a normal executable section of this image rather than into a "
            "separate high-entropy or writable region, that each one is the "
            "START of a function the compiler registered in .pdata, and what "
            "its unwind data says about its prologue and its exception "
            "handling"),
        "what_this_does_not_settle": (
            "what the callbacks do. A TLS callback is where an anti-debug check "
            "would be placed if there were one, and the directory cannot "
            "distinguish the MSVC CRT's __dyn_tls_init/__dyn_tls_dtor pair from "
            "a hand-written check. Only disassembling the two addresses settles "
            "it, which is M2's work"),
    }


def authenticode_probe(file_offset: int | None, size: int | None,
                       file_size: int, *, path: str) -> dict:
    """Does the SECURITY directory actually point at a WIN_CERTIFICATE?

    F-01 reports ``has_authenticode_signature`` from the directory entry being
    non-zero, which is the right contract for a header parser. It is not enough
    here. A signed image is one of the CEG indicators, so "the field is
    non-zero" would let a stale directory entry be read as DRM.

    The check is three literal comparisons against the published
    WIN_CERTIFICATE layout: dwLength must agree with the directory size,
    wRevision must be 0x0200 and wCertificateType must be 0x0002
    (WIN_CERT_TYPE_PKCS_SIGNED_DATA). A real blob also sits at the very end of
    the file, so that is reported too.

    The printable runs from inside the blob are extracted and reported as-is.
    They normally include the signer's common name, which answers "who signed
    this" cheaply. This is NOT signature verification: no chain is built, no
    digest is recomputed, and nothing here says the signature is valid.
    """
    probe = {
        "directory_file_offset": file_offset,
        "directory_size": size,
        "header_bytes_hex": None,
        "length_field": None,
        "revision": None,
        "certificate_type": None,
        "looks_like_win_certificate": False,
        "ends_at_end_of_file": None,
        "printable_runs": [],
        "limits": (
            "the WIN_CERTIFICATE header and the printable runs inside the blob "
            "are read literally. No certificate chain is built, no digest is "
            "recomputed: this says a certificate blob is THERE, never that it "
            "is valid or that it covers the bytes on disk"),
    }
    if not file_offset or not size:
        return probe
    if file_offset < 0 or size < 8 or file_offset + 8 > file_size:
        probe["note"] = ("the directory entry does not address 8 readable bytes "
                         "of this file")
        return probe
    try:
        with open(path, "rb", buffering=0) as handle:
            handle.seek(file_offset)
            header = handle.read(8)
            body = handle.read(min(max(0, size - 8), 1 << 16))
    except OSError as error:
        probe["note"] = "not readable: %s" % error
        return probe
    if len(header) < 8:
        return probe
    length, revision, cert_type = struct.unpack("<IHH", header)
    probe.update({
        "header_bytes_hex": hex_bytes(header),
        "length_field": length,
        "revision": "0x%04x" % revision,
        "certificate_type": "0x%04x" % cert_type,
        "looks_like_win_certificate": (revision == 0x0200
                                       and cert_type == 0x0002
                                       and 8 < length <= size),
        "ends_at_end_of_file": (file_offset + size == file_size),
    })
    if probe["looks_like_win_certificate"]:
        # DER is mostly binary, so a raw printable-run extraction returns
        # mostly noise. Keep only runs that read like a name: letters, digits
        # and ordinary name punctuation, with at least one four-letter word in
        # them. This is a readability filter on an already-literal reading, not
        # a parse of the certificate.
        wanted = re.compile(rb"^[A-Za-z0-9 .,'&()/\-]{6,64}$")
        word = re.compile(rb"[A-Za-z]{4,}")
        runs: list[str] = []
        for raw_pattern, encoding in ((rb"[\x20-\x7e]{6,64}", "ascii"),
                                      (rb"(?:[\x20-\x7e]\x00){6,64}", "utf-16-le")):
            for match in re.finditer(raw_pattern, body):
                blob = match.group(0)
                flat = (blob.decode(encoding).encode("ascii", "ignore")
                        if encoding != "ascii" else blob)
                if not wanted.match(flat) or not word.search(flat):
                    continue
                text = flat.decode("ascii")
                if text not in runs:
                    runs.append(text)
        probe["printable_runs"] = sorted(runs)[:32]
    return probe


def module_header_surface(document: dict, path: str) -> dict:
    pe = document["pe"]
    extended = document["pe_extended"]
    load_config = extended.get("load_config") or {}
    security = extended.get("security_directory") or {}
    probe = authenticode_probe(security.get("file_offset"), security.get("size"),
                              document["file"]["size"], path=path)
    return {
        "security_directory_entry_present": pe.get("has_authenticode_signature"),
        "authenticode": probe,
        "carries_a_certificate_blob": probe["looks_like_win_certificate"],
        "security_directory": security,
        "overlay_size": pe.get("overlay_size"),
        "dll_characteristics": pe.get("dll_characteristics"),
        "dll_characteristics_flags": extended.get("dll_characteristics_flags"),
        "checksum": pe.get("checksum"),
        "checksum_valid": pe.get("checksum_valid"),
        "entry_point": pe.get("entry_point"),
        "number_of_sections": pe.get("number_of_sections"),
        "guard_flags": load_config.get("guard_flags"),
        "guard_cf_function_count": load_config.get("guard_cf_function_count"),
        "has_reloc": pe.get("has_reloc"),
        "pdb_path_if_any": pe.get("pdb_path_if_any"),
        "version_company": ((pe.get("version_info") or {}).get("strings") or {}
                            ).get("CompanyName")
        if isinstance(pe.get("version_info"), dict) else None,
        "version_product": ((pe.get("version_info") or {}).get("strings") or {}
                            ).get("ProductName")
        if isinstance(pe.get("version_info"), dict) else None,
    }


def api_kit_matches(imports: list[dict]) -> list[dict]:
    """Import-table occurrences of the detection kit, each with its benign reading."""
    index = {entry["name"]: entry for entry in API_KIT}
    matches: list[dict] = []
    for row in imports:
        name = row.get("name")
        if not name:
            continue
        entry = index.get(name)
        if entry is None:
            # Accept the A/W/Ex spellings of a listed name without listing all
            # of them, but only as an exact stem plus a known suffix.
            for suffix in ("W", "A", "Ex", "ExW", "ExA", "64", "W64"):
                if name.endswith(suffix) and name[:-len(suffix)] in index:
                    entry = index[name[:-len(suffix)]]
                    break
        if entry is None:
            continue
        matches.append({
            "name": name,
            "canonical": entry["name"],
            "category": entry["category"],
            "weight": entry["weight"],
            "kind": row["kind"],
            "dll": row["dll"],
            "benign_explanation_in_ue": entry["benign"],
            "what_would_distinguish_it": entry["distinguishes"],
        })
    matches.sort(key=lambda item: (item["category"], item["name"], item["kind"]))
    return matches


def analyze_module(path: str, relative: str, *,
                   needle_set: NeedleSet | None,
                   want_entropy: bool = True,
                   primary: bool = True) -> dict:
    """Every PE surface for one module, plus its string hits if asked for."""
    # pe_info computes per-section entropy only in the same pass as the section
    # digest, so entropy needs want_digests as well.
    document = pe_info.analyze(path, want_digests=want_entropy,
                               want_entropy=want_entropy,
                               want_checksum=False, want_file_digest=False)
    pe = document["pe"]
    sections = pe.get("sections") or []
    imports = flatten_imports(pe)
    record = {
        "path": relative,
        "primary": primary,
        "size": document["file"]["size"],
        "machine_name": pe.get("machine_name"),
        "subsystem_name": pe.get("subsystem_name"),
        "section_names": [section.get("name") for section in sections],
        "imported_module_count": len(pe.get("imports") or []),
        "delay_imported_modules": sorted(
            (module.get("dll") or "").lower()
            for module in (pe.get("delay_imports") or [])),
        "named_import_count": sum(1 for row in imports if row["name"]),
        "section_findings": module_section_findings(pe),
        "tls": module_tls_surface(document, path),
        "headers": module_header_surface(document, path),
        "api_kit_imports": api_kit_matches(imports),
        "export_count": len(pe.get("exports") or []),
        "middleware_export_matches": [],
        "middleware_exports_offered": [],
        "middleware_symbol_imports": [],
        "string_hits": None,
        "string_scan_stats": None,
        "parse_warnings": document["pe_extended"].get("parse_warnings") or [],
    }

    # Exports OFFERED versus symbols IMPORTED. The distinction decides a
    # verdict, so it is made in the data and not in the prose.
    #
    # A bundled general-purpose SDK can export a protection API family without
    # anything in the installation using it: the Epic Online Services SDK
    # exports its whole anti-cheat surface in every build. "The library offers
    # it" and "the game links it" are different facts, and only the second says
    # anything about this build. So exports are recorded as an available
    # CAPABILITY, and the import tables are searched separately for symbols that
    # would mean the capability is actually wired up.
    export_index = {}
    for entry in MIDDLEWARE:
        for name in entry["exports"]:
            export_index[name] = entry
    offered: dict[str, dict] = {}
    for export in (pe.get("exports") or []):
        name = export.get("name")
        if not name:
            continue
        entry = export_index.get(name)
        if entry is None:
            for candidate in MIDDLEWARE:
                if any(name.startswith(prefix)
                       for prefix in candidate.get("symbol_prefixes") or ()):
                    entry = candidate
                    break
        if entry is None:
            continue
        bucket = offered.setdefault(entry["id"], {
            "middleware": entry["display"],
            "middleware_id": entry["id"],
            "family": entry["family"],
            "exported_symbol_count": 0,
            "examples": [],
        })
        bucket["exported_symbol_count"] += 1
        if len(bucket["examples"]) < 6:
            bucket["examples"].append(name)
    for bucket in offered.values():
        bucket["examples"].sort()
    record["middleware_exports_offered"] = sorted(
        offered.values(), key=lambda item: item["middleware_id"])
    record["middleware_export_matches"] = [
        {"export": name, "middleware": export_index[name]["display"],
         "middleware_id": export_index[name]["id"]}
        for name in sorted(export_index)
        if any(name == export.get("name") for export in (pe.get("exports") or []))]

    linked: dict[str, dict] = {}
    for row in imports:
        name = row.get("name")
        if not name:
            continue
        entry = export_index.get(name)
        if entry is None:
            for candidate in MIDDLEWARE:
                if any(name.startswith(prefix)
                       for prefix in candidate.get("symbol_prefixes") or ()):
                    entry = candidate
                    break
        if entry is None:
            continue
        bucket = linked.setdefault(entry["id"], {
            "middleware": entry["display"],
            "middleware_id": entry["id"],
            "family": entry["family"],
            "imported_symbols": [],
            "from_module": row["dll"],
            "kind": row["kind"],
        })
        bucket["imported_symbols"].append(name)
    for bucket in linked.values():
        bucket["imported_symbols"].sort()
    record["middleware_symbol_imports"] = sorted(
        linked.values(), key=lambda item: item["middleware_id"])

    if needle_set is not None:
        lookup = make_section_lookup(sections)
        scan = scan_file(path, needle_set, section_lookup=lookup)
        record["string_hits"] = scan["hits"]
        record["string_scan_stats"] = scan["stats"]
    return record


# --------------------------------------------------------------------------- #
# the filesystem surface
# --------------------------------------------------------------------------- #

DRIVER_EXTENSIONS = (".sys", ".inf", ".cat", ".vxd")
SERVICE_NAME_HINTS = ("service", "svc", "daemon", "helper64", "guard")


def filesystem_surface(files: list[dict]) -> dict:
    """Name-level matching over the whole inventory. One surface, named as one."""
    middleware_hits: list[dict] = []
    driver_files: list[dict] = []
    service_shaped: list[dict] = []
    for entry in files:
        relative = entry["path"]
        lowered = relative.lower()
        components = [part for part in re.split(r"[\\/]+", lowered) if part]
        base = components[-1] if components else lowered
        stem, extension = os.path.splitext(base)
        for product in MIDDLEWARE:
            for pattern in product["files"]:
                if pattern in lowered:
                    middleware_hits.append({
                        "path": relative,
                        "matched_pattern": pattern,
                        "middleware": product["display"],
                        "middleware_id": product["id"],
                        "family": product["family"],
                    })
        if extension in DRIVER_EXTENSIONS:
            driver_files.append({"path": relative, "extension": extension,
                                 "size": entry.get("size")})
        if extension == ".exe" and any(hint in stem for hint in SERVICE_NAME_HINTS):
            service_shaped.append({"path": relative, "size": entry.get("size")})

    middleware_hits.sort(key=lambda item: (item["path"], item["matched_pattern"]))
    driver_files.sort(key=lambda item: item["path"])
    service_shaped.sort(key=lambda item: item["path"])
    extensions: dict[str, int] = {}
    for entry in files:
        extension = os.path.splitext(entry["path"].lower())[1] or "<none>"
        extensions[extension] = extensions.get(extension, 0) + 1
    return {
        "files_examined": len(files),
        "extension_census": dict(sorted(extensions.items())),
        "middleware_name_matches": middleware_hits,
        "kernel_driver_files": driver_files,
        "service_shaped_executables": service_shaped,
        "what_it_proves": (
            "which names are and are not present on disk in this installation"),
        "what_it_does_not_prove": (
            "anything about a protection layer that ships inside the game "
            "executable, inside a container, or under a name this table does not "
            "list. This is the surface the forbidden inference of unknowns.md "
            "rests on, and on its own it settles nothing"),
    }


# --------------------------------------------------------------------------- #
# the service / driver surface
# --------------------------------------------------------------------------- #

def service_surface(modules: list[dict]) -> dict:
    """Service-control against service-INSTALL, plus the neighbourhood.

    This surface exists because OpenSCManager is the one API on the list with a
    genuinely common innocent use in a renderer -- reading the display driver's
    version -- and a report that recorded the hit without recording which
    neighbourhood it sat in would be handing a reader half a fact.
    """
    rows: list[dict] = []
    for module in modules:
        control = sorted({match["name"] for match in module["api_kit_imports"]
                          if match["category"] == "service-control"})
        install = sorted({match["name"] for match in module["api_kit_imports"]
                          if match["category"] == "service-install"})
        driver_io = sorted({match["name"] for match in module["api_kit_imports"]
                            if match["category"] == "driver-communication"})
        control_strings: list[str] = []
        install_strings: list[str] = []
        context_strings: list[str] = []
        for hit in (module["string_hits"] or []):
            if hit["group"] == "service-context":
                context_strings.append(hit["needle"])
            elif hit["group"] == "api-kit" and hit["category"] == "service-control":
                control_strings.append(hit["needle"])
            elif hit["group"] == "api-kit" and hit["category"] == "service-install":
                install_strings.append(hit["needle"])
        if not (control or install or driver_io or control_strings
                or install_strings):
            continue
        rows.append({
            "module": module["path"],
            "primary_scope": bool(module.get("primary", True)),
            "service_control_imports": control,
            "service_install_imports": install,
            "driver_io_imports": driver_io,
            "service_control_strings": sorted(set(control_strings)),
            "service_install_strings": sorted(set(install_strings)),
            "gpu_driver_enumeration_context": sorted(set(context_strings)),
        })
    rows.sort(key=lambda item: item["module"])
    return {
        "modules": rows,
        "reading": (
            "service-control without service-install is a QUERY: a handle to the "
            "service database plus OpenService, QueryServiceConfig and "
            "CloseServiceHandle cannot install, start or load anything. "
            "Surrounded by adapter enumeration and ICD registry keys it is a "
            "driver-version query, which is what a renderer does at startup. "
            "service-install -- CreateService, StartService, NtLoadDriver -- has "
            "no such reading in a shipped game and would be a finding"),
        "limits": (
            "the access mask passed to OpenSCManager and the service that is "
            "opened are not readable from a name table; only disassembly (M2) "
            "settles them"),
    }


# --------------------------------------------------------------------------- #
# the Steam layer
# --------------------------------------------------------------------------- #

def steam_surface(modules: list[dict], files: list[dict]) -> dict:
    """Ordinary Steamworks presence versus Steam CEG / SteamStub DRM wrapping.

    The distinction matters and is easy to get wrong. Steamworks is an SDK: a
    redistributable steam_api64.dll and calls to SteamAPI_Init. CEG is a
    re-link performed by Valve: the shipped executable gains a .bind section
    holding the stub, an Authenticode signature from Valve, and normally an
    overlay. The two have nothing to do with each other, and plan.md forbids
    working around DRM in any case -- the job here is to observe whether it is
    there.
    """
    steam_modules = [module["path"] for module in modules
                     if "steam_api" in module["path"].lower()]
    steam_files = [entry["path"] for entry in files
                   if "steam" in entry["path"].lower()]
    bind_sections = []
    signed_game_images = []
    for module in modules:
        for name in module["section_names"]:
            if (name or "").lower() == ".bind":
                bind_sections.append({"module": module["path"], "section": name})
        if module["headers"].get("has_authenticode_signature") and \
                module["path"].lower().endswith(".exe"):
            signed_game_images.append({
                "module": module["path"],
                "security_directory": module["headers"]["security_directory"],
                "overlay_size": module["headers"]["overlay_size"],
                "signer_strings": module["headers"]["authenticode"][
                    "printable_runs"],
            })
    ceg_string_hits = []
    for module in modules:
        for hit in (module["string_hits"] or []):
            if hit["detail"].get("middleware_id") == "steam-ceg":
                ceg_string_hits.append({"module": module["path"],
                                        "needle": hit["needle"],
                                        "count": hit["count"]})
    bind_sections.sort(key=lambda item: item["module"])
    signed_game_images.sort(key=lambda item: item["module"])
    ceg_string_hits.sort(key=lambda item: (item["module"], item["needle"]))
    return {
        "steamworks_modules": sorted(steam_modules),
        "steam_related_files": sorted(steam_files),
        "bind_sections": bind_sections,
        "authenticode_signed_executables": signed_game_images,
        "ceg_string_hits": ceg_string_hits,
        "reading": (
            "CEG / SteamStub indicators are: a .bind section, an Authenticode "
            "signature on the game executable, an overlay, and the SteamStub "
            "strings. Ordinary Steamworks indicators are: a redistributable "
            "steam_api64.dll and the SteamAPI_* entry points"),
        "scope_note": (
            "plan.md forbids working around DRM. This surface exists to record "
            "whether DRM is present, never to defeat it"),
    }


# --------------------------------------------------------------------------- #
# class-P literal reads
# --------------------------------------------------------------------------- #

def literal_read(target: str, offset: int, raw: bytes,
                 join_key: str) -> dict:
    """One class-P record: a literal read at a determinate place, nothing more.

    ``claim`` states the offset AND the length -- mandatory for the
    binary-analysis oracle to be class P at all (plan.md 10.3 v2.4) -- and stops
    short of naming what the bytes are. The interpretive half lives elsewhere in
    this document and is pointed at, not embedded, because naming a structure
    inside the graded string is exactly what would push it into class I.
    """
    length = len(raw)
    plural = "byte" if length == 1 else "bytes"
    claim = "%d %s at offset %d of %s are %s" % (
        length, plural, offset, target, hex_bytes(raw))
    return {
        "join_key": join_key,
        "interpretation_lives_in": (
            "the matching module record of this document (tls[] / string_hits[]) "
            "-- plan.md 10.3, the A-07 / A-07i split"),
        "target": target,
        "offset": offset,
        "length": length,
        "bytes_hex": hex_bytes(raw),
        "claim": claim,
        "evidence": {
            "evidence_level": "OBSERVED",
            "claim_class": "P",
            "confidence": CONFIDENCE_LITERAL,
            "oracle": ["binary-analysis"],
            "sources": [{
                "method": "Q-8-protection",
                "artifact": None,
                "locator": "%s@%d+%d" % (target, offset, length),
                "note": ("oracle binary-analysis. Read by %s, read-only. "
                         "Reproduction: PENDING." % GENERATOR_NAME),
            }],
            "read_locus": {
                "target": target,
                "address_kind": "file-offset",
                "offset": offset,
                "length": length,
                "bytes_hex": hex_bytes(raw),
                "note": None,
            },
            "note": ("%s. This record gives the position and the extent, and "
                     "nothing else." % claim),
        },
    }


def confirm_literal_reads(literals: list[dict], roots: dict,
                          warnings: list[str]) -> bool:
    """Perform every literal read a SECOND time, through a fresh handle.

    plan.md 10.3 class-P criterion 2 executed rather than asserted. On any
    disagreement nothing is adjusted: the failure is recorded and the reading
    stands as unreproduced.
    """
    reproduced = True
    by_target: dict[str, list[dict]] = {}
    for read in literals:
        by_target.setdefault(read["target"], []).append(read)
    for target, group in sorted(by_target.items()):
        path = roots.get(target)
        if not path:
            reproduced = False
            warnings.append("%s: no path recorded for the confirming re-read"
                            % target)
            continue
        try:
            with open(path, "rb", buffering=0) as handle:
                for read in group:
                    handle.seek(read["offset"])
                    again = handle.read(read["length"])
                    if hex_bytes(again) != read["bytes_hex"]:
                        reproduced = False
                        warnings.append(
                            "%s: the second read of %d bytes at offset %d gave %s "
                            "but the first gave %s -- the reading did NOT reproduce"
                            % (target, read["length"], read["offset"],
                               hex_bytes(again), read["bytes_hex"]))
        except OSError as error:
            reproduced = False
            warnings.append("%s: the confirming re-read could not be performed: %s"
                            % (target, error))
    attestation = RERUN_CONFIRMED if reproduced else RERUN_NOT_CONFIRMED
    for read in literals:
        read["reproduced"] = reproduced
        read["evidence"]["sources"][0]["note"] = (
            "oracle binary-analysis. Read by %s, read-only. %s"
            % (GENERATOR_NAME, attestation))
        read["evidence"]["note"] = "%s %s" % (read["evidence"]["note"], attestation)
    return reproduced


def collect_literal_reads(modules: list[dict], paths: dict,
                          warnings: list[str]) -> tuple[list[dict], bool]:
    """The primitive layer: the TLS callback array, the first bytes of each
    callback, and a bounded sample of the string regions the argument leans on.

    Scoped to the PRIMARY modules, for two reasons that point the same way.

    The substantive one: a class-P record exists to carry the primitive half of
    a claim the document actually grades (plan.md 10.3, the A-07 / A-07i split).
    The graded class-P claims here are about the images that execute; a literal
    read of a byte range in a bundled third-party DLL underpins nothing and is
    breadth without purpose.

    The mechanical one, recorded because it influenced the decision and hiding
    that would be dishonest: tools/kb/validate.py derives the claim class from
    the claim wording, and its "does this name what the bytes are" heuristic
    includes a CamelCase-identifier pattern. Third-party PATH components match
    it -- "ThirdParty", "OpenImageDenoise" -- so a perfectly primitive reading of
    a byte range inside Engine/Binaries/ThirdParty/... derives as class I and is
    rejected. That is a false positive of the linter on a file path rather than
    a defect in the record, and the fix chosen here is the one that is also
    right on the merits, not a rewording that would dodge the check.
    """
    literals: list[dict] = []
    for module in modules:
        if not module.get("primary", True):
            continue
        relative = module["path"]
        absolute = paths.get(relative)
        if not absolute:
            continue
        tls = module["tls"]
        array_offset = tls.get("callback_array_file_offset")
        count = tls.get("callback_count") or 0
        if array_offset is not None and count:
            length = min(8 * count, 64)
            try:
                with open(absolute, "rb", buffering=0) as handle:
                    handle.seek(array_offset)
                    raw = handle.read(length)
            except OSError as error:
                warnings.append("%s: TLS array not readable: %s" % (relative, error))
                raw = b""
            if raw:
                literals.append(literal_read(relative, array_offset, raw,
                                             "tls.callback_array"))
        for callback in tls.get("callbacks") or []:
            offset = callback.get("file_offset")
            if offset is None:
                continue
            try:
                with open(absolute, "rb", buffering=0) as handle:
                    handle.seek(offset)
                    raw = handle.read(16)
            except OSError as error:
                warnings.append("%s: TLS callback target not readable: %s"
                                % (relative, error))
                continue
            if raw:
                literals.append(literal_read(
                    relative, offset, raw,
                    "tls.callbacks[%d].target" % callback["index"]))
        if len(literals) >= MAX_LITERAL_READS:
            break

    # A sample of the string regions that carry argumentative weight: the
    # high-weight api-kit names and every middleware or kernel-only hit.
    for module in modules:
        if not module.get("primary", True):
            continue
        relative = module["path"]
        absolute = paths.get(relative)
        if not absolute:
            continue
        for hit in (module["string_hits"] or []):
            # What "carries argumentative weight" means here, concretely: a hit
            # the report has to either treat as a finding or explain away. Both
            # deserve a primitive record. Middleware names, kernel-mode routine
            # names and detection constants are the first kind. The
            # service-control cluster and the GPU-driver-enumeration markers
            # around it are the second -- that explanation is the only one in
            # the report that had to be argued, so its bytes get attested at
            # determinate offsets rather than described.
            detail = hit["detail"]
            interesting = (
                hit["group"] in ("middleware", "middleware-export", "kernel-only",
                                 "detection-constant", "service-context")
                or detail.get("weight") in ("high", "medium")
                or hit["category"] in ("service-control", "service-install",
                                       "driver-communication"))
            if not interesting or not hit["occurrences"]:
                continue
            occurrence = hit["occurrences"][0]
            try:
                with open(absolute, "rb", buffering=0) as handle:
                    handle.seek(occurrence["offset"])
                    raw = handle.read(min(occurrence["length"], 48))
            except OSError:
                continue
            if raw:
                literals.append(literal_read(
                    relative, occurrence["offset"], raw,
                    "string_hits[%s/%s]" % (hit["needle"], hit["encoding"])))
            if len(literals) >= MAX_LITERAL_READS:
                break
        if len(literals) >= MAX_LITERAL_READS:
            break

    literals.sort(key=lambda item: (item["target"], item["offset"]))
    reproduced = confirm_literal_reads(literals, paths, warnings)
    return literals, reproduced


# --------------------------------------------------------------------------- #
# refutation probes
# --------------------------------------------------------------------------- #

POSITIVE_CONTROL_STRING = {
    "module_suffix": "dbghelp.dll",
    "needle": "NtQueryInformationProcess",
}
NEGATIVE_CONTROL_MODULE_SUFFIX = "tbbmalloc.dll"


def _shape_of(callback: dict) -> dict:
    code = callback.get("code") or {}
    unwind = code.get("unwind") or {}
    return {
        "function_length": code.get("function_length"),
        "size_of_prolog": unwind.get("size_of_prolog"),
        "count_of_unwind_codes": unwind.get("count_of_unwind_codes"),
        "flag_names": unwind.get("flag_names"),
        "is_function_start": code.get("is_function_start"),
        "first_bytes_hex": code.get("first_bytes_hex"),
    }


def _common_prefix_bytes(left, right):
    """How many leading BYTES two hex strings share."""
    if not left or not right:
        return None
    limit = min(len(left), len(right))
    matched = 0
    for index in range(0, limit, 2):
        if left[index:index + 2] != right[index:index + 2]:
            break
        matched += 1
    return matched


def compare_tls_shape(modules: list[dict]) -> dict:
    """Census: how many OTHER modules of this installation carry the same TLS
    callback, byte for byte at the entry and unwind field for unwind field.

    The reasoning this supports, and its limit. A TLS callback runs before the
    entry point, so it is where an anti-debug check would go. This tool cannot
    disassemble, so it cannot say what the callbacks DO. What it can do is
    compare them against the callbacks of modules in the same installation that
    OTHER vendors built with their own toolchains and that have no reason to
    contain a check. If a game callback is byte-identical at its entry, and
    identical in function extent, prologue size, unwind-code count and handler
    flags, to the corresponding callback of several independently built modules,
    then it is the same CRT helper they all got from MSVC -- and "there are two
    TLS callbacks" is evidence of MSVC, not of a check.

    A single reference module is not enough, and the earlier version of this
    probe proved it: with dbghelp.dll alone the comparison reported a mismatch,
    because Microsoft built it with a different compiler version and its
    callback[0] has a 24-byte prologue where every other module here has 15.
    One reference cannot tell "the game is unusual" from "the reference is
    unusual". A census can.
    """
    donors = [module for module in modules
              if (module["tls"].get("callback_count") or 0) > 0]
    result = {
        "modules_with_tls_callbacks": sorted(module["path"] for module in donors),
        "method": (
            "for each callback of each primary module, compare against the "
            "callback at the same index of every OTHER module in the "
            "installation that has one. Three counts are kept separately: "
            "byte-identical on the first 16 bytes; identical unwind shape "
            "(prologue size, unwind-code count, handler flags); and identical "
            "unwind shape AND identical function length. The length is kept "
            "apart on purpose -- vendors ship different CRT versions and the "
            "same helper differs by a byte or two in its tail between them"),
        "comparisons": [],
        "limits": (
            "only the first 16 bytes of each callback are compared, and two "
            "functions can agree there and diverge later. This bounds the "
            "unknown, it does not close it. Closing it means disassembling the "
            "callbacks -- M2"),
    }
    for module in modules:
        if not module.get("primary", True):
            continue
        callbacks = module["tls"].get("callbacks") or []
        if not callbacks:
            continue
        rows = []
        for callback in callbacks:
            index = callback["index"]
            mine = _shape_of(callback)
            byte_identical = []
            shape_identical = []
            same_length = []
            partial = []
            available = 0
            for other in donors:
                if other["path"] == module["path"]:
                    continue
                others = other["tls"].get("callbacks") or []
                if index >= len(others):
                    continue
                available += 1
                theirs = _shape_of(others[index])
                shared = _common_prefix_bytes(mine["first_bytes_hex"],
                                              theirs["first_bytes_hex"])
                # "Same unwind shape" is prologue size, unwind-code count and
                # handler flags -- the three facts that describe how the
                # function was compiled. The function LENGTH is deliberately NOT
                # part of it and is reported on its own: vendors ship different
                # CRT versions, and the same helper differs by a byte or two in
                # its tail between them. Folding length into the test would call
                # a one-byte difference a different function, which is the
                # opposite of what this census is for.
                same_shape = (
                    mine["size_of_prolog"] == theirs["size_of_prolog"]
                    and mine["count_of_unwind_codes"]
                    == theirs["count_of_unwind_codes"]
                    and mine["flag_names"] == theirs["flag_names"])
                if shared == 16:
                    byte_identical.append(other["path"])
                if same_shape:
                    shape_identical.append(other["path"])
                if same_shape and mine["function_length"] == theirs["function_length"]:
                    same_length.append(other["path"])
                if shared is not None and shared < 16:
                    partial.append({
                        "module": other["path"],
                        "shared_leading_bytes": shared,
                        "their_size_of_prolog": theirs["size_of_prolog"],
                        "their_count_of_unwind_codes":
                            theirs["count_of_unwind_codes"],
                        "their_function_length": theirs["function_length"],
                    })
            rows.append({
                "index": index,
                "shape": mine,
                "donors_compared": available,
                "byte_identical_modules": sorted(byte_identical),
                "shape_identical_modules": sorted(shape_identical),
                "same_unwind_shape_and_length_modules": sorted(same_length),
                "both_identical_modules": sorted(
                    set(byte_identical) & set(shape_identical)),
                "partial_matches": sorted(partial,
                                          key=lambda item: item["module"]),
            })
        result["comparisons"].append({
            "module": module["path"],
            "callback_count": len(callbacks),
            "callbacks": rows,
        })
    result["comparisons"].sort(key=lambda item: item["module"])
    return result


def build_probes(modules: list[dict], self_test: dict,
                 wide_stats: dict, tls_comparison: dict) -> list[dict]:
    """Checks whose PURPOSE is to break the headline conclusion.

    A scan that produces only supporting numbers cannot tell a real finding from
    a broken scanner. Each probe states what result would refute the verdict and
    reports whether that happened.
    """
    probes: list[dict] = []

    probes.append({
        "id": "needle-self-test",
        "question": "does every declared needle actually fire?",
        "would_refute": ("any needle that does not match a buffer built to "
                         "contain it: the negative answers would then be an "
                         "artifact of a dead matcher"),
        "result": "PASS" if self_test["passed"] else "FAIL",
        "detail": {"declared": self_test["needles_declared"],
                   "fired": self_test["needles_that_fired"],
                   "silent": self_test["needles_that_did_not_fire"]},
    })

    positive = None
    for module in modules:
        if module["path"].lower().endswith(POSITIVE_CONTROL_STRING["module_suffix"]):
            positive = module
            break
    found = False
    if positive is not None:
        found = any(hit["needle"] == POSITIVE_CONTROL_STRING["needle"]
                    for hit in (positive["string_hits"] or []))
    probes.append({
        "id": "positive-control-string-surface",
        "question": ("can the string surface find a high-weight API name in a "
                     "REAL module of this installation?"),
        "would_refute": ("the needle not being found in %s, which is Microsoft's "
                         "own debug-helper library and is expected to contain it"
                         % POSITIVE_CONTROL_STRING["module_suffix"]),
        "result": ("PASS" if found else
                   ("NOT RUN" if positive is None else "FAIL")),
        "detail": {"module": positive["path"] if positive else None,
                   "needle": POSITIVE_CONTROL_STRING["needle"],
                   "found": found},
    })

    negative = None
    for module in modules:
        if module["path"].lower().endswith(NEGATIVE_CONTROL_MODULE_SUFFIX):
            negative = module
            break
    noise = []
    if negative is not None:
        noise = sorted({hit["needle"] for hit in (negative["string_hits"] or [])
                        if hit["group"] in ("middleware", "kernel-only",
                                            "detection-constant")})
    probes.append({
        "id": "negative-control-module",
        "question": ("does a module with no business touching any of this come "
                     "back clean?"),
        "would_refute": ("middleware, kernel-only or detection-constant hits in "
                         "%s, which would mean the tables match noise"
                         % NEGATIVE_CONTROL_MODULE_SUFFIX),
        "result": ("PASS" if negative is not None and not noise else
                   ("NOT RUN" if negative is None else "FAIL")),
        "detail": {"module": negative["path"] if negative else None,
                   "unexpected_hits": noise},
    })

    two_callbacks = sorted(module["path"] for module in modules
                           if (module["tls"].get("callback_count") or 0) == 2)
    probes.append({
        "id": "tls-shape-control",
        "question": ("is 'two TLS callbacks' a distinctive shape, or the norm "
                     "for any MSVC module in this installation?"),
        "would_refute": ("only the game executables having the shape, which "
                         "would make it worth explaining"),
        "result": ("PASS -- the shape is common" if len(two_callbacks) > 2
                   else "ATTENTION -- the shape is rare here"),
        "detail": {"modules_with_exactly_two_callbacks": two_callbacks,
                   "count": len(two_callbacks),
                   "reading": ("the MSVC CRT emits a two-entry callback array "
                               "(__dyn_tls_init and its dtor companion) for any "
                               "module with dynamically initialised thread_local "
                               "storage. A count of two is therefore evidence of "
                               "MSVC, not of a check")},
    })

    compared = 0
    corroborated = 0
    weakest = None
    for comparison in tls_comparison["comparisons"]:
        for row in comparison["callbacks"]:
            compared += 1
            twins = len(row["both_identical_modules"])
            if twins >= TLS_MIN_INDEPENDENT_TWINS:
                corroborated += 1
            if weakest is None or twins < weakest:
                weakest = twins
    probes.append({
        "id": "tls-callback-twins-in-other-modules",
        "question": ("is each TLS callback of the primary modules byte-identical "
                     "at its entry, and identical in unwind shape, to the same "
                     "callback of at least %d independently built modules of "
                     "this installation?" % TLS_MIN_INDEPENDENT_TWINS),
        "would_refute": ("a callback with no twin: unique opening bytes, a "
                         "unique prologue or a unique unwind shape would make it "
                         "worth explaining on its own, and would keep Q-8.2 open"),
        "result": ("PASS -- every callback has independent twins"
                   if compared and corroborated == compared
                   else ("NOT RUN" if not compared
                         else "ATTENTION -- a callback has no twin")),
        "detail": {"callbacks_compared": compared,
                   "callbacks_with_enough_twins": corroborated,
                   "fewest_twins_seen": weakest,
                   "census": tls_comparison},
    })

    rejected = sum((module["string_scan_stats"] or {}).get("rejected_undelimited", 0)
                   for module in modules)
    accepted = sum((module["string_scan_stats"] or {}).get("accepted", 0)
                   for module in modules)
    wrong_case = sum((module["string_scan_stats"] or {}).get("rejected_wrong_case", 0)
                     for module in modules)
    probes.append({
        "id": "delimiter-discipline",
        "question": "are the delimiter and case tests doing any work?",
        "would_refute": ("zero rejections, which would mean short needles are "
                         "being accepted inside longer words -- the 'Friday "
                         "contains frida' class of false positive -- and that "
                         "case-sensitive API names are matching any casing"),
        "result": "PASS" if rejected > 0 and wrong_case > 0 else "ATTENTION",
        "detail": {"candidates_rejected_as_undelimited": rejected,
                   "candidates_rejected_as_wrong_case": wrong_case,
                   "candidates_accepted": accepted,
                   "wide_pass": wide_stats},
    })

    probes.sort(key=lambda item: item["id"])
    return probes


# --------------------------------------------------------------------------- #
# verdicts
# --------------------------------------------------------------------------- #

def _high_weight_findings(modules: list[dict], categories: tuple) -> list[dict]:
    out: list[dict] = []
    for module in modules:
        if not module.get("primary", True):
            continue
        for match in module["api_kit_imports"]:
            if match["category"] in categories and match["weight"] == "high":
                out.append({"module": module["path"], "surface": "pe-imports",
                            **match})
        for hit in (module["string_hits"] or []):
            if hit["group"] != "api-kit":
                continue
            if hit["detail"].get("weight") != "high":
                continue
            out.append({"module": module["path"], "surface": "strings",
                        "name": hit["needle"], "category": hit["category"],
                        "weight": "high", "count": hit["count"],
                        "benign_explanation_in_ue": hit["detail"].get("benign"),
                        "what_would_distinguish_it":
                            hit["detail"].get("distinguishes")})
    out.sort(key=lambda item: (item["module"], item["surface"],
                              item.get("name") or ""))
    return out


def build_verdicts(filesystem: dict, modules: list[dict], probes: list[dict],
                   steam: dict, wide_hits: list[dict],
                   scope: dict, services: dict) -> dict:
    """Compute both verdicts from an explicit rule, and print the rule.

    The rule is deliberately conservative in one direction only: any positive
    indicator produces FOUND, and the absence of every indicator produces
    NOT FOUND WITHIN TESTED SURFACE -- never a bare "there is none". A broken
    control forces UNKNOWN, because a clean result from an unproven detector is
    not a result.
    """
    controls_ok = all(probe["result"].startswith("PASS")
                      for probe in probes
                      if probe["id"] in ("needle-self-test",
                                         "positive-control-string-surface",
                                         "negative-control-module"))

    # ---- Q-8.3 anti-cheat ------------------------------------------------- #
    anticheat_families = ("anti-cheat", "anti-tamper", "drm-anti-tamper")
    ac_positive: list[dict] = []
    for hit in filesystem["middleware_name_matches"]:
        if hit["family"] in anticheat_families:
            ac_positive.append({"surface": "filesystem-inventory", **hit})
    for entry in wide_hits:
        product = entry.get("middleware_id")
        family = entry.get("family")
        if family in anticheat_families:
            ac_positive.append({"surface": "strings", **entry})
    capability_offered: list[dict] = []
    for module in modules:
        for match in module["middleware_symbol_imports"]:
            # The game (or a module in the installation) actually LINKS a
            # protection API. This is the positive that matters.
            ac_positive.append({"surface": "pe-imports-middleware-symbol",
                                "module": module["path"], **match})
        for offered in module["middleware_exports_offered"]:
            capability_offered.append({"module": module["path"],
                                       "primary_scope": bool(
                                           module.get("primary", True)),
                                       **offered})
        for finding in module["section_findings"]:
            if finding["kind"] == "known-protector-section-name":
                ac_positive.append({"surface": "pe-sections",
                                    "module": module["path"], **finding})
        for match in module["api_kit_imports"]:
            if match["category"] == "service-install":
                ac_positive.append({"surface": "pe-imports",
                                    "module": module["path"], **match})
    ac_positive.sort(key=lambda item: (item["surface"], str(sorted(item.items()))))
    capability_offered.sort(key=lambda item: (item["module"],
                                              item["middleware_id"]))
    # Which primary modules import anything at all from the module that offers
    # the capability -- the question that decides whether "offered" matters.
    for row in capability_offered:
        linked_by = []
        for module in modules:
            if not module.get("primary", True):
                continue
            base = row["module"].split("/")[-1].lower()
            if base in module["delay_imported_modules"] or any(
                    base == name for name in module["delay_imported_modules"]):
                linked_by.append({"module": module["path"],
                                  "how": "delay-import of the whole library",
                                  "imports_protection_symbols": bool(
                                      module["middleware_symbol_imports"])})
        row["referenced_by_primary_modules"] = linked_by

    kernel_hits: list[dict] = []
    for module in modules:
        for hit in (module["string_hits"] or []):
            if hit["group"] == "kernel-only":
                kernel_hits.append({"module": module["path"],
                                    "needle": hit["needle"],
                                    "count": hit["count"]})
    kernel_hits.sort(key=lambda item: (item["module"], item["needle"]))

    if not controls_ok:
        ac_verdict = VERDICT_UNKNOWN
    elif ac_positive:
        ac_verdict = VERDICT_FOUND
    else:
        ac_verdict = VERDICT_NOT_FOUND_IN_SURFACE

    # ---- Q-8.2 anti-debug ------------------------------------------------- #
    ad_categories = ("anti-debug-probe", "anti-debug-active", "injection")
    ad_positive = _high_weight_findings(modules, ad_categories)
    # Outside the primary scope the same evidence is still reported in full --
    # it is simply not allowed to decide a verdict ABOUT the shipped game. A
    # high-weight name inside Microsoft's own dbghelp.dll is a fact about
    # dbghelp.dll.
    outside_scope: list[dict] = []
    for module in modules:
        if module.get("primary", True):
            continue
        for match in module["api_kit_imports"]:
            if match["category"] in ad_categories and match["weight"] == "high":
                outside_scope.append({"module": module["path"],
                                      "surface": "pe-imports", **match})
        for hit in (module["string_hits"] or []):
            if hit["group"] == "api-kit" and hit["detail"].get("weight") == "high":
                outside_scope.append({
                    "module": module["path"], "surface": "strings",
                    "name": hit["needle"], "category": hit["category"],
                    "weight": "high", "count": hit["count"],
                    "benign_explanation_in_ue": hit["detail"].get("benign"),
                    "what_would_distinguish_it": hit["detail"].get("distinguishes")})
    outside_scope.sort(key=lambda item: (item["module"], item["surface"],
                                         item.get("name") or ""))

    detection_constants: list[dict] = []
    for module in modules:
        for hit in (module["string_hits"] or []):
            if hit["group"] == "detection-constant":
                detection_constants.append({"module": module["path"],
                                            "primary_scope": bool(
                                                module.get("primary", True)),
                                            "needle": hit["needle"],
                                            "count": hit["count"],
                                            "occurrences": hit["occurrences"]})
    detection_constants.sort(key=lambda item: (item["module"], item["needle"]))

    obfuscation: list[dict] = []
    for module in modules:
        for finding in module["section_findings"]:
            if finding["kind"] in ("known-protector-section-name",) or \
                    (finding["kind"] == "high-entropy-section"
                     and finding["severity"] != "low"):
                obfuscation.append({"module": module["path"], **finding})
    obfuscation.sort(key=lambda item: (item["module"], item["section"] or ""))

    broad: dict[str, dict] = {}
    for module in modules:
        for hit in (module["string_hits"] or []):
            if hit["group"] != "broad-vocabulary":
                continue
            bucket = broad.setdefault(hit["needle"], {
                "needle": hit["needle"], "total": 0, "modules": [],
                "sample_contexts": []})
            bucket["total"] += hit["count"]
            if module["path"] not in bucket["modules"]:
                bucket["modules"].append(module["path"])
            for occurrence in hit["occurrences"][:2]:
                if len(bucket["sample_contexts"]) < 4:
                    bucket["sample_contexts"].append({
                        "module": module["path"],
                        "offset": occurrence["offset"],
                        "section": occurrence.get("section"),
                        "context": occurrence["context"]})
    broad_rows = sorted(broad.values(), key=lambda item: item["needle"])
    for row in broad_rows:
        row["modules"].sort()
    broad_absent = sorted(text for text in BROAD_VOCABULARY_NEEDLES
                          if text not in broad)

    primary_constants = [entry for entry in detection_constants
                         if entry["primary_scope"]]
    if not controls_ok:
        ad_verdict = VERDICT_UNKNOWN
    elif primary_constants or obfuscation or any(
            item["category"] == "anti-debug-active" for item in ad_positive):
        ad_verdict = VERDICT_FOUND
    elif ad_positive:
        # High-weight probes present but no detection constant and no
        # obfuscation: not enough to call it protection, not clean either.
        ad_verdict = VERDICT_UNKNOWN
    else:
        ad_verdict = VERDICT_NOT_FOUND_IN_SURFACE

    common_untested = [
        {"surface": "call-graph and control flow",
         "why": ("this tool does not disassemble. Whether any of the imported "
                 "functions is CALLED, from where, and whether its result "
                 "reaches a branch that changes behaviour, is unread"),
         "what_would_close_it": ("disassembly of the call sites -- M2 work "
                                 "(plan.md section 7)")},
        {"surface": "the two TLS callbacks of each game executable",
         "why": ("their addresses, their section and the bytes at those "
                 "addresses are recorded, but their instructions are not "
                 "decoded. A TLS callback runs before the entry point and is "
                 "the classic anti-debug hook site"),
         "what_would_close_it": ("disassembling the two addresses in each image "
                                 "and following what they call -- M2")},
        {"surface": "runtime behaviour",
         "why": ("nothing was executed. A protection layer that is downloaded, "
                 "unpacked or injected at run time leaves no trace in the image "
                 "on disk"),
         "what_would_close_it": ("an external observation of the live process "
                                 "-- module list, handle list, thread list. "
                                 "This is level 1 of section 8 and is itself "
                                 "gated on these answers")},
        {"surface": "container payloads",
         "why": ("the middleware name pass covered every byte of every file in "
                 "the inventory, but .ucas/.pak payloads are compressed and the "
                 "MISERY-Windows.utoc directory index is encrypted (D-02, never "
                 "decrypted), so a name that is present but compressed would "
                 "not appear as a literal string"),
         "what_would_close_it": ("nothing admissible: D-02 forbids decrypting "
                                 "shipped containers. This stays a bounded "
                                 "unknown by decision, not by omission")},
        {"surface": "the Steam client layer outside the installation",
         "why": ("Steam's own VAC module lives in the Steam client, not in the "
                 "game folder, and was not examined. Whether this appid is "
                 "VAC-enabled is a Steam-side fact"),
         "what_would_close_it": ("steam-metadata: the appinfo record for the "
                                 "appid. Out of scope for a binary-analysis "
                                 "pass")},
        {"surface": "server-side enforcement",
         "why": ("nothing about a dedicated server, a backend, or EOS-side "
                 "checks can be read from a client image"),
         "what_would_close_it": ("network observation, which section 8 does not "
                                 "propose")},
    ]
    common_untested.extend(scope.get("not_run") or [])
    common_untested.sort(key=lambda item: item["surface"])

    return {
        "Q-8.3": {
            "question": ("does this build carry an anti-cheat or another "
                         "execution-protection layer?"),
            "verdict": ac_verdict,
            "verdict_display": VERDICT_DISPLAY[ac_verdict],
            "rule": ("FOUND if any middleware file name, protector section "
                     "name, service-install import, or IMPORT of a middleware "
                     "protection symbol appears on any tested surface; UNKNOWN "
                     "if a control probe failed; otherwise NOT FOUND WITHIN "
                     "TESTED SURFACE. A middleware EXPORT in a bundled library "
                     "is reported separately and does not on its own trigger "
                     "FOUND -- a general-purpose SDK exports its whole API "
                     "surface whether or not the game uses it"),
            "positive_indicators": ac_positive,
            "middleware_capability_offered_but_not_linked": {
                "rows": capability_offered,
                "reading": (
                    "a bundled library EXPORTS a protection API family. That is "
                    "a fact about the library, not about this build: the Epic "
                    "Online Services SDK exports its whole anti-cheat surface "
                    "in every build it ships. What decides the question is "
                    "whether anything in the installation IMPORTS one of those "
                    "symbols -- see positive_indicators, surface "
                    "pe-imports-middleware-symbol"),
            },
            "kernel_mode_indicators": kernel_hits,
            "service_and_driver_surface": services,
            "steam_layer": {
                "bind_sections": steam["bind_sections"],
                "ceg_string_hits": steam["ceg_string_hits"],
                "steamworks_modules": steam["steamworks_modules"],
            },
            "tested_surfaces": scope["tested"],
            "untested_surfaces": common_untested,
            "what_would_change_the_answer": [
                "a kernel driver, a service registration, or a launcher stub "
                "appearing in a later build of the installation",
                "a middleware name appearing in a container payload once a "
                "legitimate route to read one exists",
                "a call-graph pass (M2) showing a self-check or a blacklist "
                "comparison inside the game image",
                "an observation of the live process showing a module that is "
                "not on disk",
            ],
        },
        "Q-8.2": {
            "question": ("does this build carry anti-debug or "
                         "anti-instrumentation logic?"),
            "verdict": ad_verdict,
            "verdict_display": VERDICT_DISPLAY[ad_verdict],
            "rule": ("FOUND if a detection constant inside the primary scope, "
                     "an obfuscated/protector section in ANY module, or a "
                     "high-weight ACTIVE anti-debug import inside the primary "
                     "scope is present; UNKNOWN if a control probe failed, or if "
                     "high-weight probe APIs are present in the primary scope "
                     "with no detection constant and no obfuscation; otherwise "
                     "NOT FOUND WITHIN TESTED SURFACE"),
            "primary_scope": scope.get("primary_scope"),
            "primary_scope_rule": scope.get("primary_scope_rule"),
            "high_weight_api_presence": ad_positive,
            "high_weight_api_presence_outside_primary_scope": outside_scope,
            "detection_constants": detection_constants,
            "obfuscation_indicators": obfuscation,
            "broad_vocabulary": {
                "present": broad_rows,
                "absent": broad_absent,
                "reading": (
                    "counted, not interpreted. These words are asked for by "
                    "name so that 'we looked' is checkable, but in an Unreal "
                    "Engine image they are dominated by ordinary identifiers "
                    "and console-variable help text. A count of ZERO is the "
                    "informative case; a non-zero count is a pointer to read "
                    "the context, not a finding"),
            },
            "interpretive_warning": (
                "the low-weight kit -- IsDebuggerPresent, OutputDebugString, "
                "DebugBreak, SetUnhandledExceptionFilter, "
                "AddVectoredExceptionHandler, dbghelp/MiniDumpWriteDump, "
                "CreateToolhelp32Snapshot, VirtualProtect -- IS present and is "
                "NOT counted as evidence of protection. Every one of those has "
                "a routine explanation in an Unreal Engine crash reporter, and "
                "presenting them as protection would be the same error as "
                "inferring absence from absent files"),
            "tested_surfaces": scope["tested"],
            "untested_surfaces": common_untested,
            "what_would_change_the_answer": [
                "a detection constant (ProcessDebugPort, ThreadHideFromDebugger, "
                "SystemKernelDebuggerInformation, CONTEXT_DEBUG_REGISTERS) "
                "appearing in the image",
                "a disassembly pass showing a TLS callback reaching any probe "
                "API, or a probe result feeding a branch that changes behaviour",
                "any section with protector-like entropy or a W+X mapping "
                "appearing in the game image",
                "an observed behavioural difference when a debugger is attached "
                "-- which would require running the game and is not proposed "
                "here",
            ],
        },
    }


def build_instrumentation_assessment(verdicts: dict, modules: list[dict]) -> dict:
    """The operational question section 8 actually needs, answered per level.

    Level 1 and level 2 are assessed separately on purpose. A protection that
    would notice an injected module can be completely indifferent to an external
    reader, and conflating the two either blocks safe work or licences unsafe
    work.
    """
    ac = verdicts["Q-8.3"]["verdict"]
    ad = verdicts["Q-8.2"]["verdict"]
    found = (ac == VERDICT_FOUND or ad == VERDICT_FOUND)
    # Level 1 is admissible only when BOTH questions came back
    # NOT FOUND WITHIN TESTED SURFACE. An UNKNOWN is not a quiet yes: it means
    # this pass could not establish the answer -- a control probe failed, or
    # ambiguous high-weight APIs are present in the primary scope with nothing
    # to disambiguate them. Licensing instrumentation off an UNKNOWN would be
    # the same over-reach as inferring absence from absent files, one level up.
    clean = (ac == VERDICT_NOT_FOUND_IN_SURFACE
             and ad == VERDICT_NOT_FOUND_IN_SURFACE)
    if found:
        level_1_reason = ("protection was FOUND on a tested surface; the stop "
                          "condition applies and nothing is licensed")
    elif not clean:
        level_1_reason = ("at least one question came back UNKNOWN, so this pass "
                          "did not establish an answer. An UNKNOWN licenses "
                          "nothing")
    else:
        level_1_reason = ("both questions came back NOT FOUND WITHIN TESTED "
                          "SURFACE with every control probe passing")

    return {
        "stop_condition_triggered": found,
        "stop_condition_text": (
            "binding rule of this task: if protection is found that would make "
            "the planned instrumentation unsafe, or that would have to be "
            "circumvented, STOP and record the gate. No bypass, no evasion, no "
            "fingerprint-around, and no description of how to do any of those"),
        "level_1_external_read_only_inspector": {
            "description": ("a separate process that opens the game process with "
                            "read-only access and never writes, never injects, "
                            "never hooks"),
            "admissible": clean,
            "why": level_1_reason,
            "reasoning": [
                "no anti-cheat middleware, no kernel driver and no service "
                "registration was found on any tested surface, so there is no "
                "known component that could observe another process opening a "
                "handle",
                "an external reader does not modify the target, does not load a "
                "module into it and does not patch it, so the shapes that a "
                "protection layer normally reacts to are absent by construction",
                "the residual risk is NOT protection but ordinary process "
                "hygiene: a read of a moving structure can tear, and a handle "
                "with more access than needed is a self-inflicted hazard",
            ],
            "conditions": [
                "open with the least access that works -- "
                "PROCESS_QUERY_LIMITED_INFORMATION plus PROCESS_VM_READ; never "
                "PROCESS_VM_WRITE or PROCESS_VM_OPERATION",
                "never suspend, never inject, never patch, never set a hardware "
                "or software breakpoint",
                "treat every read as possibly torn and re-read rather than "
                "trusting a single sample",
                "record every run under research/instrument-runs/ so a "
                "behavioural change is attributable",
            ],
            "residual_unknowns": [
                "whether the process reacts to a foreign handle at all is not "
                "readable from the image; it becomes observable the first time "
                "level 1 is used, and the first run should therefore be treated "
                "as an experiment with a recorded expectation",
            ],
        },
        "level_2_in_process_probe": {
            "description": ("code running inside the game process; requires the "
                            "documented escalation of plan.md section 8.4"),
            "admissible_on_this_evidence": False,
            "reasoning": [
                "this pass answers 'nothing found on the tested surfaces', not "
                "'nothing is there'. The two questions that matter most for an "
                "in-process probe -- what the TLS callbacks do, and whether any "
                "probe API result reaches a branch -- are exactly the two this "
                "tool cannot read",
                "an in-process probe changes the module list, allocates "
                "executable memory and may patch code. Those are the shapes a "
                "protection layer reacts to, so the margin for error is much "
                "smaller than at level 1",
                "plan.md section 8.6 already makes level 1 the default and "
                "level 2 an escalation with a written justification; nothing "
                "here removes that requirement",
            ],
            "preconditions_before_reconsidering": [
                "the two TLS callbacks of MISERY-Win64-Shipping.exe disassembled "
                "and shown to be the MSVC CRT pair, or shown not to be",
                "a call-graph pass showing that no probe API result reaches a "
                "branch that changes behaviour",
                "a concrete research question that level 1 provably cannot "
                "answer -- plan.md section 8.4 criterion, not a convenience",
                "the level-1 first-contact experiment already run and recorded "
                "without incident",
            ],
        },
        "verdict_inputs": {"Q-8.3": ac, "Q-8.2": ad},
    }


# --------------------------------------------------------------------------- #
# orchestration
# --------------------------------------------------------------------------- #

def load_inventory(install_root: str,
                   inventory_path: str | None) -> tuple[list[dict], dict]:
    """Prefer the committed install inventory; fall back to a filesystem walk.

    The inventory is preferred because it is the artifact the rest of the
    repository already agrees on, and because reusing it makes the file surface
    of this run comparable with the F-02/F-03 runs rather than merely similar.
    """
    meta = {"source": None, "path": None, "build_id": None, "file_count": None}
    if inventory_path:
        with open(inventory_path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        files = [{"path": entry["path"], "size": entry.get("size")}
                 for entry in document.get("files", [])]
        meta.update({"source": "install-inventory", "path": inventory_path,
                     "build_id": document.get("build_id"),
                     "file_count": document.get("file_count")})
        return sorted(files, key=lambda item: item["path"]), meta

    files = []
    for current, _dirs, names in os.walk(install_root):
        for name in sorted(names):
            absolute = os.path.join(current, name)
            relative = os.path.relpath(absolute, install_root).replace(os.sep, "/")
            try:
                size = os.path.getsize(absolute)
            except OSError:
                size = None
            files.append({"path": relative, "size": size})
    meta.update({"source": "filesystem-walk", "path": install_root,
                 "file_count": len(files)})
    return sorted(files, key=lambda item: item["path"]), meta


def is_primary_module(relative: str, primary_patterns: list[str] | None) -> bool:
    """Is this module part of what the verdict is ABOUT?

    The distinction exists because a high-weight API name inside Microsoft's own
    dbghelp.dll is a fact about dbghelp.dll, not about the game, and letting it
    grade the game would be the mirror image of the forbidden inference: reading
    a conclusion off a surface that cannot support it.

    Nothing is hidden by the split. Every finding outside the primary scope is
    still reported, in full, in its own field; the scope only decides which
    findings are allowed to move the AMBIGUOUS half of a verdict. Unambiguous
    indicators -- middleware names, protector sections, service-install imports,
    kernel-mode routine names -- are global and trigger FOUND from any module.

    With no explicit patterns every module is primary, which is the conservative
    default.
    """
    if not primary_patterns:
        return True
    lowered = relative.replace("\\", "/").lower()
    for pattern in primary_patterns:
        candidate = pattern.replace("\\", "/").lower()
        if lowered == candidate:
            return True
        # A pattern that contains a separator may match by suffix. A BARE
        # basename may not: this installation holds two different files called
        # MISERY.exe -- the bootstrap shim at the root and the D-04 oracle under
        # Binaries/Win64 -- and a suffix rule silently pulled the oracle into
        # the scope of a verdict about the shipped game. Exact-only for bare
        # names is the fix; say "Win64/MISERY.exe" when a suffix is meant.
        if "/" in candidate and lowered.endswith("/" + candidate):
            return True
    return False


def analyze(install_root: str, *, inventory_path: str | None = None,
            wide_scan: bool = True, module_paths: list[str] | None = None,
            want_entropy: bool = True,
            primary_patterns: list[str] | None = None) -> dict:
    """Run every surface and assemble the document."""
    warnings: list[str] = []
    needle_set = build_needle_set()
    wide_set = build_wide_needle_set()
    self_test = self_test_needle_set(needle_set)
    if not self_test["passed"]:
        warnings.append(
            "needle self-test FAILED for %d needles; every negative result in "
            "this document is unreliable until that is explained"
            % len(self_test["needles_that_did_not_fire"]))

    if module_paths is not None:
        files = []
        for path in module_paths:
            try:
                size = os.path.getsize(path)
            except OSError:
                size = None
            files.append({"path": os.path.basename(path), "size": size})
        absolute_by_relative = {os.path.basename(path): path
                                for path in module_paths}
        inventory_meta = {"source": "explicit-module-list", "path": None,
                          "build_id": None, "file_count": len(files)}
    else:
        files, inventory_meta = load_inventory(install_root, inventory_path)
        absolute_by_relative = {
            entry["path"]: os.path.join(install_root,
                                        entry["path"].replace("/", os.sep))
            for entry in files}

    filesystem = filesystem_surface(files)

    modules: list[dict] = []
    for entry in files:
        relative = entry["path"]
        if os.path.splitext(relative.lower())[1] not in PE_EXTENSIONS:
            continue
        absolute = absolute_by_relative[relative]
        if not os.path.isfile(absolute):
            warnings.append("listed but not on disk, skipped: %s" % relative)
            continue
        try:
            modules.append(analyze_module(
                absolute, relative, needle_set=needle_set,
                want_entropy=want_entropy,
                primary=is_primary_module(relative, primary_patterns)))
        except PEFormatError as error:
            warnings.append("%s: not parsed as PE: %s" % (relative, error))
        except OSError as error:
            warnings.append("%s: not readable: %s" % (relative, error))
    modules.sort(key=lambda item: item["path"])

    # The wide pass: the small middleware/kernel needle set over EVERY file,
    # containers included. This is the pass that makes "no anti-cheat name
    # anywhere in the installation" a statement about the installation rather
    # than about its executables.
    wide = {"ran": False, "files_scanned": 0, "bytes_scanned": 0,
            "hits": [], "stats": {"candidates": 0, "rejected_undelimited": 0,
                                  "rejected_wrong_case": 0, "accepted": 0},
            "skipped": []}
    if wide_scan:
        wide["ran"] = True
        for entry in files:
            relative = entry["path"]
            absolute = absolute_by_relative[relative]
            if not os.path.isfile(absolute):
                wide["skipped"].append(relative)
                continue
            try:
                scan = scan_file(absolute, wide_set)
            except OSError as error:
                warnings.append("%s: wide pass could not read: %s"
                                % (relative, error))
                wide["skipped"].append(relative)
                continue
            wide["files_scanned"] += 1
            wide["bytes_scanned"] += scan["stats"]["bytes_scanned"]
            for key in ("candidates", "rejected_undelimited",
                        "rejected_wrong_case", "accepted"):
                wide["stats"][key] += scan["stats"][key]
            for hit in scan["hits"]:
                wide["hits"].append({
                    "path": relative,
                    "needle": hit["needle"],
                    "group": hit["group"],
                    "family": hit["category"],
                    "middleware_id": hit["detail"].get("middleware_id"),
                    "encoding": hit["encoding"],
                    "count": hit["count"],
                    "occurrences": hit["occurrences"],
                })
        wide["hits"].sort(key=lambda item: (item["path"], item["needle"],
                                            item["encoding"]))
        wide["skipped"].sort()

    steam = steam_surface(modules, files)
    services = service_surface(modules)
    tls_comparison = compare_tls_shape(modules)
    probes = build_probes(modules, self_test, wide["stats"], tls_comparison)
    literals, reproduced = collect_literal_reads(modules, absolute_by_relative,
                                                 warnings)

    tested = [
        {"id": "filesystem-inventory",
         "covered": "%d files" % filesystem["files_examined"],
         "what_it_proves": filesystem["what_it_proves"],
         "what_it_does_not_prove": filesystem["what_it_does_not_prove"]},
        {"id": "pe-sections",
         "covered": "%d PE modules" % len(modules),
         "what_it_proves": ("which section names and section shapes are present "
                            "in every PE module of the installation"),
         "what_it_does_not_prove": ("anything about a protector that adds no "
                                    "section, of which Arxan-class weaving is "
                                    "the named example")},
        {"id": "pe-imports",
         "covered": "%d PE modules, normal and delay-load tables" % len(modules),
         "what_it_proves": ("which functions each module resolves at load time "
                            "or first use, by name"),
         "what_it_does_not_prove": ("that any of them is called, or from where. "
                                    "A function resolved through GetProcAddress "
                                    "is not in this table at all -- which is why "
                                    "the strings surface exists")},
        {"id": "pe-exports",
         "covered": "%d PE modules" % len(modules),
         "what_it_proves": "which entry points each module publishes",
         "what_it_does_not_prove": "anything about an unexported protection layer"},
        {"id": "pe-tls",
         "covered": "%d PE modules" % len(modules),
         "what_it_proves": ("that a callback array exists, how long it is, and "
                            "which section each callback lands in"),
         "what_it_does_not_prove": ("what the callbacks do. This is the single "
                                    "biggest bounded unknown of both questions")},
        {"id": "pe-headers",
         "covered": "%d PE modules" % len(modules),
         "what_it_proves": ("Authenticode presence, overlay size, load-config "
                            "guard flags, DLL characteristics"),
         "what_it_does_not_prove": ("signature validity or signer identity -- "
                                    "this tool reads the directory, it does not "
                                    "verify a chain")},
        {"id": "strings-modules",
         "covered": ("%d PE modules, full file, ASCII and UTF-16LE"
                     % len(modules)),
         "what_it_proves": ("which API names, middleware names, detection "
                            "constants and tool names appear as literal bytes, "
                            "with offset, length and containing section"),
         "what_it_does_not_prove": ("that a name present is used, or that a name "
                                    "absent is not reached -- an import can be "
                                    "resolved by ordinal or by hash, leaving no "
                                    "string")},
    ]
    # A surface that did not run must never appear in the tested list. Reporting
    # a skipped pass as a covered surface is the same error as inferring absence
    # from absent files, one level up.
    not_run: list[dict] = []
    if wide["ran"]:
        tested.append({
            "id": "strings-whole-install",
            "covered": ("%d files, %d bytes, middleware and kernel-routine names "
                        "only" % (wide["files_scanned"], wide["bytes_scanned"])),
            "what_it_proves": ("that these product names do not appear as literal "
                               "bytes anywhere in the installation, container "
                               "payloads included"),
            "what_it_does_not_prove": ("anything about a name stored compressed or "
                                       "encrypted, which is the normal state of "
                                       "container payloads")})
    else:
        not_run.append({
            "surface": "strings-whole-install",
            "why": "the whole-install string pass was not run in this invocation",
            "what_would_close_it": "run without --no-wide-scan / --module-only"})
    if module_paths is not None:
        not_run.append({
            "surface": "filesystem-inventory (whole installation)",
            "why": ("this invocation was given an explicit module list, so the "
                    "file surface covers those modules only"),
            "what_would_close_it": "run against the installation root"})
    scope = {
        "tested": tested,
        "not_run": not_run,
        "primary_scope": sorted(module["path"] for module in modules
                                if module["primary"]),
        "primary_scope_rule": (
            "every PE module in the installation is examined and every finding "
            "is reported. The primary scope names the modules the AMBIGUOUS half "
            "of the Q-8.2 verdict is about; unambiguous indicators -- middleware "
            "names, protector section names, service-install imports, "
            "kernel-mode routine names, protector sections -- are global and "
            "trigger FOUND from any module. "
            + ("Set explicitly to: %s" % ", ".join(primary_patterns)
               if primary_patterns else
               "No --primary given, so every module is primary (the "
               "conservative default)")),
    }

    verdicts = build_verdicts(filesystem, modules, probes, steam, wide["hits"],
                              scope, services)
    instrumentation = build_instrumentation_assessment(verdicts, modules)

    return {
        "generated_at": now_iso_utc(),
        "generator": GENERATOR_NAME,
        "generator_version": GENERATOR_VERSION,
        "target": {
            "install_root": os.path.abspath(install_root) if install_root else None,
            "inventory": inventory_meta,
        },
        "self_test": self_test,
        "surfaces": {
            "filesystem_inventory": filesystem,
            "modules": modules,
            "service_and_driver": services,
            "tls_callback_shape_comparison": tls_comparison,
            "whole_install_string_pass": wide,
            "steam_layer": steam,
        },
        "refutation_probes": probes,
        "literal_reads": literals,
        "literal_reads_reproduced": reproduced,
        "verdicts": verdicts,
        "instrumentation_assessment": instrumentation,
        "warnings": sorted(set(warnings)),
    }


# --------------------------------------------------------------------------- #
# human summary
# --------------------------------------------------------------------------- #

def format_summary(document: dict) -> str:
    lines: list[str] = []
    add = lines.append
    target = document["target"]
    add("=" * 78)
    add("protection surface scan -- Q-8.2 (anti-debug) and Q-8.3 (anti-cheat)")
    add("=" * 78)
    add("install root : %s" % target["install_root"])
    add("inventory    : %s (%s files)" % (target["inventory"]["source"],
                                          target["inventory"]["file_count"]))
    add("build_id     : %s" % target["inventory"]["build_id"])
    add("")

    self_test = document["self_test"]
    add("-- detector self-test ------------------------------------------------")
    add("  %d/%d needles fired -> %s"
        % (self_test["needles_that_fired"], self_test["needles_declared"],
           "PASS" if self_test["passed"] else "FAIL"))
    if self_test["needles_that_did_not_fire"]:
        add("  silent: %s" % ", ".join(self_test["needles_that_did_not_fire"]))
    add("")

    filesystem = document["surfaces"]["filesystem_inventory"]
    add("-- surface: filesystem-inventory ------------------------------------")
    add("  files examined              : %d" % filesystem["files_examined"])
    add("  middleware name matches     : %d"
        % len(filesystem["middleware_name_matches"]))
    for hit in filesystem["middleware_name_matches"]:
        add("      %s  <- %s" % (hit["path"], hit["middleware"]))
    add("  kernel driver files (.sys)  : %d" % len(filesystem["kernel_driver_files"]))
    add("  service-shaped executables  : %d"
        % len(filesystem["service_shaped_executables"]))
    add("")

    modules = document["surfaces"]["modules"]
    add("-- surface: PE modules ----------------------------------------------")
    add("  modules parsed              : %d" % len(modules))
    protector_sections = [(module["path"], finding)
                          for module in modules
                          for finding in module["section_findings"]
                          if finding["kind"] == "known-protector-section-name"]
    add("  protector section names     : %d" % len(protector_sections))
    for path, finding in protector_sections:
        add("      %s: %s -> %s" % (path, finding["section"],
                                    ", ".join(finding["attributed_to"])))
    offered = [(module["path"], row) for module in modules
               for row in module["middleware_exports_offered"]]
    add("  middleware API offered by a bundled library : %d" % len(offered))
    for path, row in offered:
        add("      %s: %s, %d exported symbol(s)"
            % (path, row["middleware"], row["exported_symbol_count"]))
    linked = [(module["path"], row) for module in modules
              for row in module["middleware_symbol_imports"]]
    add("  middleware symbols actually IMPORTED        : %d" % len(linked))
    for path, row in linked:
        add("      %s: %s <- %s"
            % (path, row["middleware"], ", ".join(row["imported_symbols"][:6])))
    add("")
    add("  certificate blobs (SECURITY directory verified, not validated):")
    for module in modules:
        headers = module["headers"]
        if not headers["security_directory_entry_present"]:
            continue
        probe = headers["authenticode"]
        names = [run for run in probe["printable_runs"]
                 if "digicert" not in run.lower()
                 and "verisign" not in run.lower()
                 and "symantec" not in run.lower()]
        add("      %-64s blob=%-5s %s"
            % (module["path"], probe["looks_like_win_certificate"],
               "; ".join(names[:3]) if names else ""))
    add("")
    twins_by_module = {}
    for comparison in (document["surfaces"]["tls_callback_shape_comparison"]
                       ["comparisons"]):
        for row in comparison["callbacks"]:
            twins_by_module[(comparison["module"], row["index"])] = row
    add("  TLS callback arrays:")
    for module in modules:
        tls = module["tls"]
        if not tls["callback_count"]:
            continue
        add("      %-64s %d callback(s)" % (module["path"], tls["callback_count"]))
        for callback in tls["callbacks"]:
            code = callback.get("code") or {}
            unwind = code.get("unwind") or {}
            add("          [%d] VA %s  RVA %s  section %s  file offset %s"
                % (callback["index"], callback["virtual_address_hex"],
                   callback["rva_hex"], callback["section"],
                   callback["file_offset"]))
            add("              function start=%s length=%s prolog=%s "
                "unwind codes=%s flags=%s"
                % (code.get("is_function_start"), code.get("function_length"),
                   unwind.get("size_of_prolog"),
                   unwind.get("count_of_unwind_codes"),
                   ",".join(unwind.get("flag_names") or []) or "-"))
            add("              first 16 bytes: %s" % code.get("first_bytes_hex"))
            if twins_by_module.get((module["path"], callback["index"])):
                row = twins_by_module[(module["path"], callback["index"])]
                add("              twins among %d other module(s): "
                    "%d byte-identical, %d same unwind shape, %d also same length"
                    % (row["donors_compared"],
                       len(row["byte_identical_modules"]),
                       len(row["shape_identical_modules"]),
                       len(row["same_unwind_shape_and_length_modules"])))
    add("")

    add("-- surface: detection kit in import tables ---------------------------")
    for module in modules:
        high = [match for match in module["api_kit_imports"]
                if match["weight"] == "high"]
        if not high:
            continue
        add("  %s" % module["path"])
        for match in high:
            add("      HIGH  %-30s %-22s (%s)"
                % (match["name"], match["category"], match["kind"]))
    add("  (low- and medium-weight entries are in the JSON with their benign")
    add("   explanation attached; they are NOT counted as protection)")
    add("")

    services = document["surfaces"]["service_and_driver"]
    add("-- surface: service / driver control ---------------------------------")
    if not services["modules"]:
        add("  no module names any service-control or service-install API")
    for row in services["modules"]:
        add("  %s%s" % (row["module"],
                        "" if row["primary_scope"]
                        else "  [outside primary scope]"))
        add("      control : %s" % (", ".join(
            row["service_control_imports"] + row["service_control_strings"]) or "-"))
        add("      INSTALL : %s" % (", ".join(
            row["service_install_imports"] + row["service_install_strings"]) or "none"))
        add("      driver io: %s" % (", ".join(row["driver_io_imports"]) or "-"))
        add("      gpu-driver-enumeration context: %d marker(s)"
            % len(row["gpu_driver_enumeration_context"]))
    add("")

    wide = document["surfaces"]["whole_install_string_pass"]
    add("-- surface: whole-install string pass -------------------------------")
    add("  files scanned : %d" % wide["files_scanned"])
    add("  bytes scanned : %d" % wide["bytes_scanned"])
    add("  hits          : %d" % len(wide["hits"]))
    for hit in wide["hits"]:
        add("      %s: %r x%d (%s)" % (hit["path"], hit["needle"], hit["count"],
                                       hit["encoding"]))
    add("")

    broad = document["verdicts"]["Q-8.2"]["broad_vocabulary"]
    add("-- surface: broad vocabulary (counted, not interpreted) --------------")
    add("  absent entirely: %s" % (", ".join(broad["absent"]) or "-"))
    for row in broad["present"]:
        add("  %-12s total=%-6d in %d module(s)"
            % (row["needle"], row["total"], len(row["modules"])))
    add("")

    add("-- refutation probes -------------------------------------------------")
    for probe in document["refutation_probes"]:
        add("  %-34s %s" % (probe["id"], probe["result"]))
    add("")

    add("-- literal reads (class P) ------------------------------------------")
    add("  records: %d, reproduced through a second handle: %s"
        % (len(document["literal_reads"]),
           document["literal_reads_reproduced"]))
    add("")

    add("=" * 78)
    for key in ("Q-8.3", "Q-8.2"):
        verdict = document["verdicts"][key]
        add("%s  %s" % (key, verdict["verdict_display"]))
        add("    question: %s" % verdict["question"])
        add("    rule    : %s" % verdict["rule"])
        add("    tested surfaces  : %s"
            % ", ".join(item["id"] for item in verdict["tested_surfaces"]))
        add("    untested surfaces: %s"
            % "; ".join(item["surface"] for item in verdict["untested_surfaces"]))
        add("")
    add("=" * 78)

    assessment = document["instrumentation_assessment"]
    add("instrumentation admissibility (plan.md section 8)")
    add("  stop condition triggered : %s" % assessment["stop_condition_triggered"])
    add("  level 1 (external read-only inspector) admissible : %s"
        % assessment["level_1_external_read_only_inspector"]["admissible"])
    add("  level 2 (in-process probe) admissible on this evidence : %s"
        % assessment["level_2_in_process_probe"]["admissible_on_this_evidence"])
    add("=" * 78)

    if document["warnings"]:
        add("")
        add("warnings:")
        for warning in document["warnings"]:
            add("  %s" % warning)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #

def write_text(text: str, out_path: str, install_root: str, what: str) -> str:
    """Write *text*, refusing any path inside an installation (D-01).

    The guard runs before the file is opened, so a refused path leaves nothing
    behind -- not even a truncated file.
    """
    target = pathguard.check_output_path(out_path, install_root, what=what)
    parent = os.path.dirname(target)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return target


def discover_inventory(repo_root: str) -> str | None:
    builds = os.path.join(repo_root, "research", "builds")
    if not os.path.isdir(builds):
        return None
    candidates = []
    for name in sorted(os.listdir(builds)):
        candidate = os.path.join(builds, name, "install-inventory.json")
        if os.path.isfile(candidate):
            candidates.append(candidate)
    return candidates[0] if len(candidates) == 1 else (
        candidates[0] if candidates else None)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="protection_scan.py",
        description=(
            "Read-only protection-surface scanner for plan.md Q-8.2 and Q-8.3. "
            "Prints a human summary by default; --json prints the machine "
            "document. Refuses any output path that resolves inside a game "
            "installation (D-01). Never bypasses, disables or evades anything."),
    )
    parser.add_argument("path", nargs="?", default=None,
                        help="the installation root, or a single PE file with "
                             "--module-only")
    parser.add_argument("--module-only", action="store_true",
                        help="treat every positional path as a PE module and "
                             "skip the filesystem and whole-install surfaces")
    parser.add_argument("--extra-module", action="append", default=[],
                        metavar="FILE",
                        help="an additional PE module to include with "
                             "--module-only")
    parser.add_argument("--inventory", default=None, metavar="FILE",
                        help="the install-inventory.json to use as the file "
                             "surface (default: auto-discovered under "
                             "research/builds/)")
    parser.add_argument("--no-inventory", action="store_true",
                        help="walk the installation instead of using an inventory")
    parser.add_argument("--no-wide-scan", action="store_true",
                        help="skip the whole-install middleware string pass "
                             "(the slow one); the surface is then reported as "
                             "not run rather than as clean")
    parser.add_argument("--no-entropy", action="store_true",
                        help="skip per-section entropy and section digests")
    parser.add_argument("--primary", action="append", default=[],
                        metavar="RELPATH",
                        help=("a module the verdict is ABOUT, repeatable "
                              "(inventory-relative path, or a suffix of one). "
                              "Every module is still examined and every finding "
                              "still reported; this only decides which modules "
                              "may move the ambiguous half of Q-8.2. Default: "
                              "every module"))
    parser.add_argument("--json", action="store_true",
                        help="print the JSON document instead of the summary")
    parser.add_argument("--out", default=None,
                        help="write the JSON document here; refused (exit 2) if "
                             "it resolves inside a game installation")
    parser.add_argument("--install-dir", default=None,
                        help="installation root the output guard checks against")
    parser.add_argument("--self-test-only", action="store_true",
                        help="run the needle self-test and exit; touches no "
                             "game file")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if args.self_test_only:
        result = self_test_needle_set(build_needle_set())
        sys.stdout.write(dump_json(result))
        return 0 if result["passed"] else 1

    if not args.path:
        print("error: a path is required unless --self-test-only is given",
              file=sys.stderr)
        return 2

    module_paths = None
    if args.module_only:
        module_paths = [args.path] + list(args.extra_module)
        for candidate in module_paths:
            if not os.path.isfile(candidate):
                print("error: not a file: %s" % candidate, file=sys.stderr)
                return 2
        install_root = args.install_dir or pe_info.detect_install_root(args.path)
    else:
        if not os.path.isdir(args.path):
            print("error: not a directory: %s (use --module-only for a single "
                  "file)" % args.path, file=sys.stderr)
            return 2
        install_root = args.install_dir or os.path.abspath(args.path)

    inventory_path = None
    if module_paths is None and not args.no_inventory:
        inventory_path = args.inventory or discover_inventory(
            pathguard.default_repo_root())
        if inventory_path is None:
            print("note: no install inventory found; walking the installation",
                  file=sys.stderr)

    checked = None
    if args.out:
        try:
            checked = pathguard.check_output_path(args.out, install_root,
                                                 what="--out")
        except (pathguard.OutputPathRefused, ValueError) as error:
            print("error: %s" % error, file=sys.stderr)
            return 2

    try:
        document = analyze(
            install_root if module_paths is None else "",
            inventory_path=inventory_path,
            wide_scan=not args.no_wide_scan and module_paths is None,
            module_paths=module_paths,
            want_entropy=not args.no_entropy,
            primary_patterns=list(args.primary) or None,
        )
    except PEFormatError as error:
        print("error: %s" % error, file=sys.stderr)
        return 2
    except OSError as error:
        print("error: %s" % error, file=sys.stderr)
        return 2

    written = None
    if checked:
        try:
            written = write_text(dump_json(document), checked, install_root, "--out")
        except pathguard.OutputPathRefused as error:
            print("error: %s" % error, file=sys.stderr)
            return 2
        except OSError as error:
            print("error: cannot write: %s" % error, file=sys.stderr)
            return 2

    if args.json:
        sys.stdout.write(dump_json(document))
    else:
        print(format_summary(document))
        if written:
            print("\nwritten: %s" % written)
    return 0


if __name__ == "__main__":
    sys.exit(main())
