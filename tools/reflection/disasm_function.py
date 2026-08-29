#!/usr/bin/env python3
"""STRICTLY READ-ONLY. Disassemble the Kismet bytecode of named UFunctions from
the live process, with FProperty / UObject / UFunction / FName operands resolved.

Opens the process PROCESS_QUERY_INFORMATION | PROCESS_VM_READ through ERI's
single call site and writes nothing.

Grammar comes from tools/reflection/kismet_disasm.py, which is a transcription
of the engine's own UStruct::SerializeExpr; an unknown opcode raises rather than
resynchronising on operand bytes.

  disasm_function.py "BP_MoveIcon_C::SetMoveIcon" --out x.txt
  disasm_function.py --class BP_InventoryItemIcon_C          # every function
"""
import argparse
import json
import os
import struct
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO, "research", "instruments", "eri"))
sys.path.insert(0, os.path.join(REPO, "research", "instruments", "ipp"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import eri  # noqa: E402
import cr01c3_recon as recon  # noqa: E402
import kismet_disasm as kd  # noqa: E402

SCRIPT = 0x60
FFIELD_NAME = eri.FFIELD_NAME_PRIVATE_OFFSET
FFIELD_OWNER = 0x10


class LiveResolver:
    def __init__(self, api, h, np, objs):
        self.api, self.h, self.np, self.objs = api, h, np, objs
        self._p, self._n = {}, {}

    def _fname(self, eid):
        if eid in self._n:
            return self._n[eid]
        try:
            t = eri.decode_fname_entry_id(self.api, self.h, self.np, eid).get("text")
        except Exception:  # noqa: BLE001
            t = None
        self._n[eid] = t
        return t

    def prop(self, p):
        if not p:
            return "None"
        if p in self._p:
            return self._p[p]
        out = "FProperty(0x%x)" % p
        try:
            eid = eri._read_u32(self.api, self.h, p + FFIELD_NAME)
            nm = self._fname(eid)
            owner = eri._read_u64(self.api, self.h, p + FFIELD_OWNER) & ~1
            orec = self.objs.get(owner)
            oname = (orec or {}).get("name_text")
            if nm:
                out = "%s::%s" % (oname, nm) if oname else nm
        except Exception:  # noqa: BLE001
            pass
        self._p[p] = out
        return out

    def obj(self, p):
        if not p:
            return "None"
        r = self.objs.get(p)
        if not r or not r.get("name_ok"):
            return "UObject(0x%x)" % p
        cls = (self.objs.get(r.get("class_ptr") or 0) or {}).get("name_text")
        return "%s'%s'" % (cls or "?", r.get("name_text"))

    def func(self, p):
        if not p:
            return "None"
        r = self.objs.get(p)
        if not r or not r.get("name_ok"):
            return "UFunction(0x%x)" % p
        outer = eri._read_u64(self.api, self.h, p + eri.DEFAULT_OUTER_PRIVATE_OFFSET)
        own = (self.objs.get(outer) or {}).get("name_text")
        return "%s::%s" % (own or "?", r.get("name_text"))

    def name(self, eid, num):
        t = self._fname(eid)
        return ('"%s"' % t) if t else "FName(%d:%d)" % (eid, num)


def read_script(api, h, faddr):
    data = eri._read_u64(api, h, faddr + SCRIPT)
    num = struct.unpack("<i", api.read_process_memory(h, faddr + SCRIPT + 8, 4))[0]
    if not data or num <= 0 or num > (1 << 24):
        return b""
    return api.read_process_memory(h, data, num) or b""


def collect(api, h, np, objs, fmeta, want_class=None, want_pairs=()):
    """Returns [(owner_name, func_name, address)]."""
    out = []
    for a, r in objs.items():
        if r.get("class_ptr") != fmeta or not r.get("name_ok"):
            continue
        outer = eri._read_u64(api, h, a + eri.DEFAULT_OUTER_PRIVATE_OFFSET)
        own = (objs.get(outer) or {}).get("name_text")
        fn = r.get("name_text")
        if want_class and own == want_class:
            out.append((own, fn, a))
        for wc, wf in want_pairs:
            if own == wc and fn == wf:
                out.append((own, fn, a))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="*", help='"Owner::FunctionName"')
    ap.add_argument("--class", dest="cls", action="append", default=[],
                    help="disassemble every UFunction owned by this class")
    ap.add_argument("--out", default=None)
    ap.add_argument("--json", default=None)
    a = ap.parse_args(argv)

    pairs = []
    for t in a.target:
        if "::" not in t:
            ap.error("target must be Owner::FunctionName, got %r" % t)
        own, fn = t.split("::", 1)
        pairs.append((own, fn))

    api = eri.Win32Api()
    i01 = eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
    h = eri.open_process_read_only(api, i01["pid"])
    chunks, records = [], []
    try:
        np, objs = recon.universe(api, h, i01["base_address"], i01["image_size_bytes"])
        fmeta = recon.find_function_meta(objs)
        res = LiveResolver(api, h, np, objs)
        targets = []
        for c in a.cls:
            targets += collect(api, h, np, objs, fmeta, want_class=c)
        if pairs:
            targets += collect(api, h, np, objs, fmeta, want_pairs=pairs)
        seen = set()
        for own, fn, addr in sorted(targets, key=lambda x: (x[0], x[1])):
            if addr in seen:
                continue
            seen.add(addr)
            code = read_script(api, h, addr)
            head = "===== %s::%s  @0x%x  script=%d bytes" % (own, fn, addr, len(code))
            if not code:
                chunks.append(head + "\n  (no bytecode)")
                records.append({"owner": own, "function": fn, "address": "0x%x" % addr,
                                "script_len": 0, "instructions": []})
                continue
            try:
                ins = kd.disassemble(code, res)
                chunks.append(head + "\n" + kd.render(ins))
                records.append({"owner": own, "function": fn, "address": "0x%x" % addr,
                                "script_len": len(code), "instructions": ins})
            except Exception as e:  # noqa: BLE001
                chunks.append(head + "\n  DISASSEMBLY FAILED: %r" % (e,))
                records.append({"owner": own, "function": fn, "address": "0x%x" % addr,
                                "script_len": len(code), "error": repr(e)})
    finally:
        api.close_handle(h)

    text = "\n\n".join(chunks)
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(text + "\n")
        print("wrote", a.out, len(text), "bytes,", len(records), "functions")
    else:
        print(text)
    if a.json:
        with open(a.json, "w", encoding="utf-8", newline="\n") as f:
            json.dump(records, f, indent=1, sort_keys=True, default=str)
            f.write("\n")
        print("wrote", a.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
