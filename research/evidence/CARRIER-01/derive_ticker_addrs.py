"""Reproduce, read-only and fingerprint-gated, the FTSTicker addresses from the
survey via string anchors, and determine which AddTicker overload 0xf4ded0 is.
No guessed RVA: every address is reached from a string literal xref + disasm.
"""
import struct, hashlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE = r"D:\Games\Steam\steamapps\common\MISERY\MISERY\Binaries\Win64\MISERY-Win64-Shipping.exe"
EXPECT = "bace50f7185d095d03ee18a2fea701c747810c31f2037bda21ea57a81f013331"
data = open(EXE, "rb").read()
assert hashlib.sha256(data).hexdigest() == EXPECT, "build hash mismatch"

pe = struct.unpack_from("<I", data, 0x3C)[0]; coff = pe+4; opt = coff+20
IMAGE_BASE = struct.unpack_from("<Q", data, opt+24)[0]
nsec = struct.unpack_from("<H", data, coff+2)[0]; sizeopt = struct.unpack_from("<H", data, coff+16)[0]
sect = opt+sizeopt; secs = []
for i in range(nsec):
    b = sect+i*40; nm = data[b:b+8].rstrip(b"\x00").decode("latin1")
    vs, va, rs, rp = struct.unpack_from("<IIII", data, b+8); secs.append((nm, va, vs, rp, rs))
def off_to_rva(o):
    for nm, va, vs, rp, rs in secs:
        if rp <= o < rp+rs: return va+(o-rp)
def va_to_off(v):
    r = v-IMAGE_BASE
    for nm, va, vs, rp, rs in secs:
        if va <= r < va+max(vs, rs) and r-va < rs: return rp+(r-va)
def read_va(v, n):
    o = va_to_off(v); return data[o:o+n]

text = next(s for s in secs if s[0]==".text"); tb=data[text[3]:text[3]+text[4]]; TVA=IMAGE_BASE+text[1]
TLO, THI = IMAGE_BASE+text[1], IMAGE_BASE+text[1]+text[2]
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True

ANCHORS = ["RetirePakReaders", "FBackgroundableTicker", "InterchangeManagerTickHandle"]

def find_str_va(s):
    out = []
    for enc in ("utf-16-le", "ascii"):
        pat = s.encode(enc) + (b"\x00\x00" if enc == "utf-16-le" else b"\x00")
        i = 0
        while True:
            idx = data.find(pat, i)
            if idx == -1: break
            r = off_to_rva(idx)
            if r is not None: out.append((enc, IMAGE_BASE+r))
            i = idx+2
    return out

def lea_xrefs(target_va):
    hits = []; n = len(tb); i = 0
    while i < n-7:
        if 0x48 <= tb[i] <= 0x4F and tb[i+1] == 0x8D:
            modrm = tb[i+2]
            if (modrm >> 6) == 0 and (modrm & 7) == 5:
                disp = struct.unpack_from("<i", tb, i+3)[0]
                if TVA+i+7+disp == target_va:
                    hits.append(TVA+i)
                i += 1; continue
        i += 1
    return hits

def calls_after(site_va, count=40):
    """Disassemble forward from site, collect CALL rel32 targets."""
    o = va_to_off(site_va); code = data[o:o+300]
    tgts = []
    for insn in md.disasm(code, site_va):
        if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
            tgts.append(int(insn.op_str, 16))
        count -= 1
        if count <= 0: break
    return tgts

print("build hash OK; image_base=0x%x" % IMAGE_BASE)
common = {}
for a in ANCHORS:
    svas = find_str_va(a)
    print("\nanchor %-30s -> %s" % (a, [(e, hex(v)) for e, v in svas]))
    for enc, sva in svas:
        for site in lea_xrefs(sva):
            tgts = calls_after(site)
            print("  LEA@0x%x (RVA 0x%x) calls: %s" % (site, site-IMAGE_BASE, [hex(t) for t in tgts[:6]]))
            for t in tgts:
                if TLO <= t < THI:
                    common[t] = common.get(t, 0)+1

print("\n=== call targets ranked by how many anchor sites reach them ===")
for t, c in sorted(common.items(), key=lambda kv: -kv[1])[:8]:
    print("  0x%x (RVA 0x%x)  reached by %d anchor site(s)" % (t, t-IMAGE_BASE, c))

for name, rva in [("GetCoreTicker", 0xf53370), ("AddTicker", 0xf4ded0)]:
    va = IMAGE_BASE+rva
    print("\n--- claimed %s @ RVA 0x%x (VA 0x%x) ---" % (name, rva, va))
    print("    reached-by-anchors count:", common.get(va, 0))
    print("    first bytes:", read_va(va, 16).hex())
    o = va_to_off(va); code = data[o:o+80]
    for insn in list(md.disasm(code, va))[:12]:
        print("    0x%x: %-10s %s" % (insn.address, insn.mnemonic, insn.op_str))
