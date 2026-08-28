"""Corroboration test: locate the ANSI __FILE__ string 'UObjectGlobals.cpp'
(present once), find all lea r64,[rip+disp] xrefs to it in .text, map each to
its enclosing .pdata function, and report where 0x12CF3B0 sits relative to that
cluster. LoadPackage lives in UObjectGlobals.cpp, so its function should be in
(or adjacent to) the same VA neighborhood as other retained refs from that TU.
"""
import struct, bisect

EXE = r"D:\Games\Steam\steamapps\common\MISERY\MISERY\Binaries\Win64\MISERY-Win64-Shipping.exe"
CLAIMED = 0x12CF3B0
data = open(EXE, "rb").read()

pe = struct.unpack_from("<I", data, 0x3C)[0]; coff = pe + 4; opt = coff + 20
image_base = struct.unpack_from("<Q", data, opt + 24)[0]
nsec = struct.unpack_from("<H", data, coff + 2)[0]
sizeopt = struct.unpack_from("<H", data, coff + 16)[0]
sect = opt + sizeopt; secs = []
for i in range(nsec):
    b = sect + i*40; nm = data[b:b+8].rstrip(b"\x00").decode("latin1")
    vs, va, rs, rp = struct.unpack_from("<IIII", data, b+8); secs.append((nm, va, vs, rp, rs))
def r2o(rva):
    for nm, va, vs, rp, rs in secs:
        if va <= rva < va+max(vs, rs) and rva-va < rs: return rp+(rva-va)
    return None
def o2r(off):
    for nm, va, vs, rp, rs in secs:
        if rp <= off < rp+rs: return va+(off-rp)
    return None

# .pdata function begins
pd = next(s for s in secs if s[0] == ".pdata"); _, pva, pvs, prp, prs = pd
recs = []
for i in range(pvs//12):
    b0, e0, u0 = struct.unpack_from("<III", data, prp+i*12)
    if b0 or e0: recs.append((b0, e0))
recs.sort()
begins = [b for b, e in recs]
def func_of(rva):
    j = bisect.bisect_right(begins, rva) - 1
    if j >= 0:
        b0, e0 = recs[j]
        if b0 <= rva < e0: return b0, e0
    return None

# locate ANSI 'UObjectGlobals.cpp\x00'
needle = b"UObjectGlobals.cpp\x00"
offs = []
i = 0
while True:
    idx = data.find(needle, i)
    if idx == -1: break
    offs.append(idx); i = idx+1
print("ANSI 'UObjectGlobals.cpp' occurrences:", [hex(o) for o in offs],
      "VAs:", [hex(image_base+o2r(o)) for o in offs if o2r(o)])

text = next(s for s in secs if s[0] == ".text"); _, tva, tvs, trp, trs = text
tb = data[trp:trp+trs]; tvb = image_base + tva

def lea_xrefs(target_va):
    hits = []; n = len(tb); i = 0
    while i < n-7:
        if 0x48 <= tb[i] <= 0x4F and tb[i+1] == 0x8D:
            modrm = tb[i+2]
            if (modrm >> 6) == 0 and (modrm & 7) == 5:
                disp = struct.unpack_from("<i", tb, i+3)[0]
                insn_va = tvb + i
                if insn_va + 7 + disp == target_va:
                    hits.append(insn_va); i += 7; continue
        i += 1
    return hits

all_xref_funcs = []
for o in offs:
    rva = o2r(o); va = image_base + rva
    xr = lea_xrefs(va)
    print("\nstring va 0x%x : %d lea xref(s)" % (va, len(xr)))
    for insn_va in xr:
        fn = func_of(insn_va - image_base)
        fstr = ("func 0x%x-0x%x" % (fn[0], fn[1])) if fn else "no-func"
        print("   lea @0x%x  RVA 0x%x  in %s" % (insn_va, insn_va-image_base, fstr))
        if fn: all_xref_funcs.append(fn[0])

cf = func_of(CLAIMED)
print("\nclaimed 0x%x .pdata func:" % CLAIMED, ("0x%x-0x%x" % cf) if cf else None)
if all_xref_funcs:
    uniq = sorted(set(all_xref_funcs))
    print("distinct funcs referencing __FILE__:", [hex(x) for x in uniq])
    print("claimed RVA 0x%x among them: %s" % (CLAIMED, CLAIMED in uniq))
    print("nearest __FILE__-ref func to claimed: min |delta| = 0x%x"
          % min(abs(x-CLAIMED) for x in uniq))
