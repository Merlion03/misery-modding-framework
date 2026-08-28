"""Independent re-derivation of the `LoadPackage(const TCHAR*, ...)` address in
the installed MISERY Shipping image, from string anchors in the matching UE
5.4.4 source. No trust in any prior number. Prints where the anchors' xrefs
land and whether they cluster at the claimed RVA 0x12CF3B0.

Method: the const TCHAR* overload of LoadPackage (UObjectGlobals.cpp:1985)
emits four Warning-level UE_LOG strings unique to it (Warning survives
Shipping). Find each string (UTF-16LE) in the file, map to its VA, then scan
.text for `48 8D <modrm(mod=00,rm=101)> <disp32>` (lea r64,[rip+disp32]) whose
target equals the string VA. Every such site must sit inside one function; its
start is LoadPackage.
"""
import struct

EXE = r"D:\Games\Steam\steamapps\common\MISERY\MISERY\Binaries\Win64\MISERY-Win64-Shipping.exe"
CLAIMED_RVA = 0x12CF3B0

ANCHORS = {
    "short_script": "LoadPackage: %s is a short script package name.",
    "cant_find":    "LoadPackage can't find package %s.",
    "empty_name":   "Empty name passed to LoadPackage.",
}

with open(EXE, "rb") as f:
    data = f.read()

# --- minimal PE parse ---
assert data[:2] == b"MZ"
pe_off = struct.unpack_from("<I", data, 0x3C)[0]
assert data[pe_off:pe_off+4] == b"PE\x00\x00"
coff = pe_off + 4
num_sections = struct.unpack_from("<H", data, coff + 2)[0]
size_opt = struct.unpack_from("<H", data, coff + 16)[0]
opt = coff + 20
magic = struct.unpack_from("<H", data, opt)[0]
assert magic == 0x20B, "expected PE32+"
image_base = struct.unpack_from("<Q", data, opt + 24)[0]
sec_tbl = opt + size_opt

sections = []
for i in range(num_sections):
    b = sec_tbl + i * 40
    name = data[b:b+8].rstrip(b"\x00").decode("latin1")
    vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, b + 8)
    sections.append((name, vaddr, vsize, rawptr, rawsize))

print("image_base = 0x%x" % image_base)
for s in sections:
    print("  %-8s RVA=0x%08x vsize=0x%08x raw=0x%08x rawsize=0x%08x" % s)

def rva_to_off(rva):
    for name, va, vs, rp, rs in sections:
        if va <= rva < va + max(vs, rs):
            if rva - va < rs:
                return rp + (rva - va)
    return None

def off_to_rva(off):
    for name, va, vs, rp, rs in sections:
        if rp <= off < rp + rs:
            return va + (off - rp)
    return None

text = next(s for s in sections if s[0] == ".text")
text_name, text_rva, text_vsize, text_rawptr, text_rawsize = text
text_bytes = data[text_rawptr:text_rawptr + text_rawsize]
text_va_base = image_base + text_rva
print("\n.text VA span: 0x%x .. 0x%x (raw 0x%x)" % (
    text_va_base, text_va_base + text_rawsize, text_rawptr))

# --- find each anchor string VA (UTF-16LE) ---
string_vas = {}
for key, s in ANCHORS.items():
    pat = s.encode("utf-16-le")
    occ = []
    start = 0
    while True:
        idx = data.find(pat, start)
        if idx == -1:
            break
        # require NUL-terminated (wide) to avoid substring false hits
        rva = off_to_rva(idx)
        occ.append((idx, rva, image_base + rva if rva is not None else None))
        start = idx + 2
    string_vas[key] = occ
    print("\nanchor %-12s %r" % (key, s))
    for off, rva, va in occ:
        print("   off=0x%x rva=0x%x va=0x%x" % (off, rva, va))

# --- scan .text for lea r64,[rip+disp32] referencing each string VA ---
def find_lea_xrefs(target_va):
    hits = []
    n = len(text_bytes)
    i = 0
    while i < n - 7:
        # REX.W prefix 0x48..0x4F with W set, opcode 0x8D (LEA), modrm mod=00 rm=101
        b0 = text_bytes[i]
        if 0x48 <= b0 <= 0x4F and text_bytes[i+1] == 0x8D:
            modrm = text_bytes[i+2]
            mod = modrm >> 6
            rm = modrm & 7
            if mod == 0 and rm == 5:  # RIP-relative
                disp = struct.unpack_from("<i", text_bytes, i+3)[0]
                insn_len = 7  # rex+8d+modrm+disp32
                insn_va = text_va_base + i
                next_va = insn_va + insn_len
                if next_va + disp == target_va:
                    reg = ((b0 & 0x4) << 1) | (modrm >> 3 & 7)  # REX.R extends reg
                    hits.append((insn_va, reg))
                i += 1
                continue
        i += 1
    return hits

print("\n=== LEA xref sites ===")
all_hits = []
for key, occ in string_vas.items():
    for off, rva, va in occ:
        if va is None:
            continue
        hits = find_lea_xrefs(va)
        for insn_va, reg in hits:
            all_hits.append((insn_va, key, va, reg))
            print("  lea @ 0x%x  ->  %-12s (str va 0x%x) reg=%d  [RVA 0x%x]" % (
                insn_va, key, va, reg, insn_va - image_base))

if not all_hits:
    print("  (none found)")
else:
    lo = min(h[0] for h in all_hits)
    hi = max(h[0] for h in all_hits)
    print("\nxref VA span: 0x%x .. 0x%x  (RVA 0x%x .. 0x%x)" % (
        lo, hi, lo - image_base, hi - image_base))
    claimed_va = image_base + CLAIMED_RVA
    print("claimed LoadPackage start VA = 0x%x (RVA 0x%x)" % (claimed_va, CLAIMED_RVA))
    inside = all(claimed_va <= h[0] for h in all_hits)
    span = hi - claimed_va
    print("all xrefs at/after claimed start: %s ; max offset past start = 0x%x" % (inside, span))
