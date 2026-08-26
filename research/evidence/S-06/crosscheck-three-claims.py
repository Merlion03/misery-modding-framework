"""Second, independent measurement of three headline claims.

Deliberately shares NO code with sigmake/sigscan: plain file reads, plain
struct, plain bytes.find. If any of the three disagrees, the finding is wrong.
"""
import os, struct, sys, json, hashlib
sys.path[:0] = [os.path.abspath('tools/fingerprint'), os.path.abspath('tools/inventory')]
import pe_info   # used ONLY for header offsets, not for any counting

SH = r"D:/Games/Steam/steamapps/common/MISERY/MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe"
OR = r"D:/Games/Steam/steamapps/common/MISERY/MISERY/Binaries/Win64/MISERY.exe"

def sections(path):
    img = pe_info.Image.open(path)
    try:
        h = pe_info.PEHeaders(img)
        return [dict(s) for s in h.sections], h.directory(5), h.size_of_image
    finally:
        img.close()

# ---- claim 1: .reloc holds 941 132 fixups and ZERO of them lie in .text ----
secs, (rrva, rsize), _ = sections(SH)
def off_of(rva, secs):
    for s in secs:
        span = max(s["vsize"], s["rsize"])
        if s["rva"] <= rva < s["rva"] + span:
            return s["raw_pointer"] + (rva - s["rva"])
    return None
with open(SH, "rb") as f:
    f.seek(off_of(rrva, secs)); blob = f.read(rsize)
pos = 0; fixups = []; skip = False
while pos + 8 <= len(blob):
    page, size = struct.unpack_from("<II", blob, pos)
    if size < 8 or pos + size > len(blob): break
    for i in range((size - 8) // 2):
        e, = struct.unpack_from("<H", blob, pos + 8 + i * 2)
        if skip: skip = False; continue
        t = e >> 12
        if t == 4: skip = True
        if t == 0: continue
        fixups.append((page + (e & 0xFFF), {1:2,2:2,3:4,4:4,10:8}.get(t, 0)))
    pos += size
print("claim 1: fixups counted independently =", len(fixups))
exec_spans = [(s["rva"], s["rva"] + max(s["vsize"], s["rsize"]), s["name"])
              for s in secs if s["characteristics"] & 0x20000020]
print("         executable spans:", [(hex(a), hex(b), n) for a, b, n in exec_spans])
in_exec = [r for r, w in fixups if any(a <= r < b for a, b, _ in exec_spans)]
print("         fixups landing inside an executable span =", len(in_exec))

# ---- claim 2: the 37-byte ICU body really does occur at 7 distinct RVAs ----
rvas = [0x566cfa0, 0x575ff60, 0x5760c20, 0x5760cc0, 0x5760d30, 0x576a340, 0x576beb0]
with open(SH, "rb") as f:
    bodies = []
    for r in rvas:
        f.seek(off_of(r, secs)); bodies.append(f.read(37))
print("claim 2: 7 reads of 37 bytes, distinct byte values =", len(set(bodies)))
print("         sha256 of the common body =", hashlib.sha256(bodies[0]).hexdigest()[:32])
# and count the body over .text with a plain find loop
text = next(s for s in secs if s["name"] == ".text")
with open(SH, "rb") as f:
    f.seek(text["raw_pointer"]); tb = f.read(text["rsize"])
n = 0; c = 0
while True:
    i = tb.find(bodies[0], c)
    if i < 0: break
    n += 1; c = i + 1
print("         plain bytes.find count over .text =", n)

# ---- claim 3: >=32-byte Shipping signatures present in the oracle, verified
#      by direct byte comparison rather than by the matcher ----
scan = json.load(open('research/evidence/S-07/scan-all-oracle-d04.json', encoding='utf-8'))
osecs, _, _ = sections(OR)
hits = [s for s in scan['signatures']
        if s['verdict'] != 'absent' and s['length'] >= 32 and s['hits']]
print("claim 3: >=32-byte signatures reported present in the oracle =", len(hits))
same = 0; checked = 0; mism = []
with open(SH, "rb") as fs, open(OR, "rb") as fo:
    for s in hits:
        src_off = s['source_file_offset']
        if src_off is None: continue
        fs.seek(src_off); a = fs.read(s['length'])
        fo.seek(s['hits'][0]['file_offset']); b = fo.read(s['length'])
        checked += 1
        if a == b: same += 1
        else: mism.append(s['label'][:40])
print("         direct byte-for-byte comparison: %d of %d identical" % (same, checked))
if mism: print("         MISMATCHES:", mism[:5])
