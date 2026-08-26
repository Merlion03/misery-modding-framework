"""Independent re-decode of .pdata chunk structure. Deliberately NOT sharing
sigmake's code path: reads every record's UNWIND_INFO head without the distinct-
address de-duplication, and validates the chain relation structurally."""
import os, struct, sys, collections
sys.path[:0] = [os.path.abspath('tools/fingerprint'), os.path.abspath('tools/inventory')]
import pe_info

PATH = r"D:/Games/Steam/steamapps/common/MISERY/MISERY/Binaries/Win64/MISERY-Win64-Shipping.exe"
img = pe_info.Image.open(PATH)
h = pe_info.PEHeaders(img)
rva, size = h.directory(3)
off = h.rva_to_offset(rva)
n = min(size, h.rva_available(rva)) // 12
print("records", n, "dir rva", rva, "size", size)

with open(PATH, "rb", buffering=0) as f:
    f.seek(off)
    blob = f.read(n * 12)
recs = list(struct.iter_unpack("<III", blob))
begins = [r[0] for r in recs]
begin_set = set(begins)

# Read the whole .rdata-ish span that holds unwind info in one go: map the
# section containing the first unwind address and slurp it.
uw = sorted({r[2] for r in recs})
print("distinct unwind addrs", len(uw), "min", hex(uw[0]), "max", hex(uw[-1]))
sec = None
for s in h.sections:
    span = max(s["vsize"], s["rsize"])
    if s["rva"] <= uw[0] < s["rva"] + span:
        sec = s
print("unwind lives in", sec["name"])
with open(PATH, "rb", buffering=0) as f:
    f.seek(sec["raw_pointer"])
    sdata = f.read(sec["rsize"])
base = sec["rva"]

def head(u):
    o = u - base
    if 0 <= o and o + 4 <= len(sdata):
        return sdata[o:o+4]
    return None

CHAIN = 0x4
flags_hist = collections.Counter()
chunks = []
bad_head = 0
for i, (b, e, u) in enumerate(recs):
    hd = head(u)
    if hd is None:
        bad_head += 1
        continue
    fl = hd[0] >> 3
    ver = hd[0] & 0x7
    flags_hist[(ver, fl)] += 1
    if fl & CHAIN:
        codes = hd[2]
        tail = u + 4 + 2 * ((codes + 1) & ~1)
        to = tail - base
        if 0 <= to and to + 12 <= len(sdata):
            pb, pe_, pu = struct.unpack_from("<III", sdata, to)
            chunks.append((i, b, e, pb, pe_, pu))
print("bad_head", bad_head)
print("(version, flags) histogram:", dict(flags_hist))
print("chunk records", len(chunks))
prim_in_table = sum(1 for c in chunks if c[3] in begin_set)
print("chunk primaries that ARE a BeginAddress in the table:", prim_in_table,
      "of", len(chunks))
# a genuine continuation chunk must not overlap its primary's range
overlap = sum(1 for c in chunks if not (c[2] <= c[3] or c[4] <= c[1]))
print("chunk ranges overlapping their primary range:", overlap)
# does the huge shared unwind info carry CHAININFO?
cnt = collections.Counter(r[2] for r in recs)
top = cnt.most_common(3)
for u, k in top:
    hd = head(u)
    print("unwind 0x%x shared by %d records; head=%s flags=%d" % (u, k, hd.hex(), hd[0] >> 3))
by_prim = collections.Counter(c[3] for c in chunks)
print("distinct primaries owning >=1 chunk:", len(by_prim))
print("chunks-per-primary histogram:", dict(sorted(collections.Counter(by_prim.values()).items())[:12]))
print("max chunks on one primary:", by_prim.most_common(1))
img.close()
