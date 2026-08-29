import sys,os,struct
sys.path.insert(0,os.path.join("research","instruments","eri"))
import eri
SPOR=0x90
api=eri.Win32Api(); i01=eri.run_i01(api, eri.DEFAULT_PROCESS_NAME)
h=eri.open_process_read_only(api,i01["pid"])
try:
    base,size=i01["base_address"],i01["image_size_bytes"]
    i02=eri.run_i02(api,h,base,size,guobjectarray_rva=eri.DEFAULT_GUOBJECTARRAY_RVA,sample_size=eri.DEFAULT_I02_SAMPLE_SIZE,poll_interval_seconds=0,max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
    i03=eri.run_i03(api,h,base,size,namepool_rva=eri.DEFAULT_NAMEPOOL_RVA,name_pool_initialized_rva=eri.DEFAULT_NAME_POOL_INITIALIZED_RVA,name_entry_id=0)
    np=i03["namepool_live_va"]
    w=eri.walk_object_universe(api,h,i02["objects_ptr_live_va"],i02["num_elements"],base,size,np,
        class_private_offset=eri.DEFAULT_CLASS_PRIVATE_OFFSET,name_private_offset=eri.DEFAULT_NAME_PRIVATE_OFFSET,
        outer_private_offset=eri.DEFAULT_OUTER_PRIVATE_OFFSET,max_scan_indices=eri.DEFAULT_I02_MAX_SCAN_INDICES)
    objs=w["objects_by_address"]
    itemlist=None; fmeta=None
    for a,r in objs.items():
        if not r.get("name_ok"): continue
        nm=r.get("name_text"); cn=(objs.get(r.get("class_ptr") or 0) or {}).get("name_text")
        if cn=="DataTable" and nm=="ItemList": itemlist=a
        if nm=="Function" and eri.canonicalize_object_path(eri.resolve_object_path(a,objs).get("object_path"))=="/Script/CoreUObject.Function": fmeta=a
    print("ItemList @0x%x"%itemlist)
    # every live UFunction: does its bytecode reference ItemList?
    refs_by_owner={}
    n=0
    for a,r in objs.items():
        if not r.get("name_ok"): continue
        if r.get("class_ptr")!=fmeta: continue
        n+=1
        try:
            d=eri._read_u64(api,h,a+SPOR); cnt=struct.unpack("<i",api.read_process_memory(h,a+SPOR+8,4))[0]
        except Exception: continue
        if not d or not (0<cnt<4096): continue
        try: raw=api.read_process_memory(h,d,cnt*8)
        except Exception: continue
        ptrs=[struct.unpack_from("<Q",raw,i*8)[0] for i in range(cnt)]
        if itemlist in ptrs:
            owner=eri.resolve_object_path(a,objs).get("object_path") or ""
            names=[(objs.get(p) or {}).get("name_text") for p in ptrs]
            refs_by_owner.setdefault(owner.rsplit(".",1)[0].split("/")[-1],[]).append(
                (r.get("name_text"),[x for x in names if x and ("Row" in x or "DataTable" in x)]))
    print("UFunctions scanned:",n)
    print("\n=== classes whose bytecode references ItemList ===")
    for owner,fns in sorted(refs_by_owner.items()):
        print("\n %s  (%d functions)"%(owner,len(fns)))
        for fn,calls in sorted(fns)[:12]:
            print("    %-38s %s"%(fn,calls[:5]))
finally: api.close_handle(h)
