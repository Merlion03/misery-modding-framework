// C5Io.h -- the CR-01C5 registration path's input block, shared.
//
// WHY THIS MOVED OUT OF THE PROBE
// -------------------------------
// This struct WAS defined inside CR01C5ProbeDll.cpp, where only the probe could
// see it, because until now only the Python controller ever filled one -- it
// packed the bytes by layout from the other side of a process boundary.
//
// Production has to fill it in-process, from the binding profile and the current
// content generation, so the definition has to be reachable from more than one
// translation unit. It was MOVED, not rewritten: the field order, the packing
// and the size assert are exactly what the proven path has always used, and the
// assert is what will catch it if that ever stops being true.
//
// Nothing else about the registration path changed. CR01C5ProbeDll.cpp still
// owns the jobs; this file only says what they are handed.
#pragma once

#include <cstdint>

// The size the Python controller packs and the C++ side expects. If these ever
// disagree the struct is being read at the wrong layout, which is worse than a
// build failure -- so it is a build failure.
#define C5IO_EXPECTED_SIZE 5648

static constexpr int TXT_CAP = 128;
constexpr uint64_t kC5Magic = 0x4950502D43350000ULL;  // "IPP-C5" then two NUL bytes
constexpr uint32_t kC5Proto = 1;
constexpr int kNameMax = 96;

#pragma pack(push, 1)
struct C5Io {
    uint64_t magic; uint32_t proto; uint32_t struct_size;
    uint64_t add_ticker, get_core_ticker, fmemory_malloc, fmemory_free;
    uint8_t sig_add[16], sig_get[16], sig_malloc[16];
    uint64_t process_event, cdo_stringlib, fn_conv_str_to_name;
    uint64_t cdo_gameplaystatics, fn_spawn_object;
    uint64_t cdo_textlib, fn_str_to_text, fn_text_to_str;
    uint64_t cdo_syslib, fn_load_asset_blocking, fn_soft_to_string, texture2d_class;
    uint64_t datatable_class, transient_package, row_struct;
    uint64_t item_list, master_item_list, expected_plain_vtable;
    uint64_t expected_composite_vtable, master_class;
    uint64_t add_row, remove_row, initialize_struct, destroy_struct;
    uint64_t set_root_flags, clear_root_flags;
    uint64_t guobjectarray_objects_ptr;
    uint64_t player_inventory, fn_additem, fn_removeitem, fn_sgk_itemdetails;
    uint64_t cdo_sgkfunctions, reserved_obj;
    uint32_t off_parent_tables, off_rowstruct, off_delegate, off_inventory_array;
    uint32_t off_name, off_shortname, off_description, off_inventory_icon;
    uint32_t off_weight, off_width, off_height, off_maxstack, off_allowstacking, pad0;
    double val_weight;
    int32_t val_width, val_height, val_maxstack; uint8_t val_allowstacking; uint8_t pad1[3];
    int32_t inv_amount, inv_quickbind, inv_useamount, inv_decaytime, inv_rotated, inv_inuse;
    float inv_durability; uint32_t pad2;
    uint16_t row_name[kNameMax];
    uint16_t trigger_name[kNameMax];
    uint8_t slot_in[80];
    uint16_t name_in[TXT_CAP], shortname_in[TXT_CAP], desc_in[TXT_CAP];
    uint16_t name_row[TXT_CAP], shortname_row[TXT_CAP], desc_row[TXT_CAP];
    uint16_t name_res[TXT_CAP], shortname_res[TXT_CAP], desc_res[TXT_CAP];
    uint16_t icon_pkg_in[TXT_CAP], icon_asset_in[TXT_CAP], icon_path_roundtrip[TXT_CAP];
    uint64_t empty_textdata[3];
    uint64_t our_textdata[3];
    uint64_t row_textdata[3];
    uint64_t icon_object, icon_item_ptr, icon_class, icon_outer;
    uint64_t icon_store_handle, row_icon_ptr, resolve_icon_ptr, icon_reserved;
    uint32_t icon_size_x, icon_size_y, icon_rooted_after_acquire, icon_rooted_after_release;
    uint32_t loadicon_ran, verifyicon_ran, releaseicon_ran, soft_roundtrip_ok;
    // --- CR-01C5 world representation inputs ---
    uint64_t staticmesh_class, world_class, actor_class, c5_pad0;
    uint32_t off_move_icon, off_override_flag, off_override_sizey, off_override_sizex;
    uint32_t off_worldclass, off_staticmesh, off_itemoffsets, off_rot;
    uint32_t off_trans, off_scale, want_sizex, want_sizey;
    double want_scale_x, want_scale_y, want_scale_z;
    double want_trans_x, want_trans_y, want_trans_z;
    uint16_t mesh_pkg_in[TXT_CAP], mesh_asset_in[TXT_CAP], mesh_path_roundtrip[TXT_CAP];
    // outputs
    uint32_t activated, initialized, state, wait_stopped_ok;
    uint32_t create_ran, populate_ran, attach_ran, detach_ran;
    uint32_t zero_ran, release_ran, resolve_ran, additem_ran;
    uint32_t removeitem_ran, gt_tid, fstring_ok, err;
    uint32_t err_step, internal_index, temp_freed, rooted_after_acquire;
    uint32_t rooted_after_release, owned_count, item_flags, table_addrow_matches;
    uint32_t table_removerow_matches, resolve_found, use_item_decay, use_durability;
    uint32_t parent_num_before, parent_max, parent_num_after_attach, parent_num_after_detach;
    uint32_t verifytext_ran, resolvetext_ran, text_fields_written, internrow_ran;
    uint64_t table_ptr, table_item_ptr, table_class, table_outer, table_vtable;
    uint64_t table_rowstruct_after, row_fname, trigger_fname, temp_ptr, store_handle;
    uint64_t parent_data, parent_elem0, parent_elem1_before, parent_elem1_after;
    uint8_t out_remaining_invitem[48];
    uint8_t out_newitemslot[16];
    uint32_t out_remaining_item, resolve_width, resolve_height, resolve_maxstack;
    double resolve_weight; uint32_t resolve_allowstacking, pad3;
    // --- CR-01C5 world representation outputs ---
    uint64_t mesh_object, mesh_item_ptr, mesh_class, mesh_store_handle;
    uint64_t mesh_pkg_name, mesh_asset_name;
    uint64_t row_move_icon, row_worldclass, resolve_worldclass, c5_pad1;
    uint32_t loadmesh_ran, verifymesh_ran, releasemesh_ran, mesh_soft_roundtrip_ok;
    uint32_t mesh_rooted_after_acquire, mesh_rooted_after_release, row_override, row_sizex;
    uint32_t row_sizey, resolve_override, resolve_sizex, resolve_sizey;
    double row_scale_x, row_scale_y, row_scale_z;
    double resolve_scale_x, resolve_scale_y, resolve_scale_z;
    uint64_t row_staticmesh_pkg, row_staticmesh_asset;
    uint64_t resolve_staticmesh_pkg, resolve_staticmesh_asset;
    // The UClass* actually written into the row's WorldClass field.
    //
    // Defaults to the game's own world item class, which is what every row
    // carried before a mod could ship one. A mod that declares its own world
    // class -- proven possible by E-3c -- has it validated and put here, and
    // JobPopulate writes THIS rather than the anchor.
    //
    // Taken from `reserved`, so the wire format and every existing field offset
    // are unchanged and cr01c5_controller's size assert still holds.
    uint64_t row_worldclass_write;
    uint64_t reserved[1];
};
#pragma pack(pop)
static_assert(sizeof(C5Io) == C5IO_EXPECTED_SIZE, "C5Io layout must match the controller");
