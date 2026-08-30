#!/usr/bin/env python3
"""Three items, all authored through the same public API.

The point of this file is what it does NOT contain: no special case, no branch,
no "if this is the radio". The production radio is one ``ItemDefinition`` among
others, built from the same constructor a third-party mod would call. If the
core ever has to know which of these it is holding, the abstraction has failed.

``radio_matches_proven_controller()`` at the bottom makes that claim checkable
rather than asserted: it compares the radio definition, field by field, against
the constants the already-proven CR-01C5 controller used for the run that passed
the owner's visual acceptance. If the definition layer cannot reproduce those
exact values, then "the radio is just a definition" is not true yet, and the
test says so.
"""
from definition import (AssetRef, DRAG_ICON_SAME_AS_INVENTORY, ItemDefinition, ItemId,
                        Transform)

RADIO_CONTENT = "/Game/MBPLTest/Items/Radio"
WORLD_ITEM_CLASS = "BP_StaticMasterItem_C"


def simple_item():
    """The smallest thing a mod can register: one generated item.

    Everything optional is left alone, so this also exercises the defaults --
    stacking off, drag icon following the inventory icon, identity transform.
    """
    return ItemDefinition(
        ItemId("mbpl", "simple_probe"),
        display_name="MBPL Simple Probe",
        short_name="Probe",
        description="The smallest item the framework can register.",
        weight=0.1,
        width=1, height=1,
        inventory_icon=AssetRef(RADIO_CONTENT + "/T_MBPL_Radio_Icon"),
        world_mesh=AssetRef(RADIO_CONTENT + "/SM_MBPL_Radio"),
        world_class=WORLD_ITEM_CLASS,
    )


def production_radio():
    """The radio -- authored exactly as any third-party mod would author it.

    These values are the ones that passed the owner's world drop and pickup
    acceptance. They live here as a definition, not as constants in the core.
    """
    return ItemDefinition(
        ItemId("mbpl", "radio"),
        display_name="MBPL Radio",
        short_name="Radio",
        description="A runtime-defined MBPL test radio.",
        weight=0.5,
        width=1, height=1,
        allow_stacking=False, max_stack=1,
        inventory_icon=AssetRef(RADIO_CONTENT + "/T_MBPL_Radio_Icon"),
        drag_icon_policy=DRAG_ICON_SAME_AS_INVENTORY,
        drag_icon_size=(100, 100),
        world_mesh=AssetRef(RADIO_CONTENT + "/SM_MBPL_Radio"),
        world_class=WORLD_ITEM_CLASS,
        # The small +Z lift ordinary vanilla 1x1 rows use, so the mesh does not
        # spawn intersecting the ground.
        transform=Transform(translation=(0.0, 0.0, 5.0)),
    )


def colliding_item(mod_id="othermod"):
    """A deliberate collision: a DIFFERENT mod claiming the radio's local id.

    Its derived row name is ``othermod__radio``, which does not collide with
    ``mbpl__radio`` -- namespacing is doing its job. To force a real collision
    the same mod_id must be used, which ``negative_same_mod_collision`` does.
    This one exists to show the distinction, because "two mods used the same
    local name" must NOT be a collision and it would be easy to write a registry
    where it was.
    """
    return ItemDefinition(
        ItemId(mod_id, "radio"),
        display_name="Another Mod's Radio",
        short_name="Radio",
        description="A different mod's item that happens to share a local name.",
        weight=1.0,
        width=1, height=1,
        inventory_icon=AssetRef(RADIO_CONTENT + "/T_MBPL_Radio_Icon"),
        world_mesh=AssetRef(RADIO_CONTENT + "/SM_MBPL_Radio"),
        world_class=WORLD_ITEM_CLASS,
    )


def negative_same_mod_collision():
    """The real negative case: the same mod_id AND local_id as the radio.

    Registering this while the radio is held must be refused, and refused with a
    code that says which kind of collision it was.
    """
    return ItemDefinition(
        ItemId("mbpl", "radio"),
        display_name="Duplicate Radio",
        short_name="Dup",
        description="Same namespace and same local id as the production radio.",
        weight=9.0,
        width=2, height=2,
        inventory_icon=AssetRef(RADIO_CONTENT + "/T_MBPL_Radio_Icon"),
        world_mesh=AssetRef(RADIO_CONTENT + "/SM_MBPL_Radio"),
        world_class=WORLD_ITEM_CLASS,
    )


# The values the proven CR-01C5 controller used for the accepted production run.
# Transcribed from the controller's own module constants, so that the comparison
# below is against what actually ran, not against what this file wishes had run.
PROVEN_C5_CONSTANTS = {
    "row_name": "mbpl__radio",
    "texts": {"Name": "MBPL Radio", "ShortName": "Radio",
              "Description": "A runtime-defined MBPL test radio."},
    "values": {"Weight": 0.5, "Width": 1, "Height": 1, "MaxStack": 1, "AllowStacking": 0},
    "icon": "/Game/MBPLTest/Items/Radio/T_MBPL_Radio_Icon",
    "mesh": "/Game/MBPLTest/Items/Radio/SM_MBPL_Radio",
    "world_class": "BP_StaticMasterItem_C",
    "drag_size": (100, 100),
    "scale": (1.0, 1.0, 1.0),
    "translation": (0.0, 0.0, 5.0),
}


def radio_matches_proven_controller():
    """Compare the radio DEFINITION against what the proven controller ran.

    Returns ``(ok, differences)``. Any difference means the definition layer
    cannot yet express the item that actually passed acceptance -- which would
    make "the radio is just a definition" false, however tidy the code looked.
    """
    d = production_radio()
    p = PROVEN_C5_CONSTANTS
    checks = [
        ("row_name", d.row_name, p["row_name"]),
        ("Name", d.display_name, p["texts"]["Name"]),
        ("ShortName", d.short_name, p["texts"]["ShortName"]),
        ("Description", d.description, p["texts"]["Description"]),
        ("Weight", d.weight, p["values"]["Weight"]),
        ("Width", d.width, p["values"]["Width"]),
        ("Height", d.height, p["values"]["Height"]),
        ("MaxStack", d.max_stack, p["values"]["MaxStack"]),
        ("AllowStacking", int(d.allow_stacking), p["values"]["AllowStacking"]),
        ("icon", d.inventory_icon.package, p["icon"]),
        ("drag_icon", d.effective_drag_icon().package, p["icon"]),
        ("mesh", d.world_mesh.package, p["mesh"]),
        ("world_class", d.world_class, p["world_class"]),
        ("drag_size", d.drag_icon_size, p["drag_size"]),
        ("scale", d.transform.scale, p["scale"]),
        ("translation", d.transform.translation, p["translation"]),
    ]
    differences = [{"field": name, "definition": got, "proven_controller": want}
                   for name, got, want in checks if got != want]
    return (not differences), differences


ALL_EXAMPLES = {
    "simple": simple_item,
    "radio": production_radio,
    "other_mod_same_local_name": colliding_item,
    "negative_same_mod_collision": negative_same_mod_collision,
}
