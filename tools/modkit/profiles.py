#!/usr/bin/env python3
"""Safe parent-material profiles.

A profile says how to drive ONE material the game already ships: which parameter
carries which map, and -- for a packed mask -- which channel is which. Both are
build-specific facts that were measured, not conventions that can be assumed.

WHY THE CHANNEL ORDER IS A MEASUREMENT
--------------------------------------
The mask parameter is called ``ARM``, which reads as AO / Roughness / Metallic.
That name is NOT the evidence. This game also ships ``M_Master_material``, which
declares its own mask as ``MT(R)_R(G)_AO(B)`` -- the reverse R/B order. So two
shipped masters genuinely disagree and the name could not settle it.

The order below came from a controlled A/B: a reference surface metallic under
EITHER reading rendered as a red mirror, one candidate matched it and the other
looked like glossy plastic. G was never in question, since roughness is the
middle channel in both conventions -- which is what reduced the experiment to a
single unknown bit.

A parent with no profile here is UNSUPPORTED, and asking for it produces a
diagnostic. Guessing parameter names on an unmeasured parent would produce a
material that builds, cooks, stages and then renders as the default checker.
"""

M_BASIC = "/Game/PlayerElectricitySystem/Materials/M_BasicMaterial"

PROFILES = {
    M_BASIC: {
        "parent": M_BASIC,
        "base_color_parameter": "BaseColor",
        "mask_parameter": "ARM",
        "normal_parameter": "Normal",
        # measured, not inferred from the parameter's name
        "mask_channels": ("ao", "roughness", "metallic"),
        "supports": ("base_color", "ao", "roughness", "metallic", "normal"),
        "does_not_support": {
            "emissive": "no emissive parameter is reachable on this parent under any "
                        "of the three names tested; an emissive-overridden instance "
                        "and an identical control were indistinguishable at every "
                        "angle",
        },
        "evidence": "research/evidence/CR-01C6/ARM-and-EMISSIVE-RESOLVED.json",
        "shader_cost": "zero: an instance with no static-parameter overrides reuses "
                       "the parent's existing shader map, so the cook produces no "
                       "shader library and no shader-code chunks",
    },
}


class UnsupportedParent(Exception):
    def __init__(self, parent):
        super().__init__(
            "%r has no measured profile. A profile records which parameter carries "
            "which map and, for a packed mask, which channel is which -- both are "
            "measurements. Guessing them would produce a material that builds, cooks, "
            "stages and then renders as the default checker. Known parents: %s"
            % (parent, sorted(PROFILES)))
        self.parent = parent


def profile_for(parent):
    profile = PROFILES.get(parent)
    if profile is None:
        raise UnsupportedParent(parent)
    return profile


def is_supported(parent):
    return parent in PROFILES
