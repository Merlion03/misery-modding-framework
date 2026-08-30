#!/usr/bin/env python3
"""Stage 4's version module. The implementation now lives in the platform.

Kept as a name because Stage 4 code and its tests import ``semver``; the rule
itself moved to ``tools/modplatform/semverlib.py`` so that Stage 4.5's service
versions and capability negotiation could not start a second, drifting copy.
Everything below is a re-export -- there is no second implementation to diverge.
"""
import os
import sys

_PLATFORM = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "modplatform")
if _PLATFORM not in sys.path:
    sys.path.insert(0, _PLATFORM)

from semverlib import (                                            # noqa: F401,E402
    OPERATORS, REQUIREMENT_PATTERN, VERSION_PATTERN, Requirement, Version,
    VersionError, parse_requirement, parse_version,
)
