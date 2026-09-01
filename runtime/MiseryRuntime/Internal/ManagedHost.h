// ManagedHost.h -- starting CoreCLR and the managed host from the installation.
//
// The last Python dependency on the Stage 5A path was three strings: where
// nethost is, where the managed host assembly is, and which mods to load. This
// supplies them from the installed framework directory instead. Nothing about
// the hosting itself changed.
#pragma once

#include <string>
#include <vector>

#include "../Public/MiseryBridge.h"

namespace misery {
namespace managed {

using LogFn = void (*)(const char* line);

// "modId=assembly;modId=assembly". Placeholder discovery -- see the .cpp. Step 4
// replaces this with the Stage 4 load plan.
// Start CoreCLR and hand the managed host the bridge root. Runs the bootstrap
// ON THE GAME THREAD, because that is the thread the managed side will record
// and check every later call against.
//
// Returns false with a reason. "No mods installed" is one of those reasons and
// is not a defect: an installation with nothing to load should not pay for a
// runtime it will not use.
bool Start(const std::string& framework_dir, const MbRoot* root,
           MbHandle host_handle, LogFn log, std::string* error);

}  // namespace managed
}  // namespace misery
