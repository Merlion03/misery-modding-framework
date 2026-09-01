// ModDiscovery.h -- which mods are installed, and what to load for each.
#pragma once

#include <string>
#include <vector>

namespace misery {
namespace managed {

// Builds the managed host's load plan from *framework_dir*.
//
// Returns "id=path;id=path" -- empty when nothing is installed. *found*
// receives the mod ids planned; *skipped* receives a human sentence per
// directory that claimed to be a mod and was refused. Neither may be null.
std::string DiscoverPlan(const std::string& framework_dir,
                         std::vector<std::string>* found,
                         std::vector<std::string>* skipped);

}  // namespace managed
}  // namespace misery
