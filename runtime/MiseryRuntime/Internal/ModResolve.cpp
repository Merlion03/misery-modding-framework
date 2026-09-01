// ModResolve.cpp -- from a set of manifests to a load plan.
//
// A port of tools/modframework/resolve.py. The only layer that compares mods.
//
// WHAT "FAIL CLOSED" MEANS HERE, PRECISELY
// ----------------------------------------
// Two mods declare the same mod_id. One appears first on disk. The tempting
// implementation keeps that one and warns about the other -- and it is wrong,
// because "first on disk" is not a decision anybody made. The user did not
// choose it, the authors did not choose it, and it changes when a folder is
// renamed. So a duplicate id removes BOTH claimants: an ambiguous identity is
// not resolved, it is refused. The same reasoning governs an explicit conflict,
// where "which of these two incompatible mods did the user actually want" is a
// question only the user can answer.
//
// EXCLUSION PROPAGATES
// --------------------
// A mod whose dependency was excluded cannot load either, and its dependents
// cannot, transitively. Every mod in load_order has every one of its required
// dependencies in load_order too, ahead of it. A plan listing a mod whose
// dependency had been dropped would be a plan that fails at execution time,
// which is the failure this stage exists to move earlier.
//
// DETERMINISM
// -----------
// Kahn's algorithm over a queue kept sorted by mod_id, so among mods equally
// ready to load the order is by id -- never disk order, never the order
// dependencies were typed into a manifest. Feed the same manifests in any order
// and the plan is identical; the differential test asserts exactly that by
// shuffling.
#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "ModPlan.h"

namespace misery {
namespace modplan {
namespace {

void Add(std::vector<Diagnostic>* out, const char* code,
         const std::string& subject, const std::string& detail) {
  Diagnostic d;
  d.code = code;
  d.subject = subject;
  d.detail = detail;
  out->push_back(d);
}

using Excluded = std::map<std::string, std::set<std::string>>;
using Accepted = std::map<std::string, Manifest>;

std::string CommaJoin(const std::vector<std::string>& items) {
  std::string out;
  for (size_t i = 0; i < items.size(); ++i) {
    out += (i ? ", " : "") + items[i];
  }
  return out;
}

std::vector<std::string> FatalCodes(const std::vector<Diagnostic>& diagnostics) {
  std::set<std::string> codes;
  for (const Diagnostic& d : diagnostics) {
    if (IsFatal(d.code)) {
      codes.insert(d.code);
    }
  }
  return std::vector<std::string>(codes.begin(), codes.end());
}

// Group accepted manifests by mod_id, refusing every duplicated id.
Accepted IndexById(const std::vector<Discovered>& discovered,
                   std::vector<Diagnostic>* out, Excluded* excluded) {
  std::map<std::string, std::vector<const Discovered*>> by_id;
  for (const Discovered& entry : discovered) {
    // Carry EVERY discovery-time diagnostic into the plan, accepted or not: a
    // plan that cannot say why a mod is missing is the untrustworthy artefact
    // this stage exists to avoid.
    for (const Diagnostic& d : entry.diagnostics) {
      out->push_back(d);
    }
    // Grouped by what the folder CLAIMED, not by what validated. Grouping by
    // validated manifests only meant a duplicate paired with any other failure
    // was never reported as a duplicate: the broken twin was filed under its
    // own id as "malformed", which then evicted the healthy owner of that id
    // through the shared exclusion map, under a code naming the wrong problem.
    if (!entry.declared_mod_id.empty()) {
      by_id[entry.declared_mod_id].push_back(&entry);
    } else {
      std::vector<std::string> codes = FatalCodes(entry.diagnostics);
      if (codes.empty()) {
        codes.push_back(kMalformedManifest);
      }
      (*excluded)[entry.Identity()].insert(codes.begin(), codes.end());
    }
  }

  Accepted accepted;
  for (const auto& pair : by_id) {
    const std::string& mod_id = pair.first;
    const std::vector<const Discovered*>& entries = pair.second;
    if (entries.size() > 1) {
      std::vector<std::string> folders;
      for (const Discovered* entry : entries) {
        folders.push_back(entry->folder);
      }
      std::sort(folders.begin(), folders.end());
      Add(out, kDuplicateModId, mod_id,
          "declared by " + std::to_string(entries.size()) + " folders (" +
              CommaJoin(folders) +
              "). mod_id is the authoritative identity, so this is one mod "
              "claiming to be two -- or two mods claiming one identity. EVERY "
              "claimant is refused: keeping whichever the filesystem returned "
              "first would make the outcome depend on folder order. This holds "
              "even when only one of them would otherwise have validated, "
              "because a folder that names an id has claimed it.");
      (*excluded)[mod_id].insert(kDuplicateModId);
      continue;
    }
    const Discovered* entry = entries[0];
    if (!entry->accepted) {
      std::vector<std::string> codes = FatalCodes(entry->diagnostics);
      if (codes.empty()) {
        codes.push_back(kMalformedManifest);
      }
      (*excluded)[mod_id].insert(codes.begin(), codes.end());
      continue;
    }
    accepted[mod_id] = entry->manifest;
  }
  return accepted;
}

void CheckDependencies(const Accepted& accepted, std::vector<Diagnostic>* out,
                       Excluded* excluded) {
  for (const auto& pair : accepted) {
    const std::string& mod_id = pair.first;
    const Manifest& manifest = pair.second;
    for (const Dependency& dependency : manifest.dependencies) {
      auto target = accepted.find(dependency.mod_id);
      const bool present = target != accepted.end();
      if (!present && excluded->count(dependency.mod_id)) {
        // Installed, but already refused. Telling the user their dependency is
        // "missing" would send them to download a mod they already have; the
        // useful answer names the refusal.
        const std::set<std::string>& why = (*excluded)[dependency.mod_id];
        Add(out, kDependencyExcluded, mod_id,
            "requires '" + dependency.mod_id + "' " +
                dependency.requirement.text +
                ", which IS installed but was itself refused (" +
                CommaJoin(std::vector<std::string>(why.begin(), why.end())) +
                ")");
        (*excluded)[mod_id].insert(kDependencyExcluded);
      } else if (!present) {
        Add(out, kMissingDependency, mod_id,
            "requires '" + dependency.mod_id + "' " +
                dependency.requirement.text +
                ", which is not present in the load set");
        (*excluded)[mod_id].insert(kMissingDependency);
      } else if (!dependency.requirement.Matches(target->second.version)) {
        Add(out, kIncompatibleDependencyVersion, mod_id,
            "requires '" + dependency.mod_id + "' " +
                dependency.requirement.text + " but the installed '" +
                dependency.mod_id + "' is " +
                target->second.version.ToString());
        (*excluded)[mod_id].insert(kIncompatibleDependencyVersion);
      }
    }
    for (const Dependency& dependency : manifest.optional_dependencies) {
      auto target = accepted.find(dependency.mod_id);
      if (target == accepted.end()) {
        // Absent optional dependency: informational, changes nothing.
        Add(out, kOptionalDependencyAbsent, mod_id,
            "optional dependency '" + dependency.mod_id + "' is not installed");
      } else if (!dependency.requirement.Matches(target->second.version)) {
        // PRESENT but incompatible is NOT optional. The author said "if this is
        // here, I need this version of it"; loading against a version they
        // excluded is worse than not loading at all.
        Add(out, kIncompatibleDependencyVersion, mod_id,
            "optional dependency '" + dependency.mod_id + "' is installed at " +
                target->second.version.ToString() + ", which its requirement " +
                dependency.requirement.text +
                " excludes. An optional dependency that is PRESENT is not "
                "optional -- the mod would run against a version it declared "
                "unusable.");
        (*excluded)[mod_id].insert(kIncompatibleDependencyVersion);
      }
    }
  }
}

void CheckConflicts(const Accepted& accepted, std::vector<Diagnostic>* out,
                    Excluded* excluded) {
  std::set<std::pair<std::string, std::string>> pairs;
  for (const auto& entry : accepted) {
    const std::string& mod_id = entry.first;
    for (const Conflict& conflict : entry.second.conflicts) {
      auto other = accepted.find(conflict.mod_id);
      if (other == accepted.end()) {
        continue;
      }
      // No requirement means every version conflicts.
      if (conflict.has_requirement &&
          !conflict.requirement.Matches(other->second.version)) {
        continue;
      }
      pairs.insert(mod_id < conflict.mod_id
                       ? std::make_pair(mod_id, conflict.mod_id)
                       : std::make_pair(conflict.mod_id, mod_id));
    }
  }
  for (const auto& pair : pairs) {
    const char* detail =
        "declared incompatible with '%s' (or vice versa). Both are refused: "
        "only the user can decide which of two mods that say they cannot "
        "coexist should be the one that loads.";
    std::string left = detail;
    left.replace(left.find("%s"), 2, pair.second);
    std::string right = detail;
    right.replace(right.find("%s"), 2, pair.first);
    Add(out, kExplicitConflict, pair.first, left);
    Add(out, kExplicitConflict, pair.second, right);
    (*excluded)[pair.first].insert(kExplicitConflict);
    (*excluded)[pair.second].insert(kExplicitConflict);
  }
}

// Tarjan's SCC, iterative and deterministic. Iterative because a deep
// dependency chain must not be bounded by a recursion limit.
std::vector<std::vector<std::string>> StronglyConnected(
    const std::set<std::string>& nodes,
    const std::map<std::string, std::vector<std::string>>& edges) {
  std::map<std::string, int> index;
  std::map<std::string, int> lowlink;
  std::map<std::string, bool> on_stack;
  std::vector<std::string> stack;
  std::vector<std::vector<std::string>> components;
  int next_index = 0;

  for (const std::string& root : nodes) {
    if (index.count(root)) {
      continue;
    }
    // (node, next child to visit)
    std::vector<std::pair<std::string, size_t>> work;
    work.push_back({root, 0});
    index[root] = lowlink[root] = next_index++;
    stack.push_back(root);
    on_stack[root] = true;

    while (!work.empty()) {
      const std::string node = work.back().first;
      size_t& cursor = work.back().second;
      auto found = edges.find(node);
      const std::vector<std::string> empty;
      const std::vector<std::string>& children =
          found == edges.end() ? empty : found->second;

      if (cursor < children.size()) {
        const std::string child = children[cursor++];
        if (!index.count(child)) {
          index[child] = lowlink[child] = next_index++;
          stack.push_back(child);
          on_stack[child] = true;
          work.push_back({child, 0});
        } else if (on_stack[child]) {
          lowlink[node] = (std::min)(lowlink[node], index[child]);
        }
        continue;
      }

      work.pop_back();
      if (!work.empty()) {
        const std::string& parent = work.back().first;
        lowlink[parent] = (std::min)(lowlink[parent], lowlink[node]);
      }
      if (lowlink[node] == index[node]) {
        std::vector<std::string> component;
        while (true) {
          const std::string member = stack.back();
          stack.pop_back();
          on_stack[member] = false;
          component.push_back(member);
          if (member == node) {
            break;
          }
        }
        std::sort(component.begin(), component.end());
        components.push_back(component);
      }
    }
  }
  std::sort(components.begin(), components.end());
  return components;
}

void CheckCycles(const Accepted& accepted, std::vector<Diagnostic>* out,
                 Excluded* excluded) {
  std::set<std::string> nodes;
  for (const auto& entry : accepted) {
    if (!excluded->count(entry.first)) {
      nodes.insert(entry.first);
    }
  }
  std::map<std::string, std::vector<std::string>> edges;
  for (const std::string& mod_id : nodes) {
    // Optional dependencies are edges too when the target is present: they
    // order the load, so they can close a cycle just as a required one can.
    std::set<std::string> targets;
    const Manifest& manifest = accepted.at(mod_id);
    for (const Dependency& d : manifest.dependencies) {
      if (nodes.count(d.mod_id)) targets.insert(d.mod_id);
    }
    for (const Dependency& d : manifest.optional_dependencies) {
      if (nodes.count(d.mod_id)) targets.insert(d.mod_id);
    }
    edges[mod_id] = std::vector<std::string>(targets.begin(), targets.end());
  }

  for (const std::vector<std::string>& component :
       StronglyConnected(nodes, edges)) {
    bool is_cycle = component.size() > 1;
    if (!is_cycle) {
      // A self-dependency is a one-node cycle, and Tarjan reports a lone node
      // as its own component whether or not it points at itself.
      auto found = edges.find(component[0]);
      if (found != edges.end()) {
        is_cycle = std::find(found->second.begin(), found->second.end(),
                             component[0]) != found->second.end();
      }
    }
    if (!is_cycle) {
      continue;
    }
    // The members, and the edges that ACTUALLY exist between them. Joining the
    // alphabetically sorted component with " -> " would name edges that do not
    // exist and send anyone debugging it to the wrong manifest.
    const std::set<std::string> members(component.begin(), component.end());
    std::vector<std::string> real_edges;
    for (const std::string& member : component) {
      auto found = edges.find(member);
      if (found == edges.end()) continue;
      for (const std::string& target : found->second) {
        if (members.count(target)) {
          real_edges.push_back(member + " -> " + target);
        }
      }
    }
    std::sort(real_edges.begin(), real_edges.end());
    for (const std::string& member : component) {
      Add(out, kDependencyCycle, member,
          "is part of a dependency cycle among {" + CommaJoin(component) +
              "}. The edges between them are: " +
              CommaJoin(real_edges) +
              ". No order satisfies 'dependencies load first' for any member, "
              "so every member is refused.");
      (*excluded)[member].insert(kDependencyCycle);
    }
  }
}

void PropagateExclusions(const Accepted& accepted, std::vector<Diagnostic>* out,
                         Excluded* excluded) {
  // Repeated to a fixed point: dropping a mod can drop its dependents, which
  // can drop theirs.
  while (true) {
    std::vector<std::pair<std::string, std::string>> newly;
    for (const auto& entry : accepted) {
      if (excluded->count(entry.first)) {
        continue;
      }
      for (const Dependency& dependency : entry.second.dependencies) {
        if (excluded->count(dependency.mod_id)) {
          newly.push_back({entry.first, dependency.mod_id});
          break;
        }
      }
    }
    if (newly.empty()) {
      return;
    }
    for (const auto& pair : newly) {
      Add(out, kDependencyExcluded, pair.first,
          "required dependency '" + pair.second +
              "' was itself refused, so this mod cannot load. Listing it would "
              "produce a plan that fails at execution time -- which is the "
              "failure this stage exists to move earlier.");
      (*excluded)[pair.first].insert(kDependencyExcluded);
    }
  }
}

// Kahn's algorithm with a deterministic ready set. Among mods equally ready,
// the tie-break is mod_id -- not folder name and not discovery order, so the
// plan cannot shift when a folder is renamed.
std::vector<std::string> TopologicalOrder(const Accepted& accepted,
                                          const Excluded& excluded) {
  std::vector<std::string> live;
  for (const auto& entry : accepted) {
    if (!excluded.count(entry.first)) {
      live.push_back(entry.first);
    }
  }
  const std::set<std::string> live_set(live.begin(), live.end());

  std::map<std::string, std::set<std::string>> prerequisites;
  std::map<std::string, std::vector<std::string>> dependents;
  for (const std::string& mod_id : live) {
    dependents[mod_id];
  }
  for (const std::string& mod_id : live) {
    std::set<std::string> needed;
    const Manifest& manifest = accepted.at(mod_id);
    for (const Dependency& d : manifest.dependencies) {
      if (live_set.count(d.mod_id)) needed.insert(d.mod_id);
    }
    for (const Dependency& d : manifest.optional_dependencies) {
      if (live_set.count(d.mod_id)) needed.insert(d.mod_id);
    }
    prerequisites[mod_id] = needed;
    for (const std::string& target : needed) {
      dependents[target].push_back(mod_id);
    }
  }

  std::vector<std::string> ready;
  for (const std::string& mod_id : live) {
    if (prerequisites[mod_id].empty()) {
      ready.push_back(mod_id);
    }
  }
  std::sort(ready.begin(), ready.end());

  std::vector<std::string> order;
  while (!ready.empty()) {
    const std::string mod_id = ready.front();
    ready.erase(ready.begin());
    order.push_back(mod_id);
    std::vector<std::string> waiting = dependents[mod_id];
    std::sort(waiting.begin(), waiting.end());
    for (const std::string& dependent : waiting) {
      prerequisites[dependent].erase(mod_id);
      if (prerequisites[dependent].empty()) {
        ready.push_back(dependent);
        std::sort(ready.begin(), ready.end());
      }
    }
  }
  // Anything left would be in a cycle, and cycles were already excluded. A
  // silent short plan is exactly the "partially accepted" outcome this stage
  // forbids, so the remainder is dropped loudly rather than returned.
  if (order.size() != live.size()) {
    order.clear();
  }
  return order;
}

}  // namespace

Plan Resolve(const std::vector<Discovered>& discovered) {
  Plan plan;
  Excluded excluded;

  Accepted accepted = IndexById(discovered, &plan.diagnostics, &excluded);
  CheckDependencies(accepted, &plan.diagnostics, &excluded);
  CheckConflicts(accepted, &plan.diagnostics, &excluded);
  CheckCycles(accepted, &plan.diagnostics, &excluded);
  PropagateExclusions(accepted, &plan.diagnostics, &excluded);

  plan.load_order = TopologicalOrder(accepted, excluded);
  plan.excluded = excluded;
  for (const std::string& mod_id : plan.load_order) {
    plan.manifests[mod_id] = accepted.at(mod_id);
  }
  return plan;
}

Plan PlanFromRoot(const std::string& mods_root) {
  return Resolve(Discover(mods_root));
}

}  // namespace modplan
}  // namespace misery
