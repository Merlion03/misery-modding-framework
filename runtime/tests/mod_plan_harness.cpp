// mod_plan_harness.cpp -- the C++ load plan, as JSON, for one directory.
//
// Exists so tests/test_mod_plan.py can run Stage 4's Python planner and this
// port over the SAME mod trees and require the same answer. That differential
// is the only thing that makes "a port, not a fork" a checkable claim rather
// than an intention.
//
// Prints {"load_order": [...], "excluded": {id: [codes]}, "ok": bool}. Nothing
// else, so a mismatch is a diff and not an exercise in reading two formats.
#include <stdio.h>

#include <string>
#include <vector>

#include "../MiseryRuntime/Internal/ModPlan.h"

namespace {

std::string Escape(const std::string& text) {
  std::string out;
  for (char c : text) {
    if (c == '"' || c == '\\') {
      out += '\\';
      out += c;
    } else if (c == '\n') {
      out += "\\n";
    } else {
      out += c;
    }
  }
  return out;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: mod_plan_harness <mods-directory>\n");
    return 2;
  }
  const misery::modplan::Plan plan = misery::modplan::Resolve(
      misery::modplan::Discover(argv[1]));

  printf("{\"load_order\":[");
  for (size_t i = 0; i < plan.load_order.size(); ++i) {
    printf("%s\"%s\"", i ? "," : "", Escape(plan.load_order[i]).c_str());
  }
  printf("],\"excluded\":{");
  bool first = true;
  for (const auto& entry : plan.excluded) {
    printf("%s\"%s\":[", first ? "" : ",", Escape(entry.first).c_str());
    first = false;
    bool inner = true;
    for (const std::string& code : entry.second) {
      printf("%s\"%s\"", inner ? "" : ",", Escape(code).c_str());
      inner = false;
    }
    printf("]");
  }
  printf("},\"ok\":%s}\n", plan.ok() ? "true" : "false");
  return 0;
}
