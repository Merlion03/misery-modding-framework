#include "ContentGeneration.h"

#include <string.h>
#include <windows.h>

#include <mutex>
#include <vector>

namespace misery {
namespace content {
namespace {

// Guarded because Acquire is called from consumers and Publish/Revoke from the
// runtime, and although both currently run on the game thread, "currently" is
// not a property to build a safety rule on.
std::mutex g_mutex;

uint64_t g_generation = 0;          // monotonic; 0 means nothing published
uint64_t g_objects_ptr = 0;
resolve::Layout g_layout;
resolve::Anchors g_anchors;
std::vector<resolve::AnchorIdentity> g_identities;
bool g_published = false;
std::string g_revoke_reason = "nothing has been published yet";
uint32_t g_publish_count = 0;
uint32_t g_revoke_count = 0;

void RevokeLocked(const std::string& why) {
  if (g_published) {
    ++g_revoke_count;
  }
  g_published = false;
  g_revoke_reason = why;
  // The anchors are cleared, not merely flagged. A flag can be forgotten; an
  // empty set cannot be dereferenced by mistake.
  g_anchors = resolve::Anchors();
  g_identities.clear();
}

}  // namespace

uint64_t Publish(uint64_t objects_ptr, const resolve::Layout& layout,
                 const resolve::Anchors& anchors) {
  std::lock_guard<std::mutex> lock(g_mutex);
  g_objects_ptr = objects_ptr;
  g_layout = layout;
  g_anchors = anchors;
  g_identities = anchors.identities;
  g_published = true;
  g_revoke_reason.clear();
  ++g_generation;
  ++g_publish_count;
  return g_generation;
}

bool Acquire(Snapshot* out, std::string* why) {
  std::lock_guard<std::mutex> lock(g_mutex);
  if (!g_published) {
    if (why != nullptr) {
      *why = g_revoke_reason.empty() ? "no content generation is published"
                                     : g_revoke_reason;
    }
    return false;
  }

  // EVERY anchor, EVERY time. This is the whole mechanism: a consumer cannot
  // hold a pointer from a dead generation because it is never handed one, and
  // that does not depend on anybody having noticed the load.
  for (const resolve::AnchorIdentity& identity : g_identities) {
    const resolve::Liveness state =
        resolve::CheckSlotIdentity(g_objects_ptr, g_layout, identity);
    if (state != resolve::Liveness::kAlive) {
      const std::string reason =
          "generation " + std::to_string(g_generation) + " is revoked: '" +
          identity.label + "' " + resolve::LivenessName(state);
      RevokeLocked(reason);
      if (why != nullptr) {
        *why = reason;
      }
      return false;
    }
  }

  out->generation = g_generation;
  out->anchors = g_anchors;
  return true;
}

void Revoke(const char* why) {
  std::lock_guard<std::mutex> lock(g_mutex);
  RevokeLocked(why != nullptr ? why : "revoked by the runtime");
}

uint64_t CurrentGeneration() {
  std::lock_guard<std::mutex> lock(g_mutex);
  return g_published ? g_generation : 0;
}

bool IsPublished() {
  std::lock_guard<std::mutex> lock(g_mutex);
  return g_published;
}

const char* LastRevokeReason() {
  std::lock_guard<std::mutex> lock(g_mutex);
  return g_revoke_reason.c_str();
}

uint32_t PublishCount() {
  std::lock_guard<std::mutex> lock(g_mutex);
  return g_publish_count;
}

uint32_t RevokeCount() {
  std::lock_guard<std::mutex> lock(g_mutex);
  return g_revoke_count;
}

}  // namespace content
}  // namespace misery
