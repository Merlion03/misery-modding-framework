// ConsoleBackend.h -- the seam the console UI reaches the command engine through.
//
// The UI is a FRONTEND CLIENT, and this is the whole of its access: run a line,
// list the names. It does not have a registry, a dispatcher, a builtin, or an
// envelope format of its own, and there is deliberately nothing here that would
// let it acquire one. Every command the UI runs goes through the same code path
// MbConsoleTable::run exposes -- the same ownership checks, the same
// re-resolution of a mod handle immediately before the call, the same envelope.
//
// WHY NOT JUST CALL MbConsoleTable::run
// -------------------------------------
// Because it answers through the per-thread reply arena, which exists to hand a
// pointer across the ABI to a caller who will copy it before the next call. The
// UI is in-process C++ and wants a std::string; borrowing the ABI's arena to
// talk to ourselves would put the UI's reply lifetime in the same bucket as a
// mod's, so that a long console reply could evict something a mod was still
// holding. Same engine, different door.
#ifndef MISERY_CONSOLEBACKEND_H
#define MISERY_CONSOLEBACKEND_H

#include <string>
#include <vector>

namespace misery {
namespace console_backend {

struct RunResult {
  // False only when the CONSOLE could not run -- the wrong thread. An unknown
  // command, an empty line and a handler that faulted are all `ran == true`
  // with the failure described inside the envelope, exactly as the reference's
  // run() contract requires and as MbConsoleTable::run reports it.
  bool ran = false;
  std::string envelope;   // JSON
  std::string refusal;    // why it could not run, when ran == false
};

RunResult Run(const std::string& line);

// Every registered command name, sorted: the builtins plus whatever mods have
// registered right now. The completion source, and nothing more -- the registry
// does not describe arguments, so the UI cannot complete them.
std::vector<std::string> CommandNames();

}  // namespace console_backend
}  // namespace misery

#endif  // MISERY_CONSOLEBACKEND_H
