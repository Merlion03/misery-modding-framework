/* MiseryBridge.h -- the stable semantic native bridge.
 *
 * MISERY -> MiseryRuntime (C++) -> THIS -> Misery.ModAPI (C#) -> third-party mods
 *
 * WHAT THIS FILE IS FOR
 * ---------------------
 * It is the only thing the managed side is allowed to know about the native
 * side. Everything above it is C# a mod author reads; everything below it is
 * build-specific reverse-engineered detail that must never be visible to one.
 * There is deliberately no UObject, no FName, no ProcessEvent and no address
 * anywhere in this header: a mod that could name one would be a mod that breaks
 * when MISERY is patched.
 *
 * WHY A FROZEN ROOT PLUS VERSIONED TABLES
 * ---------------------------------------
 * The root struct never changes. Not "rarely" -- never. Its size and field
 * order are the one thing both sides must agree on before they can agree on
 * anything else, so it holds four integers and three function pointers and
 * nothing that could ever need extending.
 *
 * Everything else is reached through MbRoot::acquire_capability, which hands
 * back a table for a named capability at a requested MAJOR. Each table carries
 * its own struct_size and version. That is what lets the items table reach v3
 * while the log table is still v1, and it is why adding a subsystem is a MINOR
 * bump rather than an ABI break. A single flat vtable would make every addition
 * a renumbering.
 *
 * NOTHING AGGREGATE CROSSES BY VALUE IN THE ROOT
 * ----------------------------------------------
 * The root's own functions take only scalars -- pointer and length, never a
 * struct. Passing a 16-byte struct by value is implemented differently by
 * different ABIs and compilers (hidden pointer on win-x64, register pair
 * elsewhere), and while every current toolchain agrees, the root is the one
 * thing that can never be fixed if one ever does not. Capability tables may use
 * MbStr freely: a table CAN be revised, so it is allowed to take the risk the
 * root is not.
 *
 * NO FUNCTION POINTER INTO MOD CODE EVER CROSSES INTO NATIVE
 * ----------------------------------------------------------
 * This is the single most important rule here, and it is what makes the
 * lifecycle guarantee structural rather than diligent.
 *
 * The obvious design is for each subscription to pass a callback pointer. It is
 * also the design that makes a managed host unable to unload a mod: a native
 * table holding a pointer into a collectible AssemblyLoadContext roots that
 * context forever, so ALC.Unload() never completes and the mod's memory is
 * never reclaimed -- no matter how carefully everything else was released.
 *
 * So callbacks go the other way. The managed HOST registers exactly ONE
 * trampoline, once, at process start (MbHostTable::set_trampoline), whose
 * lifetime is the process and which lives in the DEFAULT load context. Every
 * dispatch calls that one trampoline with the SUBSCRIPTION HANDLE; the managed
 * side looks the handle up in its own table and finds the mod's delegate there.
 * Native therefore holds handles -- integers -- and never an address inside mod
 * code. Unloading a mod becomes an integer invalidation on the native side and
 * a dictionary removal on the managed side, and nothing anywhere holds the ALC
 * alive.
 *
 * EXCEPTIONS NEVER CROSS
 * ----------------------
 * Every function returns MbStatus and takes an out-parameter for its result. A
 * managed exception crossing this boundary would unwind through C++ frames not
 * compiled to expect it; a C++ exception reaching the CLR is no better. Both
 * sides catch at the edge and translate to MbError, which carries the same
 * (subsystem, code, detail, mod_id) that the Python reference implementation
 * and the C# ModException carry. A test compares all three.
 *
 * STRING AND POINTER OWNERSHIP -- ONE RULE, NO EXCEPTIONS
 * -------------------------------------------------------
 *   IN  parameters: borrowed for the duration of the call. The callee must copy
 *                   anything it keeps; the caller may free immediately after.
 *   OUT parameters: owned by the BRIDGE, valid until the next bridge call on
 *                   the same thread. The caller must copy before calling again.
 *
 * The second rule is deliberately strict. "Valid until you release it" needs a
 * release function per type and a discipline nobody keeps; "valid until your
 * next call" needs neither, and the managed side marshals to a string
 * immediately anyway.
 *
 * THREADING
 * ---------
 * Every function must be called on the game thread and returns
 * MB_E_WRONG_THREAD otherwise. The engine state behind these calls has
 * game-thread affinity and has been proven only there. There is deliberately no
 * async surface in this epoch -- see DELIBERATELY ABSENT at the end.
 */
#ifndef MISERY_BRIDGE_H
#define MISERY_BRIDGE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The frozen root layout. Bump only for a change that cannot be expressed as a
 * new capability table -- which, by construction, should be never. */
#define MB_ABI_EPOCH 1u

/* The public API version. MAJOR is the promise that mods must be rebuilt.
 * Mirrored by capabilities.API_VERSION (Python) and ModApi.Version (C#). */
#define MB_API_MAJOR 0u
#define MB_API_MINOR 5u
#define MB_API_PATCH 0u

/* ---- primitives ------------------------------------------------------- */

/* Opaque, and deliberately NOT an address.
 *
 *      kind:8 | slot:24 | tag:32          0 is always invalid
 *
 * The tag is drawn at allocation and never reused for a slot, so a stale handle
 * is DETECTED rather than dereferenced -- there is no ABA window in which an old
 * handle silently addresses a new object. A slot whose tag space is exhausted is
 * retired permanently rather than recycled.
 *
 * MOD slots are never recycled at all: a mod id, once loaded, owns its slot for
 * the process lifetime. That makes mod identity stable for diagnostics across an
 * unload/reload cycle and removes mod-handle ABA entirely, at a cost of a few
 * bytes per mod ever loaded. */
typedef uint64_t MbHandle;
#define MB_INVALID_HANDLE ((MbHandle)0)

#define MB_HANDLE_KIND(h) ((uint8_t)((h) >> 56))
#define MB_HANDLE_SLOT(h) ((uint32_t)(((h) >> 32) & 0xFFFFFFu))
#define MB_HANDLE_TAG(h)  ((uint32_t)((h) & 0xFFFFFFFFu))

/* UTF-8, explicitly counted, never NUL-terminated by contract: a length is
 * cheaper to validate than a scan, and it makes a read past the end impossible
 * rather than merely unlikely. Used in capability tables, never in MbRoot. */
typedef struct MbStr {
    const char* data;
    int32_t     length;
} MbStr;

typedef int32_t MbStatus;
#define MB_OK ((MbStatus)0)

/* ---- structured errors ------------------------------------------------ */
/* These integers are shared with tools/modplatform/errors.py and with
 * Misery.ModAPI's ModSubsystem enum. A test asserts all three agree. */

typedef enum MbSubsystem {
    MB_SUB_PLATFORM     = 1,
    MB_SUB_LIFECYCLE    = 2,
    MB_SUB_LOG          = 3,
    MB_SUB_EVENTS       = 4,
    MB_SUB_SETTINGS     = 5,
    MB_SUB_INPUT        = 6,
    MB_SUB_SERVICES     = 7,
    MB_SUB_ITEMS        = 8,
    MB_SUB_CAPABILITIES = 9,
    MB_SUB_CONSOLE      = 10
} MbSubsystem;

/* Generic codes, valid inside every subsystem's space. 0 is reserved for
 * success, so a raw pair can never read a failure as an OK. */
#define MB_E_INVALID_ARGUMENT        10
#define MB_E_NOT_FOUND               11
#define MB_E_ALREADY_EXISTS          12
#define MB_E_NOT_OWNED               13
#define MB_E_WRONG_THREAD            14
#define MB_E_CAPABILITY_NOT_GRANTED  15
#define MB_E_LIMIT_EXCEEDED          16
#define MB_E_HANDLER_FAULTED         17

/* Platform-subsystem codes. Mirrors errors.E_* in the Python reference; these
 * were missing from a first draft of this header, which is exactly the drift
 * the three-way contract test exists to catch. */
#define MB_E_NOT_INITIALISED         1
#define MB_E_ALREADY_INITIALISED     2
#define MB_E_SHUTTING_DOWN           3

/* Lifecycle-specific codes. */
#define MB_E_UNKNOWN_MOD             1
#define MB_E_MOD_ALREADY_LOADED      2
#define MB_E_MOD_NOT_LOADED          3
#define MB_E_OWNER_DISPOSED          4
#define MB_E_LOAD_FAILED             5
#define MB_E_REENTRANT_UNLOAD        6

typedef struct MbError {
    int32_t subsystem;   /* MbSubsystem */
    int32_t code;
    MbStr   detail;      /* bridge-owned, valid until the next call */
    MbStr   mod_id;      /* empty when not attributable to a mod */
} MbError;

/* ---- mod state -------------------------------------------------------- */

typedef enum MbModState {
    MB_MODSTATE_DISCOVERED = 0,
    MB_MODSTATE_LOADING    = 1,
    MB_MODSTATE_LOADED     = 2,
    MB_MODSTATE_UNLOADING  = 3,
    MB_MODSTATE_UNLOADED   = 4,
    MB_MODSTATE_FAILED     = 5,
    /* Unloaded, but something it owned could not be released, so a managed host
     * must NOT collect its assembly context. Named here because Stage 5 needs a
     * vocabulary for "the ALC will not unload", and discovering that it has none
     * is exactly the kind of gap that forces a redesign. */
    MB_MODSTATE_LEAKED     = 6
} MbModState;

/* ---- log levels (mirror modlog.py) ------------------------------------ */
#define MB_LOG_TRACE 0
#define MB_LOG_DEBUG 1
#define MB_LOG_INFO  2
#define MB_LOG_WARN  3
#define MB_LOG_ERROR 4

/* ---- setting types (mirror settings.py TYPE_CODES) -------------------- */
#define MB_SETTING_BOOL   1
#define MB_SETTING_INT    2
#define MB_SETTING_FLOAT  3
#define MB_SETTING_STRING 4

/* ---- input phases (mirror input_actions.py) --------------------------- */
#define MB_INPUT_PRESSED  1
#define MB_INPUT_RELEASED 2

/* ---- dispatch kinds, for the single trampoline ------------------------ */
#define MB_DISPATCH_EVENT   1
#define MB_DISPATCH_INPUT   2
#define MB_DISPATCH_COMMAND 3

/* THE ONE managed entry point native ever holds. Registered once, at process
 * start, by the managed host -- never per mod and never per subscription. It
 * lives in the default load context, so it does not root any mod's collectible
 * context. Native calls it with a subscription HANDLE; the managed side resolves
 * that to a delegate in its own table. See the header comment.
 *
 *   kind         MB_DISPATCH_*
 *   subscription the handle returned when the mod subscribed
 *   a, b         kind-dependent payloads (JSON, action name, argument line)
 *   phase        MB_INPUT_* for MB_DISPATCH_INPUT, otherwise 0 */
typedef void (*MbTrampoline)(int32_t kind, MbHandle subscription,
                             MbStr a, MbStr b, int32_t phase);

/* ---- capability tables ------------------------------------------------ */
/* Every table begins with these three fields, in this order. A caller given a
 * table it only partly understands can still read its size and version and
 * refuse, rather than calling off the end of a struct it assumed was longer. */
#define MB_TABLE_HEADER   \
    uint32_t struct_size; \
    uint32_t version_major; \
    uint32_t version_minor

#define MB_CAP_LOG            "core.log"
#define MB_CAP_EVENTS         "core.events"
#define MB_CAP_SETTINGS       "core.settings"
#define MB_CAP_INPUT_REGISTRY "core.input_registry"
#define MB_CAP_SERVICES       "core.services"
#define MB_CAP_ITEMS          "core.items"
#define MB_CAP_CONSOLE        "core.console"
#define MB_CAP_DIAGNOSTICS    "core.diagnostics"
/* Host-only. acquire_capability refuses this to any owner that is not the host
 * handle minted by MiseryBridgeAcquire, so a mod cannot begin or end another
 * mod's lifetime -- or its own. */
#define MB_CAP_HOST           "core.host"

typedef struct MbLogTable {
    MB_TABLE_HEADER;
    MbStatus (*write)(MbHandle mod, int32_t level, MbStr message,
                      MbStr fields_json, MbError* out_error);
} MbLogTable;

typedef struct MbEventsTable {
    MB_TABLE_HEADER;
    MbStatus (*declare)(MbHandle mod, MbStr name, MbStr detail,
                        MbHandle* out_declaration, MbError* out_error);
    /* No callback parameter: dispatch reaches the mod through the host
     * trampoline, carrying out_subscription. */
    MbStatus (*subscribe)(MbHandle mod, MbStr name,
                          MbHandle* out_subscription, MbError* out_error);
    MbStatus (*unsubscribe)(MbHandle subscription, MbError* out_error);
    MbStatus (*publish)(MbHandle mod, MbStr name, MbStr payload_json,
                        int32_t* out_handlers_run, MbError* out_error);
} MbEventsTable;

typedef struct MbSettingsTable {
    MB_TABLE_HEADER;
    MbStatus (*declare)(MbHandle mod, MbStr schema_json, MbError* out_error);
    MbStatus (*get_bool)(MbHandle mod, MbStr key, int32_t* out_value,
                         MbError* out_error);
    MbStatus (*get_int)(MbHandle mod, MbStr key, int64_t* out_value,
                        MbError* out_error);
    MbStatus (*get_float)(MbHandle mod, MbStr key, double* out_value,
                          MbError* out_error);
    MbStatus (*get_string)(MbHandle mod, MbStr key, MbStr* out_value,
                           MbError* out_error);
    MbStatus (*set_bool)(MbHandle mod, MbStr key, int32_t value,
                         MbError* out_error);
    MbStatus (*set_int)(MbHandle mod, MbStr key, int64_t value,
                        MbError* out_error);
    MbStatus (*set_float)(MbHandle mod, MbStr key, double value,
                          MbError* out_error);
    MbStatus (*set_string)(MbHandle mod, MbStr key, MbStr value,
                           MbError* out_error);
    MbStatus (*save)(MbHandle mod, MbError* out_error);
} MbSettingsTable;

typedef struct MbInputTable {
    MB_TABLE_HEADER;
    MbStatus (*register_action)(MbHandle mod, MbStr name, MbStr display_name,
                                MbStr suggested_binding, MbHandle* out_action,
                                MbError* out_error);
    MbStatus (*unregister_action)(MbHandle action, MbError* out_error);
    /* Whether anything in the engine actually delivers these yet. Reported
     * rather than assumed, because in this epoch it is 0: the engine input path
     * is unresearched, and a mod needing real key events must be able to ask
     * rather than discover the silence at runtime. */
    MbStatus (*engine_input_wired)(int32_t* out_wired, MbError* out_error);
} MbInputTable;

typedef struct MbServicesTable {
    MB_TABLE_HEADER;
    /* Methods are named in JSON and invoked by name. No delegate crosses, for
     * the reason in the header comment, and no managed Type crosses either --
     * which also makes services immune to cross-ALC type identity problems. */
    MbStatus (*publish)(MbHandle mod, MbStr name, MbStr version,
                        MbStr method_names_json, MbHandle* out_service,
                        MbError* out_error);
    MbStatus (*bind)(MbHandle mod, MbStr name, MbStr requirement,
                     MbHandle* out_binding, MbError* out_error);
    MbStatus (*is_available)(MbHandle binding, int32_t* out_available,
                             MbError* out_error);
    MbStatus (*call)(MbHandle binding, MbStr method, MbStr args_json,
                     MbStr* out_result_json, MbError* out_error);
    MbStatus (*release)(MbHandle binding, MbError* out_error);
} MbServicesTable;

typedef struct MbItemsTable {
    MB_TABLE_HEADER;
    /* Semantic JSON -- local_id, display name, weight, and the package paths the
     * Mod Kit derived. No row name, because the row name is DERIVED from the
     * mod's identity and a mod may not choose it. */
    MbStatus (*register_item)(MbHandle mod, MbStr declaration_json,
                              MbStr* out_row_name, MbHandle* out_item,
                              MbError* out_error);
    MbStatus (*unregister_item)(MbHandle item, MbError* out_error);
} MbItemsTable;

typedef struct MbConsoleTable {
    MB_TABLE_HEADER;
    MbStatus (*register_command)(MbHandle mod, MbStr name, MbStr summary,
                                 MbHandle* out_command, MbError* out_error);
    MbStatus (*unregister_command)(MbHandle command, MbError* out_error);
    MbStatus (*run)(MbStr line, MbStr* out_result_json, MbError* out_error);
} MbConsoleTable;

typedef struct MbDiagnosticsTable {
    MB_TABLE_HEADER;
    MbStatus (*snapshot_json)(MbStr* out_json, MbError* out_error);
    MbStatus (*mod_state)(MbStr mod_id, int32_t* out_state, MbError* out_error);
    /* The predicate a managed host MUST gate AssemblyLoadContext.Unload() on.
     * True only when the mod is unloaded, everything it owned was released, and
     * no live subscription still refers to its code. Exposed here rather than
     * left for Stage 5 to reconstruct, because reconstructing it would mean the
     * managed host reimplementing the ownership model. */
    MbStatus (*mod_is_reclaimable)(MbStr mod_id, int32_t* out_reclaimable,
                                   MbStr* out_reason_json, MbError* out_error);
} MbDiagnosticsTable;

/* ---- the host table: for a MANAGED HOST, not for a mod ---------------- */
/* Reached only through MB_CAP_HOST, which acquire_capability refuses to any
 * owner that is not the host handle. Stage 5's CoreCLR host talks to this and
 * nothing else. */
typedef struct MbHostTable {
    MB_TABLE_HEADER;
    /* Once, at process start. See MbTrampoline. */
    MbStatus (*set_trampoline)(MbTrampoline trampoline, MbError* out_error);
    /* Capability negotiation happens HERE -- before a byte of mod code is
     * loaded, so a mod whose required capabilities are unavailable never
     * initialises at all and never has to be torn back down from inside its own
     * code path. */
    MbStatus (*mod_begin)(MbStr mod_id, MbStr api_requirement,
                          MbStr required_caps_json, MbStr optional_caps_json,
                          MbHandle* out_mod, MbStr* out_grant_json,
                          MbError* out_error);
    MbStatus (*mod_loaded)(MbHandle mod, MbError* out_error);
    MbStatus (*mod_failed)(MbHandle mod, MbStr reason, MbError* out_error);
    /* out_teardown_json carries {released:[], faults:[], revoked_callbacks:N,
     * resources_total:N} -- the evidence Stage 5 needs to decide whether the
     * unload was clean enough to collect the context. */
    MbStatus (*mod_unload)(MbHandle mod, MbStr* out_teardown_json,
                           MbError* out_error);
    MbStatus (*shutdown)(MbStr* out_report_json, MbError* out_error);
} MbHostTable;

/* ---- the frozen root -------------------------------------------------- */
/* 32 bytes on a 64-bit target: four uint32 and three pointers -- wait, that is
 * 40. It is 40, and the number that matters is that it is FIXED and asserted
 * below, not that it is any particular value. Do not add to it; anything that
 * feels like it belongs here belongs in a capability table.
 *
 * Note every function takes name/length as separate scalars: no aggregate
 * crosses by value in the root. */
typedef struct MbRoot {
    uint32_t struct_size;
    uint32_t abi_epoch;
    uint32_t api_major;
    uint32_t api_minor;
    /* Is a capability available, and at what version? Answering without
     * acquiring lets a host report the whole picture before committing to
     * anything. */
    MbStatus (*query_capability)(const char* name, int32_t name_len,
                                 uint32_t* out_major, uint32_t* out_minor);
    /* Acquire a table by name at a MAJOR you understand. Returns
     * MB_E_CAPABILITY_NOT_GRANTED when the platform lacks it, has it at an
     * incompatible MAJOR, or when *owner* is not entitled to it (MB_CAP_HOST).
     * The caller checks struct_size before touching any field past the header. */
    MbStatus (*acquire_capability)(MbHandle owner, const char* name,
                                   int32_t name_len, uint32_t want_major,
                                   const void** out_table, MbError* out_error);
    /* The last error on the calling thread, for the rare path that could not
     * take an out-parameter. Never the primary mechanism. */
    MbStatus (*last_error)(MbError* out_error);
} MbRoot;

/* The single exported symbol. One symbol means one thing to keep stable, and
 * one thing for a loader to fail on cleanly if it is missing.
 *
 * out_host receives the host handle: the only handle MB_CAP_HOST is granted to.
 * It is minted here, in-process, by the runtime at the moment it loads the
 * bootstrap -- there is no discovery path and nothing on disk a mod could read
 * to obtain one. */
#if defined(_WIN32)
#  define MB_EXPORT __declspec(dllexport)
#else
#  define MB_EXPORT __attribute__((visibility("default")))
#endif

MB_EXPORT MbStatus MiseryBridgeAcquire(uint32_t abi_epoch,
                                       const MbRoot** out_root,
                                       MbHandle* out_host, MbError* out_error);

typedef MbStatus (*MbAcquireFn)(uint32_t, const MbRoot**, MbHandle*, MbError*);
#define MB_ACQUIRE_SYMBOL "MiseryBridgeAcquire"

/* Both sides must agree on the root's size, and a mismatch must be a build
 * error rather than a runtime mystery. */
#define MB_ROOT_EXPECTED_SIZE 40u

/* ---- DELIBERATELY ABSENT FROM THIS EPOCH ------------------------------
 *
 * No async, Task, promise or completion port. What happens to an in-flight
 * continuation when its mod is unloaded is bound up with how the managed host
 * builds its AssemblyLoadContext, which is Stage 5's decision. Committing to an
 * async contract before that is answered would be committing to the part
 * hardest to change afterwards.
 *
 * No gameplay surface. No player, world, inventory, damage or tick events. The
 * engine paths behind those have not been researched, and a table advertising
 * them would have to either lie or later be removed.
 *
 * No engine input delivery. MbInputTable registers actions and says plainly,
 * through engine_input_wired, that nothing feeds them yet.
 *
 * Each is addable as a NEW capability table without touching MbRoot, which is
 * the entire reason MbRoot looks the way it does.
 */

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* MISERY_BRIDGE_H */
