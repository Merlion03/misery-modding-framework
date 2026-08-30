using System;

namespace Misery.ModAPI
{
    /// <summary>
    /// Which part of the framework produced an error. Values mirror
    /// <c>MbSubsystem</c> in MiseryBridge.h and <c>errors.SUB_*</c> in the
    /// Python reference implementation; a test compares all three.
    /// </summary>
    /// <remarks>
    /// Split from the code rather than flattened into one enum so that a
    /// subsystem owns its own code space and can add an error without
    /// renumbering anybody else's.
    /// </remarks>
    public enum ModSubsystem
    {
        /// <summary>The platform itself: initialisation and shutdown.</summary>
        Platform = 1,
        /// <summary>Mod load, unload, ownership and teardown.</summary>
        Lifecycle = 2,
        /// <summary>Per-mod logging.</summary>
        Log = 3,
        /// <summary>The event bus.</summary>
        Events = 4,
        /// <summary>Declared, typed, persisted settings.</summary>
        Settings = 5,
        /// <summary>The input action registry.</summary>
        Input = 6,
        /// <summary>Inter-mod services.</summary>
        Services = 7,
        /// <summary>Item registration.</summary>
        Items = 8,
        /// <summary>API version and capability negotiation.</summary>
        Capabilities = 9,
        /// <summary>The developer console.</summary>
        Console = 10
    }

    /// <summary>
    /// Error codes valid inside every subsystem's space. Zero is reserved for
    /// success, so a raw pair can never read a failure as an OK.
    /// </summary>
    public static class ModErrorCode
    {
        /// <summary>No error. Never a real failure code.</summary>
        public const int Ok = 0;

        /// <summary>The caller supplied something the subsystem cannot use.</summary>
        public const int InvalidArgument = 10;
        /// <summary>The named thing does not exist.</summary>
        public const int NotFound = 11;
        /// <summary>The named thing exists and would have been overwritten.</summary>
        public const int AlreadyExists = 12;
        /// <summary>The caller does not own the resource it named.</summary>
        public const int NotOwned = 13;
        /// <summary>Called off the game thread, where the engine state is not valid.</summary>
        public const int WrongThread = 14;
        /// <summary>The mod did not request this capability at load.</summary>
        public const int CapabilityNotGranted = 15;
        /// <summary>A per-mod quota would have been exceeded.</summary>
        public const int LimitExceeded = 16;
        /// <summary>A mod's callback threw; the framework contained it.</summary>
        public const int HandlerFaulted = 17;

        // Lifecycle-specific.
        /// <summary>No such mod is known to the host.</summary>
        public const int UnknownMod = 1;
        /// <summary>The mod is already loaded.</summary>
        public const int ModAlreadyLoaded = 2;
        /// <summary>The mod is not in a state that can be unloaded.</summary>
        public const int ModNotLoaded = 3;
        /// <summary>The mod's context has been torn down.</summary>
        public const int OwnerDisposed = 4;
        /// <summary>The mod's own code raised during load.</summary>
        public const int LoadFailed = 5;
        /// <summary>Unload was re-entered, e.g. a mod unloading itself.</summary>
        public const int ReentrantUnload = 6;
    }

    /// <summary>
    /// What a mod author catches. Carries the same structured data that crosses
    /// the native boundary as <c>MbError</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An exception never crosses the ABI in either direction -- the binding
    /// layer translates at the edge. This type is how the data becomes idiomatic
    /// once it is safely on the managed side.
    /// </para>
    /// <para>
    /// Failures are exceptions rather than ignorable result codes deliberately.
    /// A result code a mod author forgets to check produces a mod that is
    /// silently half-working; an exception they forget to catch produces a mod
    /// that fails loudly and gets fixed. A loud failure is the better default
    /// for code somebody else will ship to players.
    /// </para>
    /// </remarks>
    public sealed class ModException : Exception
    {
        /// <summary>Creates a structured error.</summary>
        public ModException(ModSubsystem subsystem, int code, string detail,
                            ModId modId = default)
            : base(Describe(subsystem, code, detail, modId))
        {
            Subsystem = subsystem;
            Code = code;
            Detail = detail;
            ModId = modId;
        }

        /// <summary>Which subsystem refused.</summary>
        public ModSubsystem Subsystem { get; }

        /// <summary>The code within that subsystem's space.</summary>
        public int Code { get; }

        /// <summary>Human-readable specifics. Never the thing to branch on.</summary>
        public string Detail { get; }

        /// <summary>The mod the error is attributed to, if any.</summary>
        public ModId ModId { get; }

        /// <summary>True when this is the given subsystem and code.</summary>
        public bool Is(ModSubsystem subsystem, int code) =>
            Subsystem == subsystem && Code == code;

        private static string Describe(ModSubsystem subsystem, int code,
                                       string detail, ModId modId)
        {
            string who = modId.IsValid ? " [" + modId + "]" : string.Empty;
            return subsystem + "." + code + who + ": " + detail;
        }
    }
}
