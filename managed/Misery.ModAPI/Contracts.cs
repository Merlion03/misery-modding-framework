using System;
using System.Collections.Generic;

namespace Misery.ModAPI
{
    /// <summary>The public API version this assembly defines.</summary>
    public static class ModApi
    {
        /// <summary>The compatibility promise: a bump means mods must be rebuilt.</summary>
        public const int VersionMajor = 0;
        /// <summary>Additive changes; existing mods keep working.</summary>
        public const int VersionMinor = 5;
        /// <summary>Fixes with no contract change.</summary>
        public const int VersionPatch = 0;

        /// <summary>"0.5.0". Mirrors MB_API_* and capabilities.API_VERSION.</summary>
        public static string Version =>
            VersionMajor + "." + VersionMinor + "." + VersionPatch;
    }

    /// <summary>Capability names. One per independently versioned subsystem.</summary>
    /// <remarks>
    /// Constants rather than free strings so a typo is a compile error. A
    /// mistyped capability name that merely failed at runtime would take a mod
    /// author to the wrong conclusion -- "the framework does not have this" --
    /// about a framework that does.
    /// </remarks>
    public static class Capabilities
    {
        /// <summary>Per-mod structured logging.</summary>
        public const string Log = "core.log";
        /// <summary>Declare, subscribe to and publish namespaced events.</summary>
        public const string Events = "core.events";
        /// <summary>Declared, typed, persisted settings.</summary>
        public const string Settings = "core.settings";
        /// <summary>Declaring named input actions. Engine delivery is not wired.</summary>
        public const string InputRegistry = "core.input_registry";
        /// <summary>Publishing and consuming versioned inter-mod services.</summary>
        public const string Services = "core.services";
        /// <summary>Registering items under the mod's own namespace.</summary>
        public const string Items = "core.items";
        /// <summary>Contributing developer console commands.</summary>
        public const string Console = "core.console";
        /// <summary>Reading the platform's own diagnostic state.</summary>
        public const string Diagnostics = "core.diagnostics";
    }

    /// <summary>
    /// Declares what a mod needs, read by the host BEFORE the mod is
    /// constructed.
    /// </summary>
    /// <remarks>
    /// Read by reflection before instantiation on purpose: a mod whose required
    /// capabilities are unavailable must never run a line of its own code, so it
    /// never has to be torn back down from inside its own constructor.
    /// <para>
    /// Required means "absent, and this mod does not load" -- running it would
    /// be running something the author never tested. Optional means "absent, and
    /// this mod adapts", and the API makes adapting mandatory rather than
    /// optional: see <see cref="IModContext.TryGetInput"/> and friends.
    /// </para>
    /// </remarks>
    [AttributeUsage(AttributeTargets.Class, AllowMultiple = false, Inherited = false)]
    public sealed class ModCapabilitiesAttribute : Attribute
    {
        /// <param name="required">Absent means the mod does not load.</param>
        public ModCapabilitiesAttribute(params string[] required)
        {
            Required = required ?? Array.Empty<string>();
            Optional = Array.Empty<string>();
            FrameworkApi = "^" + ModApi.Version;
        }

        /// <summary>Capabilities without which this mod will not load.</summary>
        public string[] Required { get; }

        /// <summary>Capabilities this mod uses when present and adapts without.</summary>
        public string[] Optional { get; set; }

        /// <summary>The framework API this mod was built against, e.g. "^0.5.0".</summary>
        public string FrameworkApi { get; set; }
    }

    /// <summary>What every mod implements.</summary>
    /// <remarks>
    /// Two methods, and no others. <see cref="OnLoad"/> receives the context and
    /// is the only place a mod acquires anything; <see cref="OnUnload"/> is for
    /// a mod's own bookkeeping only -- everything the mod acquired through its
    /// context is released by the framework whether OnUnload runs, throws, or
    /// does nothing at all. A mod that forgets to clean up is not a leak.
    /// </remarks>
    public interface IMod
    {
        /// <summary>Called once, on the game thread, after capabilities are granted.</summary>
        void OnLoad(IModContext context);

        /// <summary>
        /// Called once before teardown. The context is still usable here, but
        /// nothing acquired during it will outlive the call.
        /// </summary>
        void OnUnload();
    }

    /// <summary>Per-mod structured logging.</summary>
    /// <remarks>
    /// A mod cannot name which mod a record came from: the framework stamps its
    /// id. Otherwise the first misbehaving mod could attribute its noise to
    /// somebody else and the "which mod is spamming" answer would be a lie.
    /// </remarks>
    public interface IModLog
    {
        /// <summary>Finest detail.</summary>
        void Trace(string message);
        /// <summary>Developer detail.</summary>
        void Debug(string message);
        /// <summary>Normal events.</summary>
        void Info(string message);
        /// <summary>Unexpected but survivable.</summary>
        void Warn(string message);
        /// <summary>Something failed.</summary>
        void Error(string message);

        /// <summary>Log with structured fields, which survive to the console.</summary>
        void Write(ModLogLevel level, string message,
                   IReadOnlyDictionary<string, object> fields);
    }

    /// <summary>Mirrors MB_LOG_* and modlog.py.</summary>
    public enum ModLogLevel
    {
        /// <summary>Finest detail; off in normal play.</summary>
        Trace = 0,
        /// <summary>Developer detail.</summary>
        Debug = 1,
        /// <summary>Normal, noteworthy events.</summary>
        Info = 2,
        /// <summary>Something unexpected that did not stop the mod.</summary>
        Warn = 3,
        /// <summary>Something failed.</summary>
        Error = 4
    }

    /// <summary>A resource owned by a mod, released when the mod unloads.</summary>
    /// <remarks>
    /// Disposing early is allowed and idempotent. NOT disposing is also fine:
    /// the framework releases everything a mod owns at unload regardless. This
    /// exists so a mod CAN release something early, not so it must.
    /// </remarks>
    public interface IModResource : IDisposable
    {
        /// <summary>False once released, by the mod or by teardown.</summary>
        bool IsAlive { get; }
    }

    /// <summary>Events the framework itself raises.</summary>
    /// <remarks>
    /// They live in the reserved <c>misery</c> namespace, which no mod may
    /// declare into, so these names cannot collide with a mod's own.
    /// A mod subscribes to them exactly as it subscribes to anything else.
    /// </remarks>
    public static class FrameworkEvents
    {
        /// <summary>
        /// A content generation is ready to be acted on.
        /// </summary>
        /// <remarks>
        /// Raised once per generation, AFTER that generation is published and
        /// after the framework has applied this mod's declarations to it. Until
        /// it arrives, a mod's items are declared but not present in any world,
        /// and operations that need a live world will refuse.
        ///
        /// This is the answer to a question a mod cannot answer for itself:
        /// <c>OnLoad</c> runs when the host starts, which is typically a main
        /// menu with no world at all.
        ///
        /// Raised AGAIN after every later transition, with a new generation, so
        /// a mod that must act per-world acts here rather than once at load.
        /// The payload is <c>{"generation":&lt;n&gt;,"phase":"&lt;phase&gt;"}</c>.
        /// </remarks>
        public const string ContentReady = "misery:content_ready";
    }

    /// <summary>Namespaced events. Platform lifecycle only in this version.</summary>
    /// <remarks>
    /// This framework ships no gameplay events, because the engine paths behind
    /// them have not been researched and an event that never fires is worse than
    /// an absent one -- a mod author builds on it and finds out later.
    /// </remarks>
    public interface IModEvents
    {
        /// <summary>Declare an event in this mod's own namespace.</summary>
        IModResource Declare(string name, string detail = null);

        /// <summary>Subscribe. The subscription is owned by this mod.</summary>
        IModResource Subscribe(string name, Action<ModEvent> handler);

        /// <summary>Raise an event this mod declared. Returns handlers run.</summary>
        int Publish(string name, string payloadJson = null);
    }

    /// <summary>One delivered event.</summary>
    public readonly struct ModEvent
    {
        /// <summary>Creates a delivered event.</summary>
        public ModEvent(string name, string payloadJson)
        {
            Name = name;
            PayloadJson = payloadJson;
        }

        /// <summary>The full "owner:name".</summary>
        public string Name { get; }

        /// <summary>
        /// The payload, as JSON. JSON rather than a generic type parameter
        /// because a strongly typed payload would have to be a type both the
        /// publisher's and the subscriber's assemblies agree on -- and with
        /// per-mod collectible load contexts, two mods holding "the same" type
        /// do not necessarily hold the same type at all.
        /// </summary>
        public string PayloadJson { get; }
    }

    /// <summary>A declared setting, typed at the call site.</summary>
    /// <remarks>
    /// The type parameter is what stops <c>GetInt</c> being called on a bool
    /// setting: the key carries its own type, so the wrong read does not
    /// compile. Only bool, int, double and string exist, because those are the
    /// four with one unambiguous representation in JSON on disk, in the C ABI
    /// and in C# alike.
    /// </remarks>
    public readonly struct SettingKey<T>
    {
        /// <summary>Creates a typed key. Validates the name.</summary>
        public SettingKey(string name)
        {
            string reason = ModId.ValidateLocalId(name);
            if (reason != null)
            {
                throw new ArgumentException(
                    "'" + name + "' is not a valid setting key: " + reason,
                    nameof(name));
            }

            Name = name;
        }

        /// <summary>The key's name.</summary>
        public string Name { get; }

        /// <inheritdoc />
        public override string ToString() => Name;
    }

    /// <summary>Declared, typed, persisted per-mod settings.</summary>
    public interface IModSettings
    {
        /// <summary>Declare this mod's settings. Once, at load.</summary>
        IModResource Declare(IEnumerable<SettingDeclaration> declarations);

        /// <summary>Read a declared setting. Undeclared keys throw.</summary>
        T Get<T>(SettingKey<T> key);

        /// <summary>Write a declared setting.</summary>
        void Set<T>(SettingKey<T> key, T value);

        /// <summary>Persist this mod's settings to disk.</summary>
        void Save();
    }

    /// <summary>One setting's schema.</summary>
    public sealed class SettingDeclaration
    {
        /// <summary>Declares one setting: its key, default and meaning.</summary>
        public SettingDeclaration(string key, object defaultValue, string description)
        {
            string reason = ModId.ValidateLocalId(key);
            if (reason != null)
            {
                throw new ArgumentException(
                    "'" + key + "' is not a valid setting key: " + reason,
                    nameof(key));
            }

            Key = key;
            DefaultValue = defaultValue ??
                throw new ArgumentNullException(
                    nameof(defaultValue),
                    "a setting with no default has no value before the user sets one");
            Description = description ?? string.Empty;
        }

        /// <summary>The setting's key, unique within the mod.</summary>
        public string Key { get; }

        /// <summary>Used until the user sets one; also fixes the type.</summary>
        public object DefaultValue { get; }

        /// <summary>Flavour and detail text.</summary>
        public string Description { get; }
    }

    /// <summary>Named input actions a mod declares.</summary>
    /// <remarks>
    /// Declaration and ownership only in this version. Nothing in the engine
    /// delivers these yet -- the engine input path is unresearched -- and
    /// <see cref="EngineInputWired"/> says so rather than leaving a mod author to
    /// discover the silence at runtime.
    /// </remarks>
    public interface IModInputActions
    {
        /// <summary>False in this version. Ask before relying on real key events.</summary>
        bool EngineInputWired { get; }

        /// <summary>Declare an action in this mod's namespace.</summary>
        IModResource Register(string name, string displayName,
                              string suggestedBinding = null,
                              Action<InputActionEvent> handler = null);
    }

    /// <summary>One input action firing.</summary>
    public readonly struct InputActionEvent
    {
        /// <summary>Creates an input action event.</summary>
        public InputActionEvent(string action, InputPhase phase)
        {
            Action = action;
            Phase = phase;
        }

        /// <summary>The full action name.</summary>
        public string Action { get; }

        /// <summary>Whether the action began or ended.</summary>
        public InputPhase Phase { get; }
    }

    /// <summary>Mirrors MB_INPUT_*.</summary>
    public enum InputPhase
    {
        /// <summary>The action began.</summary>
        Pressed = 1,
        /// <summary>The action ended.</summary>
        Released = 2
    }

    /// <summary>A service another mod published.</summary>
    /// <remarks>
    /// This is never the provider's object. Every call re-checks the provider's
    /// liveness, so the instant the provider unloads every outstanding handle
    /// stops working -- including one a consumer stored in a field. Handing over
    /// the real object would let a consumer root the provider's load context
    /// forever, and no amount of care elsewhere would fix it.
    /// </remarks>
    public interface IModService
    {
        /// <summary>The full "provider:name".</summary>
        string Name { get; }

        /// <summary>The provider's version.</summary>
        string Version { get; }

        /// <summary>False the instant the provider unloads.</summary>
        bool IsAvailable { get; }

        /// <summary>Call a method by name. Throws if the provider is gone.</summary>
        string Call(string method, string argumentsJson = null);
    }

    /// <summary>Publishing and consuming inter-mod services.</summary>
    public interface IModServices
    {
        /// <summary>Publish in this mod's namespace. Owned by this mod.</summary>
        IModResource Publish(string name, string version,
                             IReadOnlyDictionary<string, Func<string, string>> methods);

        /// <summary>Bind to another mod's service, refusing an incompatible version.</summary>
        IModService Bind(string name, string versionRequirement = ">=0.0.0");
    }

    /// <summary>Registering items under this mod's own namespace.</summary>
    public interface IModItems
    {
        /// <summary>
        /// Register one item. The row name is DERIVED from this mod's id and the
        /// declaration's local id; a mod cannot choose it, and therefore cannot
        /// collide with a vanilla row or another mod's.
        /// </summary>
        IModResource Register(ItemDeclaration declaration, out string rowName);

        /// <summary>
        /// Put an item this mod registered into the live player's inventory.
        /// </summary>
        /// <param name="item">The resource <see cref="Register"/> returned.</param>
        /// <param name="amount">How many to try to add. Must be positive.</param>
        /// <returns>How many the inventory actually took.</returns>
        /// <remarks>
        /// The item is identified by the resource, not by name, and that is the
        /// ownership rule rather than a check: a mod holds resources only for
        /// items it registered, so there is no way to express "grant a vanilla
        /// row" or "grant another mod's item".
        ///
        /// The return value is what the inventory took, which need not be what
        /// was asked. Weight, free slots and stack limits are the game's to
        /// enforce; asking for five when one fits adds one and says so.
        ///
        /// Requires a live world holding this mod's row. Between a world being
        /// torn down and the next one resolving there is nothing to add to, and
        /// the call fails rather than waiting.
        /// </remarks>
        int AddToPlayerInventory(IModResource item, int amount);
    }

    /// <summary>What a mod says about an item. No engine concepts.</summary>
    public sealed class ItemDeclaration
    {
        /// <summary>Creates an item declaration. Validates the local id.</summary>
        public ItemDeclaration(string localId, string displayName, string shortName,
                               string description, double weight,
                               string worldMesh, string inventoryIcon)
        {
            string reason = ModId.ValidateLocalId(localId);
            if (reason != null)
            {
                throw new ArgumentException(
                    "'" + localId + "' is not a valid local id: " + reason,
                    nameof(localId));
            }

            LocalId = localId;
            DisplayName = displayName;
            ShortName = shortName;
            Description = description;
            Weight = weight;
            WorldMesh = worldMesh;
            InventoryIcon = inventoryIcon;
            Width = 1;
            Height = 1;
        }

        /// <summary>The mod-local id; the row name is derived from it.</summary>
        public string LocalId { get; }

        /// <summary>Shown to the player.</summary>
        public string DisplayName { get; }

        /// <summary>A compact name for tight UI.</summary>
        public string ShortName { get; }

        /// <summary>Flavour and detail text.</summary>
        public string Description { get; }

        /// <summary>Item weight, in the game's units.</summary>
        public double Weight { get; }

        /// <summary>A Mod Kit package path, e.g. "/Game/Mods/&lt;id&gt;/Meshes/SM_X".</summary>
        public string WorldMesh { get; }

        /// <summary>A Mod Kit package path for the inventory icon.</summary>
        public string InventoryIcon { get; }

        /// <summary>Inventory grid width.</summary>
        public int Width { get; set; }

        /// <summary>Inventory grid height.</summary>
        public int Height { get; set; }

        /// <summary>
        /// Optional. A Blueprint class this mod ships, to be the item's
        /// representation in the world.
        /// </summary>
        /// <remarks>
        /// A Mod Kit package path with its class suffix, e.g.
        /// "/Game/Mods/&lt;id&gt;/BP_Thing.BP_Thing_C".
        ///
        /// Leave it null and the item uses the game's own world item actor with
        /// this declaration's mesh, which is what every item did before mods
        /// could ship a class. Set it and the item is your actor.
        ///
        /// The class MUST derive from the game's world item class. That is not
        /// a convention: the framework walks the ancestry of what it loads and
        /// refuses to register the item otherwise, because the value ends up in
        /// a row the game later constructs actors from, and an unrelated class
        /// there is the game building something nobody agreed to build.
        /// </remarks>
        public string WorldClass { get; set; }
    }

    /// <summary>What a mod actually got at load time.</summary>
    public interface ICapabilityGrant
    {
        /// <summary>The framework's API version.</summary>
        string ApiVersion { get; }

        /// <summary>True when the named capability was granted.</summary>
        bool Has(string capability);

        /// <summary>
        /// The granted version of a capability, so a mod that needs a newer
        /// feature can check rather than version-sniff the whole framework.
        /// </summary>
        string VersionOf(string capability);
    }

    /// <summary>
    /// One mod's entire view of the framework. Handed to it; never fetched.
    /// </summary>
    /// <remarks>
    /// <para>
    /// There is no <c>ModApi.Current</c> and no <c>GetContext(id)</c> anywhere in
    /// this assembly, deliberately. Every call a mod makes must be attributable
    /// to that mod and every resource it acquires must be owned by it, and a
    /// static entry point can guarantee neither -- anything a mod tells the
    /// framework about its own identity is something a buggy or hostile mod can
    /// get wrong.
    /// </para>
    /// <para>
    /// REQUIRED capabilities are plain properties, because the mod does not load
    /// without them. OPTIONAL ones are reachable ONLY through a Try method, so
    /// using a subsystem the mod did not require is a COMPILE error rather than
    /// a null reference at a player's machine. That asymmetry is the single most
    /// valuable safety property in this API.
    /// </para>
    /// </remarks>
    public interface IModContext
    {
        /// <summary>This mod's identity. The framework's, not the mod's, word.</summary>
        ModId Id { get; }

        /// <summary>Always available; every mod may log.</summary>
        IModLog Log { get; }

        /// <summary>What was granted at load.</summary>
        ICapabilityGrant Grant { get; }

        /// <summary>False once the mod has been unloaded.</summary>
        bool IsAlive { get; }

        /// <summary>Requires <see cref="Capabilities.Events"/>.</summary>
        IModEvents Events { get; }

        /// <summary>Requires <see cref="Capabilities.Settings"/>.</summary>
        IModSettings Settings { get; }

        /// <summary>Requires <see cref="Capabilities.Items"/>.</summary>
        IModItems Items { get; }

        /// <summary>
        /// Optional. Returns false when <see cref="Capabilities.InputRegistry"/>
        /// was not granted, so a mod cannot use it without handling its absence.
        /// </summary>
        bool TryGetInput(out IModInputActions input);

        /// <summary>Optional. See <see cref="TryGetInput"/>.</summary>
        bool TryGetServices(out IModServices services);
    }
}
