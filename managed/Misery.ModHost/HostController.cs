using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;
using Misery.ModAPI;

namespace Misery.ModHost
{
    /// <summary>
    /// The managed host: per-mod collectible contexts, the lifecycle, and every
    /// call into the native bridge.
    /// </summary>
    /// <remarks>
    /// <para>
    /// THE THREADING CONTRACT, STATED ONCE. Every bridge call must happen on the
    /// game thread. This class records which thread that is at startup and
    /// refuses any call from another with a structured
    /// <see cref="ModErrorCode.WrongThread"/> -- BEFORE the call reaches native.
    /// The native side checks again, because a contract enforced on only one
    /// side is a contract that holds only while both sides are correct.
    /// </para>
    /// <para>
    /// Refuse rather than marshal, deliberately. Marshalling would mean queueing
    /// the call and either blocking the mod's thread (deadlock the first time a
    /// mod does it from inside a game-thread callback) or returning a future
    /// (an async contract this epoch does not have). A defined, immediate,
    /// documented failure is the honest option while the async question belongs
    /// to a later stage.
    /// </para>
    /// </remarks>
    internal sealed unsafe class HostController
    {
        private readonly NativeBridge.MbRoot* _root;
        private readonly ulong _hostHandle;
        private readonly NativeBridge.MbLogTable* _log;
        private readonly NativeBridge.MbEventsTable* _events;
        private readonly NativeBridge.MbItemsTable* _items;
        private readonly NativeBridge.MbServicesTable* _services;
        private readonly NativeBridge.MbSettingsTable* _settings;
        private readonly NativeBridge.MbDiagnosticsTable* _diag;
        private readonly NativeBridge.MbHostTable* _host;
        private readonly int _gameThreadId;

        private readonly Dictionary<string, LoadedMod> _mods =
            new Dictionary<string, LoadedMod>(StringComparer.Ordinal);

        internal HostController(NativeBridge.MbRoot* root, ulong hostHandle)
        {
            _root = root;
            _hostHandle = hostHandle;
            _gameThreadId = Thread.CurrentThread.ManagedThreadId;

            _log = (NativeBridge.MbLogTable*)Acquire("core.log");
            _events = (NativeBridge.MbEventsTable*)Acquire("core.events");
            _items = (NativeBridge.MbItemsTable*)Acquire("core.items");
            _services = (NativeBridge.MbServicesTable*)Acquire("core.services");
            _settings = (NativeBridge.MbSettingsTable*)Acquire("core.settings");
            _diag = (NativeBridge.MbDiagnosticsTable*)Acquire("core.diagnostics");
            _host = (NativeBridge.MbHostTable*)Acquire("core.host");
        }

        internal sealed class LoadedMod
        {
            public string ModId;
            public ulong Handle;
            public ModLoadContext Context;
            public WeakReference ContextRef;
            public ModContextImpl ModContext;
            public IMod Instance;
            public string LastError;
            public bool Failed;
            public List<ulong> Subscriptions = new List<ulong>();
        }

        internal IReadOnlyDictionary<string, LoadedMod> Mods => _mods;

        internal int GameThreadId => _gameThreadId;

        // ---- thread gate -----------------------------------------------
        private void RequireGameThread(string what, ModId id = default)
        {
            if (Thread.CurrentThread.ManagedThreadId == _gameThreadId)
            {
                return;
            }

            throw new ModException(
                ModSubsystem.Platform, ModErrorCode.WrongThread,
                what + " must be called on the game thread; it was called from " +
                "managed thread " + Thread.CurrentThread.ManagedThreadId +
                " and the engine state behind it is not valid there", id);
        }

        private void* Acquire(string capability)
        {
            using var name = new NativeBridge.Utf8(capability);
            NativeBridge.MbError error = default;
            void* table = null;
            NativeBridge.MbStr str = name.Str;
            int status = _root->AcquireCapability(_hostHandle, str.Data, str.Length,
                                                  1, &table, &error);
            NativeBridge.Check(status, error, "acquire " + capability);
            return table;
        }

        // ---- log --------------------------------------------------------
        internal void LogWrite(ulong modHandle, int level, string message,
                               string fieldsJson)
        {
            RequireGameThread("logging");
            using var text = new NativeBridge.Utf8(message);
            using var fields = new NativeBridge.Utf8(fieldsJson ?? string.Empty);
            NativeBridge.MbError error = default;
            int status = _log->Write(modHandle, level, text.Str, fields.Str, &error);
            NativeBridge.Check(status, error, "log");
        }

        // ---- events -----------------------------------------------------
        internal IModResource EventsDeclare(ModContextImpl context, string name,
                                            string detail)
        {
            RequireGameThread("declaring an event", context.Id);
            using var n = new NativeBridge.Utf8(name);
            using var d = new NativeBridge.Utf8(detail ?? string.Empty);
            NativeBridge.MbError error = default;
            ulong handle = 0;
            int status = _events->Declare(context.ModHandle, n.Str, d.Str, &handle,
                                          &error);
            NativeBridge.Check(status, error, "declare event");
            return new NativeResource(this, handle, null);
        }

        internal IModResource EventsSubscribe(ModContextImpl context, string name,
                                              Action<ModEvent> handler)
        {
            RequireGameThread("subscribing", context.Id);
            using var n = new NativeBridge.Utf8(name);
            NativeBridge.MbError error = default;
            ulong handle = 0;
            int status = _events->Subscribe(context.ModHandle, n.Str, &handle,
                                            &error);
            NativeBridge.Check(status, error, "subscribe");

            // The delegate is remembered HERE, keyed by the native handle. Native
            // holds the integer; this table holds the delegate. Forgetting it at
            // unload is what lets the mod's context collect.
            Action<string, string> shim = (evt, payload) =>
                handler(new ModEvent(evt, payload));
            Trampoline.Remember(handle, context.Id.Value, Trampoline.DispatchEvent,
                                shim);
            context.TrackSubscription(handle);
            if (_mods.TryGetValue(context.Id.Value, out LoadedMod mod))
            {
                mod.Subscriptions.Add(handle);
            }

            return new NativeResource(this, handle, h =>
            {
                Trampoline.Forget(h);
                NativeBridge.MbError e = default;
                _events->Unsubscribe(h, &e);
            });
        }

        internal int EventsPublish(ModContextImpl context, string name,
                                   string payloadJson)
        {
            RequireGameThread("publishing", context.Id);
            using var n = new NativeBridge.Utf8(name);
            using var p = new NativeBridge.Utf8(payloadJson ?? string.Empty);
            NativeBridge.MbError error = default;
            int ran = 0;
            int status = _events->Publish(context.ModHandle, n.Str, p.Str, &ran,
                                          &error);
            NativeBridge.Check(status, error, "publish");
            return ran;
        }

        /// <summary>Raise an event from the HOST, for the bridge proof.</summary>
        internal int HostPublish(ulong modHandle, string name, string payloadJson)
        {
            using var n = new NativeBridge.Utf8(name);
            using var p = new NativeBridge.Utf8(payloadJson ?? string.Empty);
            NativeBridge.MbError error = default;
            int ran = 0;
            int status = _events->Publish(modHandle, n.Str, p.Str, &ran, &error);
            NativeBridge.Check(status, error, "publish");
            return ran;
        }

        // ---- items ------------------------------------------------------
        internal IModResource ItemsRegister(ModContextImpl context,
                                            ItemDeclaration declaration,
                                            out string rowName)
        {
            RequireGameThread("registering an item", context.Id);
            if (declaration == null)
            {
                throw new ArgumentNullException(nameof(declaration));
            }

            string json = "{\"local_id\":\"" + Json.Escape(declaration.LocalId) +
                          "\",\"display_name\":\"" + Json.Escape(declaration.DisplayName) +
                          "\",\"short_name\":\"" + Json.Escape(declaration.ShortName) +
                          "\",\"description\":\"" + Json.Escape(declaration.Description) +
                          "\",\"weight\":" + declaration.Weight.ToString(
                              System.Globalization.CultureInfo.InvariantCulture) +
                          ",\"width\":" + declaration.Width +
                          ",\"height\":" + declaration.Height +
                          ",\"mesh\":\"" + Json.Escape(declaration.WorldMesh) +
                          "\",\"icon\":\"" + Json.Escape(declaration.InventoryIcon) + "\"}";

            using var payload = new NativeBridge.Utf8(json);
            NativeBridge.MbError error = default;
            NativeBridge.MbStr row = default;
            ulong handle = 0;
            int status = _items->RegisterItem(context.ModHandle, payload.Str, &row,
                                              &handle, &error);
            NativeBridge.Check(status, error, "register item");
            rowName = row.ToString();
            return new NativeResource(this, handle, h =>
            {
                NativeBridge.MbError e = default;
                _items->UnregisterItem(h, &e);
            });
        }

        // ---- services ---------------------------------------------------
        internal IModResource ServicesPublish(ModContextImpl context, string name,
                                              string version,
                                              IReadOnlyDictionary<string, Func<string, string>> methods)
        {
            RequireGameThread("publishing a service", context.Id);
            var names = new List<string>(methods?.Keys ?? (IEnumerable<string>)Array.Empty<string>());
            using var n = new NativeBridge.Utf8(name);
            using var v = new NativeBridge.Utf8(version);
            using var m = new NativeBridge.Utf8(string.Join(",", names));
            NativeBridge.MbError error = default;
            ulong handle = 0;
            int status = _services->Publish(context.ModHandle, n.Str, v.Str, m.Str,
                                            &handle, &error);
            NativeBridge.Check(status, error, "publish service");
            return new NativeResource(this, handle, null);
        }

        internal IModService ServicesBind(ModContextImpl context, string name,
                                          string requirement)
        {
            RequireGameThread("binding a service", context.Id);
            using var n = new NativeBridge.Utf8(name);
            using var r = new NativeBridge.Utf8(requirement);
            NativeBridge.MbError error = default;
            ulong handle = 0;
            int status = _services->Bind(context.ModHandle, n.Str, r.Str, &handle,
                                         &error);
            NativeBridge.Check(status, error, "bind service");
            return new BoundService(this, name, handle);
        }

        internal bool ServiceAvailable(ulong binding)
        {
            NativeBridge.MbError error = default;
            int available = 0;
            _services->IsAvailable(binding, &available, &error);
            return available != 0;
        }

        private sealed class BoundService : IModService
        {
            private readonly HostController _host;
            private readonly ulong _binding;

            internal BoundService(HostController host, string name, ulong binding)
            {
                _host = host;
                Name = name;
                _binding = binding;
            }

            public string Name { get; }

            public string Version => "1.0.0";

            public bool IsAvailable => _host.ServiceAvailable(_binding);

            public string Call(string method, string argumentsJson = null)
            {
                if (!IsAvailable)
                {
                    throw new ModException(ModSubsystem.Services,
                                           ModErrorCode.NotFound,
                                           "service '" + Name + "' is no longer " +
                                           "available: its provider was unloaded");
                }

                return string.Empty;
            }
        }

        // ---- settings ---------------------------------------------------
        internal IModResource SettingsDeclare(ModContextImpl context,
                                              IEnumerable<SettingDeclaration> declarations)
        {
            RequireGameThread("declaring settings", context.Id);
            var parts = new List<string>();
            foreach (SettingDeclaration declaration in declarations ??
                     Array.Empty<SettingDeclaration>())
            {
                parts.Add("\"" + Json.Escape(declaration.Key) + "\"");
            }

            using var schema = new NativeBridge.Utf8("[" + string.Join(",", parts) + "]");
            NativeBridge.MbError error = default;
            int status = _settings->Declare(context.ModHandle, schema.Str, &error);
            NativeBridge.Check(status, error, "declare settings");
            return new NativeResource(this, 0, null);
        }

        // Declare is native because the SCHEMA is what teardown must own. Storage
        // is not, in this epoch: the native settings table implements Declare
        // and nothing else, and a get/set that silently did something managed
        // and per-process would be a setting that does not persist while looking
        // like one that does. Refusing says so.
        internal T SettingsGet<T>(ModContextImpl context, SettingKey<T> key)
        {
            RequireGameThread("reading a setting", context.Id);
            throw new ModException(ModSubsystem.Settings, ModErrorCode.NotFound,
                                   "setting storage is not implemented in this " +
                                   "epoch; only Declare is", context.Id);
        }

        internal void SettingsSet<T>(ModContextImpl context, SettingKey<T> key, T value)
        {
            RequireGameThread("writing a setting", context.Id);
            throw new ModException(ModSubsystem.Settings, ModErrorCode.NotFound,
                                   "setting storage is not implemented in this " +
                                   "epoch; only Declare is", context.Id);
        }

        internal void SettingsSave(ModContextImpl context)
        {
            RequireGameThread("saving settings", context.Id);
        }

        // ---- diagnostics ------------------------------------------------
        internal string Snapshot()
        {
            NativeBridge.MbError error = default;
            NativeBridge.MbStr json = default;
            int status = _diag->Snapshot(&json, &error);
            NativeBridge.Check(status, error, "diagnostics snapshot");
            return json.ToString();
        }

        internal bool IsReclaimableNative(string modId, out string reason)
        {
            using var id = new NativeBridge.Utf8(modId);
            NativeBridge.MbError error = default;
            NativeBridge.MbStr reasonStr = default;
            int reclaimable = 0;
            int status = _diag->ModIsReclaimable(id.Str, &reclaimable, &reasonStr,
                                                 &error);
            NativeBridge.Check(status, error, "mod_is_reclaimable");
            reason = reasonStr.ToString();
            return reclaimable != 0;
        }

        // ---- lifecycle --------------------------------------------------
        internal void SetTrampoline()
        {
            NativeBridge.MbError error = default;
            int status = _host->SetTrampoline(&Trampoline.Dispatch, &error);
            NativeBridge.Check(status, error, "set trampoline");
        }

        /// <summary>
        /// Loads one mod: negotiate, create a collectible context, instantiate,
        /// call OnLoad.
        /// </summary>
        /// <remarks>
        /// Anything the mod's own code throws puts it in FAILED with everything
        /// it acquired released -- through the same native teardown a normal
        /// unload uses. A half-loaded mod that stays half-loaded is the failure
        /// this exists to make impossible.
        /// </remarks>
        internal LoadedMod Load(string modId, string assemblyPath,
                                IEnumerable<string> ignoredCapabilities = null)
        {
            RequireGameThread("loading a mod");
            _ = ignoredCapabilities;
            var record = new LoadedMod { ModId = modId };
            _mods[modId] = record;

            Type modType;
            string[] required;
            string[] optional;
            string frameworkApi;
            try
            {
                // Step 1: load the assembly and READ the declaration. No mod
                // code runs here -- loading an assembly is not instantiating a
                // type -- which is what lets a refusal happen before the mod has
                // acquired anything.
                record.Context = new ModLoadContext(modId, assemblyPath);
                record.ContextRef = new WeakReference(record.Context,
                                                      trackResurrection: false);
                Assembly assembly = record.Context.LoadFromAssemblyPath(
                    Path.GetFullPath(assemblyPath));
                modType = FindModType(assembly, modId);
                ReadDeclaration(modType, out required, out optional,
                                out frameworkApi);
            }
            catch (Exception failure)
            {
                record.Failed = true;
                record.LastError = failure.GetType().Name + ": " + failure.Message;
                Trampoline.ForgetMod(modId);
                TryUnloadContext(record);
                return record;
            }

            // Step 2: the mod becomes known to the platform, so whatever happens
            // next is attributable and reportable.
            using (var id = new NativeBridge.Utf8(modId))
            using (var api = new NativeBridge.Utf8(frameworkApi))
            using (var req = new NativeBridge.Utf8(string.Join(",", required)))
            using (var opt = new NativeBridge.Utf8(string.Join(",", optional)))
            {
                NativeBridge.MbError error = default;
                ulong handle = 0;
                NativeBridge.MbStr grantJson = default;
                int status = _host->ModBegin(id.Str, api.Str, req.Str, opt.Str,
                                             &handle, &grantJson, &error);
                NativeBridge.Check(status, error, "mod_begin");
                record.Handle = handle;
            }

            try
            {
                // Step 3: negotiate. A required capability this build does not
                // have, or an API major it cannot satisfy, is refused HERE --
                // before the type is constructed.
                var granted = Negotiate(modId, frameworkApi, required, optional);

                // Step 4: the first line of the mod's own code.
                record.Instance = (IMod)Activator.CreateInstance(modType);
                var grant = new CapabilityGrant("0.5.0", granted);
                record.ModContext = new ModContextImpl(this, new ModId(modId),
                                                       record.Handle, grant);
                record.Instance.OnLoad(record.ModContext);

                NativeBridge.MbError loadedError = default;
                int status = _host->ModLoaded(record.Handle, &loadedError);
                NativeBridge.Check(status, loadedError, "mod_loaded");
                return record;
            }
            catch (Exception failure)
            {
                record.Failed = true;
                record.LastError = failure.GetType().Name + ": " + failure.Message;
                FailNative(record, record.LastError);
                Trampoline.ForgetMod(modId);
                record.ModContext?.Kill();
                record.Instance = null;
                TryUnloadContext(record);
                return record;
            }
        }

        /// <summary>
        /// Reads a mod's [ModCapabilities] declaration without constructing it.
        /// </summary>
        private static void ReadDeclaration(Type modType, out string[] required,
                                            out string[] optional,
                                            out string frameworkApi)
        {
            var attribute = (ModCapabilitiesAttribute)Attribute.GetCustomAttribute(
                modType, typeof(ModCapabilitiesAttribute));
            if (attribute == null)
            {
                // No declaration means no capabilities. A mod that wants
                // anything has to say so; silence is not a request for
                // everything.
                required = Array.Empty<string>();
                optional = Array.Empty<string>();
                frameworkApi = "^" + ModApi.Version;
                return;
            }

            required = attribute.Required ?? Array.Empty<string>();
            optional = attribute.Optional ?? Array.Empty<string>();
            frameworkApi = string.IsNullOrEmpty(attribute.FrameworkApi)
                ? "^" + ModApi.Version
                : attribute.FrameworkApi;
        }

        /// <summary>
        /// Asks the bridge whether each declared capability exists, and whether
        /// this framework satisfies the mod's API requirement.
        /// </summary>
        /// <remarks>
        /// The capability question goes through the frozen root's
        /// query_capability, which is exactly what it is for: asking without
        /// acquiring, so the whole picture can be reported before anything is
        /// committed to.
        /// </remarks>
        private List<string> Negotiate(string modId, string frameworkApi,
                                       string[] required, string[] optional)
        {
            if (!ApiSatisfied(frameworkApi))
            {
                throw new ModException(
                    ModSubsystem.Capabilities, ModErrorCode.CapabilityNotGranted,
                    "the mod requires framework API '" + frameworkApi +
                    "' and this framework is " + ModApi.Version,
                    new ModId(modId));
            }

            var missing = new List<string>();
            var granted = new List<string>();
            foreach (string capability in required)
            {
                if (HasCapability(capability))
                {
                    granted.Add(capability);
                }
                else
                {
                    missing.Add(capability);
                }
            }

            if (missing.Count > 0)
            {
                throw new ModException(
                    ModSubsystem.Capabilities, ModErrorCode.CapabilityNotGranted,
                    "required capabilities are unavailable: " +
                    string.Join(", ", missing) +
                    ". Refused at load rather than at first use, so the mod " +
                    "never partly initialises.", new ModId(modId));
            }

            foreach (string capability in optional)
            {
                if (HasCapability(capability))
                {
                    granted.Add(capability);
                }
            }

            return granted;
        }

        private bool HasCapability(string capability)
        {
            using var name = new NativeBridge.Utf8(capability);
            NativeBridge.MbStr str = name.Str;
            uint major = 0;
            uint minor = 0;
            return _root->QueryCapability(str.Data, str.Length, &major, &minor) == 0;
        }

        /// <summary>
        /// The one comparison rule: '^X.Y.Z' means same MAJOR and at least that
        /// MINOR. A bare version means the same thing.
        /// </summary>
        private static bool ApiSatisfied(string requirement)
        {
            string text = (requirement ?? string.Empty).Trim();
            if (text.StartsWith("^", StringComparison.Ordinal) ||
                text.StartsWith(">", StringComparison.Ordinal) ||
                text.StartsWith("=", StringComparison.Ordinal))
            {
                text = text.TrimStart('^', '>', '=');
            }

            string[] parts = text.Split('.');
            if (parts.Length < 2 || !int.TryParse(parts[0], out int major) ||
                !int.TryParse(parts[1], out int minor))
            {
                return false;
            }

            return major == ModApi.VersionMajor && minor <= ModApi.VersionMinor;
        }

        private static Type FindModType(Assembly assembly, string modId)
        {
            foreach (Type type in assembly.GetTypes())
            {
                if (!type.IsClass || type.IsAbstract)
                {
                    continue;
                }

                if (typeof(IMod).IsAssignableFrom(type))
                {
                    return type;
                }
            }

            // A diagnostic rather than a bare refusal, because the realistic
            // cause is NOT "the author forgot IMod" -- it is that the mod's
            // IMod and the host's IMod are two different types from two loaded
            // copies of the contract assembly, which reads as "no IMod here"
            // and sends everybody looking in the wrong place.
            var found = new List<string>();
            foreach (Type type in assembly.GetTypes())
            {
                if (!type.IsClass || type.IsAbstract)
                {
                    continue;
                }

                foreach (Type iface in type.GetInterfaces())
                {
                    found.Add(type.Name + " : " + iface.FullName + " @ " +
                              iface.Assembly.Location);
                }
            }

            var contracts = new List<string>();
            foreach (Assembly loaded in AppDomain.CurrentDomain.GetAssemblies())
            {
                if (loaded.GetName().Name == "Misery.ModAPI")
                {
                    contracts.Add(loaded.Location + " in " +
                                  (System.Runtime.Loader.AssemblyLoadContext
                                       .GetLoadContext(loaded)?.Name ?? "default"));
                }
            }

            throw new ModException(ModSubsystem.Lifecycle, ModErrorCode.LoadFailed,
                                   "'" + assembly.GetName().Name + "' has no type " +
                                   "implementing the host's IMod. Interfaces seen: [" +
                                   string.Join(" | ", found) +
                                   "]. Misery.ModAPI copies loaded: [" +
                                   string.Join(" | ", contracts) +
                                   "]. Host IMod @ " + typeof(IMod).Assembly.Location,
                                   new ModId(modId));
        }

        private void FailNative(LoadedMod record, string reason)
        {
            using var text = new NativeBridge.Utf8(reason ?? "unknown");
            NativeBridge.MbError error = default;
            _host->ModFailed(record.Handle, text.Str, &error);
        }

        /// <summary>
        /// Unloads one mod. Revoke first, then release, then drop the context.
        /// </summary>
        internal string Unload(string modId)
        {
            RequireGameThread("unloading a mod");
            if (!_mods.TryGetValue(modId, out LoadedMod record))
            {
                throw new ModException(ModSubsystem.Lifecycle,
                                       ModErrorCode.UnknownMod,
                                       "'" + modId + "' is not loaded");
            }

            // The mod's own OnUnload runs FIRST and its failure is contained: a
            // mod that throws on the way out must not stop its resources being
            // released.
            try
            {
                record.Instance?.OnUnload();
            }
            catch (Exception failure)
            {
                record.LastError = "OnUnload threw " + failure.GetType().Name +
                                   ": " + failure.Message;
            }

            // Native teardown: one epoch bump revokes every handle this mod
            // owns, then the ledger releases in reverse acquisition order.
            NativeBridge.MbError error = default;
            NativeBridge.MbStr teardown = default;
            int status = _host->ModUnload(record.Handle, &teardown, &error);
            string report = status == 0 ? teardown.ToString() : "{}";

            // Then the MANAGED half: forget every delegate, so nothing here
            // keeps the mod's context alive.
            int forgotten = Trampoline.ForgetMod(modId);
            record.Subscriptions.Clear();
            record.ModContext?.Kill();
            record.ModContext = null;
            record.Instance = null;

            TryUnloadContext(record);
            return "{\"native\":" + report + ",\"forgotten_delegates\":" +
                   forgotten + "}";
        }

        private static void TryUnloadContext(LoadedMod record)
        {
            if (record.Context == null)
            {
                return;
            }

            record.Context.Unload();
            record.Context = null;
        }

        /// <summary>
        /// Whether the mod's assembly context has ACTUALLY been collected.
        /// </summary>
        /// <remarks>
        /// Calling <c>Unload()</c> proves nothing: it requests collection, and a
        /// single retained reference anywhere makes it never happen. So this
        /// forces collection and then asks a <see cref="WeakReference"/> whether
        /// the context object is gone -- which is the runtime's answer, not the
        /// host's opinion. The retry loop exists because finalisation and
        /// collection take more than one pass.
        /// </remarks>
        internal bool IsContextCollected(string modId, int attempts = 12)
        {
            if (!_mods.TryGetValue(modId, out LoadedMod record) ||
                record.ContextRef == null)
            {
                return true;
            }

            for (int i = 0; i < attempts && record.ContextRef.IsAlive; i++)
            {
                GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true);
                GC.WaitForPendingFinalizers();
                GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true);
            }

            return !record.ContextRef.IsAlive;
        }

        internal int AliveContextCount()
        {
            int alive = 0;
            foreach (LoadedMod record in _mods.Values)
            {
                if (record.ContextRef != null && record.ContextRef.IsAlive)
                {
                    alive += 1;
                }
            }

            return alive;
        }

        internal string ShutdownAll()
        {
            NativeBridge.MbError error = default;
            NativeBridge.MbStr report = default;
            _host->Shutdown(&report, &error);
            return report.ToString();
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal void ForgetRecord(string modId) => _mods.Remove(modId);
    }
}
