using System;
using System.Collections.Generic;
using Misery.ModAPI;

namespace Misery.ModHost
{
    /// <summary>
    /// The <see cref="IModContext"/> a mod is handed. Every call is bound to
    /// one mod handle, which the mod never sees and cannot forge.
    /// </summary>
    internal sealed unsafe class ModContextImpl : IModContext
    {
        private readonly HostController _host;
        private readonly ulong _modHandle;
        private readonly List<ulong> _subscriptions = new List<ulong>();

        internal ModContextImpl(HostController host, ModId id, ulong modHandle,
                                ICapabilityGrant grant)
        {
            _host = host;
            Id = id;
            _modHandle = modHandle;
            Grant = grant;
            Log = new ModLogImpl(host, modHandle, id);
        }

        public ModId Id { get; }

        public IModLog Log { get; }

        public ICapabilityGrant Grant { get; }

        public bool IsAlive { get; private set; } = true;

        internal ulong ModHandle => _modHandle;

        internal IReadOnlyList<ulong> Subscriptions => _subscriptions;

        internal void Kill() => IsAlive = false;

        private void RequireAlive()
        {
            if (!IsAlive)
            {
                throw new ModException(ModSubsystem.Lifecycle,
                                       ModErrorCode.OwnerDisposed,
                                       "this mod context has been torn down", Id);
            }
        }

        public IModEvents Events
        {
            get
            {
                RequireAlive();
                Grant.Require(Capabilities.Events, Id);
                return new ModEventsImpl(_host, this);
            }
        }

        public IModSettings Settings
        {
            get
            {
                RequireAlive();
                Grant.Require(Capabilities.Settings, Id);
                return new ModSettingsImpl(_host, this);
            }
        }

        public IModItems Items
        {
            get
            {
                RequireAlive();
                Grant.Require(Capabilities.Items, Id);
                return new ModItemsImpl(_host, this);
            }
        }

        public bool TryGetInput(out IModInputActions input)
        {
            input = null;
            return false;   // the engine input path is unresearched; see Stage 4.5
        }

        public bool TryGetServices(out IModServices services)
        {
            if (!IsAlive || !Grant.Has(Capabilities.Services))
            {
                services = null;
                return false;
            }

            services = new ModServicesImpl(_host, this);
            return true;
        }

        internal void TrackSubscription(ulong handle) => _subscriptions.Add(handle);
    }

    internal sealed class CapabilityGrant : ICapabilityGrant
    {
        private readonly HashSet<string> _granted;

        internal CapabilityGrant(string apiVersion, IEnumerable<string> granted)
        {
            ApiVersion = apiVersion;
            _granted = new HashSet<string>(granted, StringComparer.Ordinal);
        }

        public string ApiVersion { get; }

        public bool Has(string capability) => _granted.Contains(capability);

        public string VersionOf(string capability) =>
            _granted.Contains(capability) ? "1.0.0" : null;

        internal void Require(string capability, ModId id)
        {
            if (!_granted.Contains(capability))
            {
                throw new ModException(ModSubsystem.Capabilities,
                                       ModErrorCode.CapabilityNotGranted,
                                       "'" + capability + "' was not granted to '" +
                                       id + "'; a mod must declare what it needs",
                                       id);
            }
        }
    }

    internal static class GrantExtensions
    {
        internal static void Require(this ICapabilityGrant grant, string capability,
                                     ModId id)
        {
            if (grant is CapabilityGrant concrete)
            {
                concrete.Require(capability, id);
                return;
            }

            if (!grant.Has(capability))
            {
                throw new ModException(ModSubsystem.Capabilities,
                                       ModErrorCode.CapabilityNotGranted,
                                       "'" + capability + "' was not granted", id);
            }
        }
    }

    internal sealed unsafe class ModLogImpl : IModLog
    {
        private readonly HostController _host;
        private readonly ulong _modHandle;
        private readonly ModId _id;

        internal ModLogImpl(HostController host, ulong modHandle, ModId id)
        {
            _host = host;
            _modHandle = modHandle;
            _id = id;
        }

        public void Trace(string message) => Write(ModLogLevel.Trace, message, null);

        public void Debug(string message) => Write(ModLogLevel.Debug, message, null);

        public void Info(string message) => Write(ModLogLevel.Info, message, null);

        public void Warn(string message) => Write(ModLogLevel.Warn, message, null);

        public void Error(string message) => Write(ModLogLevel.Error, message, null);

        public void Write(ModLogLevel level, string message,
                          IReadOnlyDictionary<string, object> fields)
        {
            _host.LogWrite(_modHandle, (int)level, message ?? string.Empty,
                           Json.FromFields(fields));
        }
    }

    internal sealed class ModEventsImpl : IModEvents
    {
        private readonly HostController _host;
        private readonly ModContextImpl _context;

        internal ModEventsImpl(HostController host, ModContextImpl context)
        {
            _host = host;
            _context = context;
        }

        public IModResource Declare(string name, string detail = null) =>
            _host.EventsDeclare(_context, name, detail);

        public IModResource Subscribe(string name, Action<ModEvent> handler)
        {
            if (handler == null)
            {
                throw new ArgumentNullException(nameof(handler));
            }

            return _host.EventsSubscribe(_context, name, handler);
        }

        public int Publish(string name, string payloadJson = null) =>
            _host.EventsPublish(_context, name, payloadJson);
    }

    internal sealed class ModItemsImpl : IModItems
    {
        private readonly HostController _host;
        private readonly ModContextImpl _context;

        internal ModItemsImpl(HostController host, ModContextImpl context)
        {
            _host = host;
            _context = context;
        }

        public IModResource Register(ItemDeclaration declaration, out string rowName) =>
            _host.ItemsRegister(_context, declaration, out rowName);

        public int AddToPlayerInventory(IModResource item, int amount) =>
            _host.ItemsGrant(_context, item, amount);
    }

    internal sealed class ModServicesImpl : IModServices
    {
        private readonly HostController _host;
        private readonly ModContextImpl _context;

        internal ModServicesImpl(HostController host, ModContextImpl context)
        {
            _host = host;
            _context = context;
        }

        public IModResource Publish(string name, string version,
                                    IReadOnlyDictionary<string, Func<string, string>> methods) =>
            _host.ServicesPublish(_context, name, version, methods);

        public IModService Bind(string name, string versionRequirement = ">=0.0.0") =>
            _host.ServicesBind(_context, name, versionRequirement);
    }

    internal sealed class ModSettingsImpl : IModSettings
    {
        private readonly HostController _host;
        private readonly ModContextImpl _context;

        internal ModSettingsImpl(HostController host, ModContextImpl context)
        {
            _host = host;
            _context = context;
        }

        public IModResource Declare(IEnumerable<SettingDeclaration> declarations) =>
            _host.SettingsDeclare(_context, declarations);

        public T Get<T>(SettingKey<T> key) => _host.SettingsGet(_context, key);

        public void Set<T>(SettingKey<T> key, T value) =>
            _host.SettingsSet(_context, key, value);

        public void Save() => _host.SettingsSave(_context);
    }

    /// <summary>
    /// A handle on something the mod owns. Disposing early is allowed and
    /// idempotent; not disposing is also fine, because teardown releases
    /// everything regardless.
    /// </summary>
    internal sealed class NativeResource : IModResource
    {
        private readonly HostController _host;
        private readonly ulong _handle;
        private readonly Action<ulong> _release;
        private bool _released;

        internal NativeResource(HostController host, ulong handle,
                                Action<ulong> release)
        {
            _host = host;
            _handle = handle;
            _release = release;
        }

        public bool IsAlive => !_released;

        internal ulong Handle => _handle;

        public void Dispose()
        {
            if (_released)
            {
                return;
            }

            _released = true;
            _release?.Invoke(_handle);
        }
    }

    /// <summary>Minimal JSON writing, so the host has no package dependency.</summary>
    internal static class Json
    {
        internal static string Escape(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return string.Empty;
            }

            var builder = new System.Text.StringBuilder(text.Length + 8);
            foreach (char c in text)
            {
                switch (c)
                {
                    case '"': builder.Append("\\\""); break;
                    case '\\': builder.Append("\\\\"); break;
                    case '\n': builder.Append("\\n"); break;
                    case '\r': builder.Append("\\r"); break;
                    case '\t': builder.Append("\\t"); break;
                    default: builder.Append(c); break;
                }
            }

            return builder.ToString();
        }

        internal static string FromFields(IReadOnlyDictionary<string, object> fields)
        {
            if (fields == null || fields.Count == 0)
            {
                return string.Empty;
            }

            var builder = new System.Text.StringBuilder("{");
            bool first = true;
            foreach (KeyValuePair<string, object> entry in fields)
            {
                if (!first)
                {
                    builder.Append(',');
                }

                first = false;
                builder.Append('"').Append(Escape(entry.Key)).Append("\":\"")
                       .Append(Escape(entry.Value?.ToString())).Append('"');
            }

            return builder.Append('}').ToString();
        }
    }
}
