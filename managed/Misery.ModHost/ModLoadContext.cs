using System;
using System.IO;
using System.Reflection;
using System.Runtime.Loader;

namespace Misery.ModHost
{
    /// <summary>
    /// One collectible <see cref="AssemblyLoadContext"/> per mod.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Collectible is what makes unload and reload real rather than nominal: a
    /// non-collectible context would leave every version of a mod's code in the
    /// process forever, and "reload A" would mean "run a second copy of A".
    /// </para>
    /// <para>
    /// THE SHARED-CONTRACT RULE. <c>Misery.ModAPI</c> must resolve to the SAME
    /// assembly for the host and for every mod. If each mod's context loaded its
    /// own copy, then <c>IMod</c> from the mod and <c>IMod</c> from the host
    /// would be different types with the same name, and the cast that hands a
    /// mod its context would fail with a message that reads like nonsense. So
    /// <see cref="Load"/> returns null for the contract assembly, which delegates
    /// to the default context -- and it does the same for everything the default
    /// context already has, because a mod accidentally shipping its own copy of
    /// a framework assembly is the same problem wearing a different hat.
    /// </para>
    /// <para>
    /// Everything else resolves from the mod's own folder. A mod's dependencies
    /// are its own, and two mods may ship different versions of the same library
    /// without a conflict, which is one of the main reasons per-mod contexts are
    /// worth their cost.
    /// </para>
    /// </remarks>
    internal sealed class ModLoadContext : AssemblyLoadContext
    {
        private readonly AssemblyDependencyResolver _resolver;
        private readonly string _folder;

        internal ModLoadContext(string modId, string assemblyPath)
            : base("misery-mod-" + modId, isCollectible: true)
        {
            ModId = modId;
            AssemblyPath = assemblyPath;
            _folder = Path.GetDirectoryName(Path.GetFullPath(assemblyPath));
            _resolver = new AssemblyDependencyResolver(assemblyPath);
        }

        internal string ModId { get; }

        internal string AssemblyPath { get; }

        protected override Assembly Load(AssemblyName assemblyName)
        {
            // Return the host's OWN assembly object, not null.
            //
            // Null means "ask the Default context", and that is wrong here in a
            // way that took a diagnostic to see. hostfxr's
            // load_assembly_and_get_function_pointer does NOT load the host into
            // the Default context -- it creates an IsolatedComponentLoadContext
            // for it. So deferring to Default loaded a SECOND copy of
            // Misery.ModAPI from the same file, and the mod's IMod and the
            // host's IMod became two different types. The symptom was
            // "'AlphaManagedMod' contains no public type implementing IMod",
            // about an assembly whose only public type implements exactly that.
            //
            // Handing back the concrete Assembly the host is already using makes
            // the identity question unanswerable-by-accident: there is one
            // object, so there is one type.
            if (assemblyName.Name == "Misery.ModAPI")
            {
                return typeof(Misery.ModAPI.IMod).Assembly;
            }

            if (assemblyName.Name == "Misery.ModHost")
            {
                return typeof(ModLoadContext).Assembly;
            }

            string resolved = _resolver.ResolveAssemblyToPath(assemblyName);
            if (resolved != null && !string.IsNullOrEmpty(_folder) &&
                resolved.StartsWith(_folder, StringComparison.OrdinalIgnoreCase))
            {
                return LoadFromAssemblyPath(resolved);
            }

            string beside = Path.Combine(_folder ?? ".", assemblyName.Name + ".dll");
            if (File.Exists(beside))
            {
                return LoadFromAssemblyPath(beside);
            }

            return null;
        }

    }
}
