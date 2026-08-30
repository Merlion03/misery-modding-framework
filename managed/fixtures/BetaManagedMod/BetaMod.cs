using System;
using System.Collections.Generic;
using Misery.ModAPI;

namespace BetaManagedMod
{
    /// <summary>
    /// The second healthy mod. Independently built, and deliberately NOT a copy
    /// of the first: it uses the same local id, which is what proves the row
    /// name is derived from the mod's identity rather than from what it asked
    /// for.
    /// </summary>
    [ModCapabilities(Capabilities.Log, Capabilities.Events, Capabilities.Items,
                     Optional = new[] { Capabilities.Services },
                     FrameworkApi = "^0.5.0")]
    public sealed class BetaMod : IMod
    {
        private IModContext _context;

        /// <summary>Events this mod saw.</summary>
        public static readonly List<string> Seen = new List<string>();

        /// <summary>Row names this mod registered.</summary>
        public static readonly List<string> Rows = new List<string>();

        /// <summary>The service handle bound from alpha, kept deliberately.</summary>
        public static IModService BoundFromAlpha;

        public void OnLoad(IModContext context)
        {
            _context = context;
            context.Log.Info("beta managed mod starting");

            context.Events.Declare("betamod:ready");
            context.Events.Subscribe("betamod:ready", evt =>
            {
                Seen.Add(evt.Name + "|" + evt.PayloadJson);
            });

            // The SAME local id alpha used. The row names must still differ.
            var declaration = new ItemDeclaration(
                localId: "managedshape",
                displayName: "Beta Managed Shape",
                shortName: "BetaMS",
                description: "Also registered from C#, under a different ModId.",
                weight: 0.35,
                worldMesh: "/Game/Mods/betamod/Meshes/SM_Shape",
                inventoryIcon: "/Game/Mods/betamod/Textures/T_Icon");

            context.Items.Register(declaration, out string rowName);
            Rows.Add(rowName);

            // Held on purpose, past alpha's unload. The acceptance checks that
            // this stops working rather than becoming dangerous.
            if (context.TryGetServices(out IModServices services))
            {
                try
                {
                    BoundFromAlpha = services.Bind("alphamod:info", "^1.0.0");
                }
                catch (ModException)
                {
                    BoundFromAlpha = null;
                }
            }
        }

        public void OnUnload() => _context?.Log.Info("beta managed mod stopping");
    }
}
