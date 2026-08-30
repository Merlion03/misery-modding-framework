using System;
using System.Collections.Generic;
using Misery.ModAPI;

namespace AlphaManagedMod
{
    /// <summary>
    /// A healthy C# mod. Written against Misery.ModAPI and nothing else.
    /// </summary>
    /// <remarks>
    /// Everything this mod does is something the Stage 5A gate has to prove
    /// works from managed code: it logs, it declares and subscribes to an event,
    /// it registers an item whose row name it never chooses, and it publishes a
    /// service another mod binds. It names no engine concept, holds no pointer,
    /// and has no idea a native bridge exists.
    /// </remarks>
    [ModCapabilities(Capabilities.Log, Capabilities.Events, Capabilities.Items,
                     Optional = new[] { Capabilities.Services },
                     FrameworkApi = "^0.5.0")]
    public sealed class AlphaMod : IMod
    {
        private IModContext _context;

        /// <summary>Events this mod saw. Read by the acceptance.</summary>
        public static readonly List<string> Seen = new List<string>();

        /// <summary>Row names this mod registered.</summary>
        public static readonly List<string> Rows = new List<string>();

        /// <summary>Set when OnUnload ran.</summary>
        public static bool Unloaded;

        public void OnLoad(IModContext context)
        {
            _context = context;
            context.Log.Info("alpha managed mod starting");

            context.Events.Declare("alphamod:ready", "raised once alpha is up");
            context.Events.Subscribe("alphamod:ready", evt =>
            {
                Seen.Add(evt.Name + "|" + evt.PayloadJson);
                context.Log.Debug("alpha saw " + evt.Name);
            });

            var declaration = new ItemDeclaration(
                localId: "managedshape",
                displayName: "Alpha Managed Shape",
                shortName: "AlphaMS",
                description: "Registered from C# through the native bridge.",
                weight: 0.25,
                worldMesh: "/Game/Mods/alphamod/Meshes/SM_Shape",
                inventoryIcon: "/Game/Mods/alphamod/Textures/T_Icon");

            context.Items.Register(declaration, out string rowName);
            Rows.Add(rowName);
            context.Log.Info("registered " + rowName);

            if (context.TryGetServices(out IModServices services))
            {
                services.Publish("alphamod:info", "1.0.0",
                    new Dictionary<string, Func<string, string>>
                    {
                        { "ping", _ => "pong" }
                    });
            }
        }

        public void OnUnload()
        {
            Unloaded = true;
            _context?.Log.Info("alpha managed mod stopping");
        }

        /// <summary>Lets the acceptance make this mod raise its own event.</summary>
        public static int RaiseFrom(IModContext context) =>
            context.Events.Publish("alphamod:ready", "{\"from\":\"alpha\"}");
    }
}
