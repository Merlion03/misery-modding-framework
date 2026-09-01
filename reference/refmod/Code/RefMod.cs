using System;
using Misery.ModAPI;

namespace RefMod
{
    /// <summary>
    /// The reference mod: one item, with a world representation this mod ships.
    /// </summary>
    /// <remarks>
    /// Its job is to be ORDINARY. Everything it does, it does through the public
    /// Misery.ModAPI, with no privileged path and no framework knowledge of it.
    /// If something here needs a special case in the core, the platform has a
    /// gap and the gap is the finding -- not the workaround.
    ///
    /// It names one engine concept, and only as data: the object path of the
    /// class its own world Blueprint derives from. That path is content, in the
    /// same way a mesh path is; the mod holds no pointer, calls no engine
    /// function, and could not tell you what a UClass is.
    /// </remarks>
    [ModCapabilities(Capabilities.Log, Capabilities.Items,
                     Capabilities.Events,
                     FrameworkApi = "^0.5.0")]
    public sealed class ReferenceMod : IMod
    {
        // The Mod Kit derives both of these from the same spec that built the
        // content, so they are written once here and nowhere else.
        private const string WorldClass =
            "/Game/Mods/refmod/Blueprints/BP_WorldItem.BP_WorldItem_C";
        private const string WorldMesh = "/Game/Mods/refmod/Meshes/SM_Shape";
        private const string InventoryIcon = "/Game/Mods/refmod/Textures/T_Icon";

        private IModContext _context;
        private IModResource _item;

        /// <summary>The row the framework derived. Read by the acceptance.</summary>
        public static string RegisteredRow { get; private set; }

        /// <summary>How many the inventory took. Read by the acceptance.</summary>
        public static int Granted { get; private set; } = -1;

        public void OnLoad(IModContext context)
        {
            _context = context;
            context.Log.Info("reference mod starting");

            var declaration = new ItemDeclaration(
                localId: "sample",
                displayName: "Reference Sample",
                shortName: "RefSample",
                description: "A reference item, built entirely on the public API.",
                weight: 0.30,
                worldMesh: WorldMesh,
                inventoryIcon: InventoryIcon)
            {
                // The whole point of the E-3c route, expressed as one property:
                // this item is MY actor in the world, not the game's with my
                // mesh on it. The framework checks the ancestry and refuses the
                // registration if the class is not really a world item.
                WorldClass = WorldClass,
            };

            _item = context.Items.Register(declaration, out string rowName);
            RegisteredRow = rowName;
            context.Log.Info("registered " + rowName);

            // WAIT TO BE TOLD THE WORLD IS READY.
            //
            // OnLoad runs when the managed host starts, which is a main menu:
            // the item above is DECLARED but not yet live in any world, and
            // asking the inventory to take it there is asking about a world
            // that does not exist. The first version of this mod did exactly
            // that, was correctly refused, and then nothing ever asked again --
            // which is what showed the framework was missing this event rather
            // than the mod being written wrong.
            context.Events.Subscribe(FrameworkEvents.ContentReady,
                                     OnContentReady);
        }

        /// <summary>The framework says this generation is ready to be used.</summary>
        /// <remarks>
        /// Raised once per content generation, after the framework has applied
        /// this mod's declarations to it -- so by the time this runs the row
        /// exists in the world being described. It is raised again after a
        /// transition, with a new generation, which is why the grant lives here
        /// rather than in OnLoad.
        /// </remarks>
        private void OnContentReady(ModEvent evt)
        {
            try
            {
                int taken = _context.Items.AddToPlayerInventory(_item, 1);
                Granted = taken;
                _context.Log.Info("inventory accepted " + taken + " for " +
                                  evt.PayloadJson);
            }
            catch (ModException failure)
            {
                // A refusal is an ordinary answer, not a crash. The pack may be
                // full, and that is the game's call to make.
                _context.Log.Warn("the inventory did not take it: " +
                                  failure.Message);
            }
        }

        public void OnUnload()
        {
            _item?.Dispose();
            _item = null;
            _context?.Log.Info("reference mod stopping");
        }
    }
}
