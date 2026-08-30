using Misery.ModAPI;

namespace ThrowOnLoadMod
{
    /// <summary>Throws from OnLoad, AFTER acquiring something.</summary>
    /// <remarks>
    /// Acquiring first is the point: a mod that fails before touching anything
    /// is easy. This one has a live subscription and a declared event when it
    /// throws, so the framework has to release them.
    /// </remarks>
    [ModCapabilities(Capabilities.Log, Capabilities.Events)]
    public sealed class BrokenLoad : IMod
    {
        public void OnLoad(IModContext context)
        {
            context.Log.Info("about to fail");
            context.Events.Declare("throwonloadmod:doomed");
            context.Events.Subscribe("throwonloadmod:doomed", _ => { });
            throw new System.InvalidOperationException("this mod fails on purpose");
        }

        public void OnUnload() { }
    }
}
