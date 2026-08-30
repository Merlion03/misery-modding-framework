using Misery.ModAPI;

namespace ThrowOnUnloadMod
{
    /// <summary>Loads fine and throws on the way out.</summary>
    /// <remarks>
    /// Its resources must still be released: a mod that throws while leaving
    /// must not be able to keep its subscriptions alive by refusing to go.
    /// </remarks>
    [ModCapabilities(Capabilities.Log, Capabilities.Events)]
    public sealed class BrokenUnload : IMod
    {
        public void OnLoad(IModContext context)
        {
            context.Events.Declare("throwonunloadmod:ready");
            context.Events.Subscribe("throwonunloadmod:ready", _ => { });
        }

        public void OnUnload() =>
            throw new System.InvalidOperationException("this mod fails on the way out");
    }
}
