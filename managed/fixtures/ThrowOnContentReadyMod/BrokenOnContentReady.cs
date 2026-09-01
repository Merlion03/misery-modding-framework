using Misery.ModAPI;

namespace ThrowOnContentReadyMod
{
    /// <summary>Loads fine, then throws from the framework's readiness event.</summary>
    /// <remarks>
    /// Stage 7 added misery:content_ready so a mod can know its declarations are
    /// live. That created a dispatch path with more than one subscriber in it,
    /// and this fixture is the adversary for it: it subscribes and throws. A mod
    /// that grants on readiness must still be notified with this installed
    /// beside it, or the primitive is only safe when nobody else uses it.
    /// </remarks>
    [ModCapabilities(Capabilities.Log, Capabilities.Events)]
    public sealed class BrokenOnContentReady : IMod
    {
        /// <summary>How many times the faulting handler was entered.</summary>
        public static int Entered;

        public void OnLoad(IModContext context)
        {
            context.Events.Subscribe(FrameworkEvents.ContentReady, _ =>
            {
                Entered += 1;
                throw new System.ApplicationException(
                    "content_ready failure, on purpose");
            });
        }

        public void OnUnload() { }
    }
}
