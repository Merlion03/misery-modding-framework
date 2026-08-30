using Misery.ModAPI;

namespace ThrowInCallbackMod
{
    /// <summary>Loads fine, then throws from inside an event callback.</summary>
    [ModCapabilities(Capabilities.Log, Capabilities.Events)]
    public sealed class BrokenCallback : IMod
    {
        /// <summary>How many times the faulting handler was entered.</summary>
        public static int Entered;

        public void OnLoad(IModContext context)
        {
            context.Events.Declare("throwincallbackmod:boom");
            context.Events.Subscribe("throwincallbackmod:boom", _ =>
            {
                Entered += 1;
                throw new System.ApplicationException("callback failure");
            });
        }

        public void OnUnload() { }
    }
}
