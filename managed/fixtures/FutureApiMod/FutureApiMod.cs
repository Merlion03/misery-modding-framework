using Misery.ModAPI;

namespace FutureApiMod
{
    /// <summary>
    /// Declares a framework API this build cannot satisfy, and a capability
    /// that does not exist.
    /// </summary>
    /// <remarks>
    /// It must be refused BEFORE its constructor runs, so it never gets the
    /// chance to acquire anything that would then need releasing.
    /// </remarks>
    [ModCapabilities("core.time_travel", FrameworkApi = "^9.0.0")]
    public sealed class FromTheFuture : IMod
    {
        /// <summary>Set if this ever runs, which it must not.</summary>
        public static bool Ran;

        public void OnLoad(IModContext context) => Ran = true;

        public void OnUnload() { }
    }
}
