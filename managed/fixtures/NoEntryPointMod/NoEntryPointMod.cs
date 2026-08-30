namespace NoEntryPointMod
{
    /// <summary>
    /// A perfectly valid assembly that implements no entry point.
    /// </summary>
    /// <remarks>
    /// It does NOT reference Misery.ModAPI at all, which is the realistic shape
    /// of the mistake: somebody ships the wrong DLL. The host must say so
    /// clearly rather than throwing something about types.
    /// </remarks>
    public sealed class NotAMod
    {
        /// <summary>Does nothing, on purpose.</summary>
        public int Nothing() => 0;
    }
}
