using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Misery.ModHost
{
    /// <summary>
    /// What the native runtime calls once CoreCLR is up.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the seam. Native starts hostfxr, loads this assembly into the
    /// DEFAULT load context, and calls <see cref="Bootstrap"/> with the bridge
    /// root it already acquired. Everything above this line is managed;
    /// everything below it is C++.
    /// </para>
    /// <para>
    /// The signature is deliberately primitive -- two pointers, two integers --
    /// because a richer one would need marshalling agreed by both sides before
    /// either can talk to the other, which is a bootstrap problem nobody needs.
    /// </para>
    /// </remarks>
    public static unsafe class HostEntry
    {
        private static HostController _controller;
        private static string _lastReport = "{}";

        /// <summary>
        /// Entry point. Returns 0 on success; the report is fetched separately
        /// because returning a string across this boundary would need an
        /// ownership rule the bootstrap does not have yet.
        /// </summary>
        [UnmanagedCallersOnly(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
        public static int Bootstrap(IntPtr rootPointer, ulong hostHandle,
                                    IntPtr argsUtf8, int argsLength)
        {
            try
            {
                string args = argsLength > 0 && argsUtf8 != IntPtr.Zero
                    ? Encoding.UTF8.GetString((byte*)argsUtf8, argsLength)
                    : string.Empty;

                EnsureSharedContractLoaded();

                var root = (NativeBridge.MbRoot*)rootPointer;
                if (root->AbiEpoch != NativeBridge.AbiEpoch)
                {
                    _lastReport = "{\"ok\":false,\"error\":\"abi epoch mismatch: " +
                                  "native " + root->AbiEpoch + ", managed " +
                                  NativeBridge.AbiEpoch + "\"}";
                    return 2;
                }

                _controller = new HostController(root, hostHandle);
                _controller.SetTrampoline();
                _lastReport = Acceptance.Run(_controller, args);
                return 0;
            }
            catch (Exception failure)
            {
                // NOTHING escapes into C++ frames. A managed exception unwinding
                // through them is undefined behaviour, not an error.
                _lastReport = "{\"ok\":false,\"error\":\"" +
                              Json.Escape(failure.GetType().Name + ": " +
                                          failure.Message) + "\"}";
                return 1;
            }
        }

        /// <summary>
        /// Makes sure the contract assembly is loaded, in the host's OWN load
        /// context.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The load is needed because every reference the host makes to
        /// Misery.ModAPI is to a <c>const</c> -- capability names, error codes --
        /// which the compiler inlines, so the host can run without the assembly
        /// ever being loaded. Touching a TYPE forces it.
        /// </para>
        /// <para>
        /// An earlier version also installed a Resolving handler on the DEFAULT
        /// context, and that was the bug: hostfxr loads this assembly into an
        /// IsolatedComponentLoadContext, not into Default, so the handler
        /// obligingly loaded a SECOND copy of the contract from the same file.
        /// Two copies means two <c>IMod</c> types, and every mod stops
        /// implementing the one the host is looking for. See ModLoadContext.
        /// </para>
        /// </remarks>
        private static void EnsureSharedContractLoaded()
        {
            _ = typeof(ModAPI.IMod).FullName;
        }

        /// <summary>
        /// Copies the last report out as UTF-8. Returns the byte length, or the
        /// required length when the buffer is too small.
        /// </summary>
        [UnmanagedCallersOnly(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
        public static int FetchReport(IntPtr buffer, int capacity)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(_lastReport ?? "{}");
            if (buffer == IntPtr.Zero || capacity < bytes.Length)
            {
                return bytes.Length;
            }

            Marshal.Copy(bytes, 0, buffer, bytes.Length);
            return bytes.Length;
        }
    }
}
