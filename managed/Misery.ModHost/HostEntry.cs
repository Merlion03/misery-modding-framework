using System;
using System.Collections.Generic;
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
        /// PRODUCTION entry point: load the mods the plan names, and nothing
        /// else.
        /// </summary>
        /// <remarks>
        /// <para>
        /// <see cref="Bootstrap"/> runs <see cref="Acceptance"/>, which is a
        /// test suite: it asserts across a fixed set of fixtures, demands at
        /// least two of them, and deliberately breaks things to prove failure
        /// isolation. That is exactly right for the Stage 5A gate and exactly
        /// wrong for a player's machine, where the host should load whatever is
        /// installed -- one mod, five, or none -- and report what happened.
        /// </para>
        /// <para>
        /// So this is a separate entry rather than a mode flag on the existing
        /// one. The gate keeps running the harness it was written against, and
        /// production does not carry an acceptance suite into a shipping game.
        /// Both share the same <see cref="HostController"/>, so the loading
        /// itself is one implementation.
        /// </para>
        /// <para>
        /// A mod that fails to load does NOT fail the call. Stage 5A's
        /// invariant is that one broken mod must not poison another, and the
        /// same rule applies here: each failure is recorded in the report and
        /// the remaining mods still load.
        /// </para>
        /// </remarks>
        [UnmanagedCallersOnly(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
        public static int Load(IntPtr rootPointer, ulong hostHandle,
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

                var loaded = new List<string>();
                var failed = new List<string>();
                foreach (var entry in ParsePlan(args))
                {
                    HostController.LoadedMod mod;
                    try
                    {
                        mod = _controller.Load(entry.Key, entry.Value);
                    }
                    catch (Exception failure)
                    {
                        // Contained here as well as inside Load: a throw that
                        // escaped this loop would stop the mods after it from
                        // loading, which is the poisoning the invariant forbids.
                        failed.Add("{\"mod\":\"" + Json.Escape(entry.Key) +
                                   "\",\"error\":\"" +
                                   Json.Escape(failure.GetType().Name + ": " +
                                               failure.Message) + "\"}");
                        continue;
                    }
                    if (mod.Failed)
                    {
                        failed.Add("{\"mod\":\"" + Json.Escape(entry.Key) +
                                   "\",\"error\":\"" +
                                   Json.Escape(mod.LastError ?? "unknown") + "\"}");
                    }
                    else
                    {
                        loaded.Add("\"" + Json.Escape(entry.Key) + "\"");
                    }
                }

                // "ok" is about the HOST, not the mods, and the two are
                // genuinely different questions. A broken mod alongside three
                // working ones must not read as a host failure -- containment is
                // the invariant, and reporting otherwise would make callers tear
                // down a host that is serving other mods perfectly well.
                //
                // But "ok" alone is then far too weak for a caller to act on,
                // and the first draft of this method proved it: every mod in the
                // plan failed, ok was true, and the run looked like a success
                // with an empty loaded list nobody was reading. So the counts are
                // stated explicitly, and "all_loaded" answers the question a
                // caller actually has.
                _lastReport = "{\"ok\":true,\"all_loaded\":" +
                              (failed.Count == 0 ? "true" : "false") +
                              ",\"loaded_count\":" + loaded.Count +
                              ",\"failed_count\":" + failed.Count +
                              ",\"loaded\":[" + string.Join(",", loaded) +
                              "],\"failed\":[" + string.Join(",", failed) +
                              "],\"native\":" + _controller.Snapshot() + "}";
                return 0;
            }
            catch (Exception failure)
            {
                // NOTHING escapes into C++ frames, here as in Bootstrap.
                _lastReport = "{\"ok\":false,\"error\":\"" +
                              Json.Escape(failure.GetType().Name + ": " +
                                          failure.Message) + "\"}";
                return 1;
            }
        }

        /// <summary>
        /// "modId=path;modId=path". The same shape Acceptance parses; kept here
        /// so the production entry does not depend on the test suite.
        /// </summary>
        private static List<KeyValuePair<string, string>> ParsePlan(string args)
        {
            var plan = new List<KeyValuePair<string, string>>();
            if (string.IsNullOrWhiteSpace(args))
            {
                return plan;
            }
            foreach (string entry in args.Split(';'))
            {
                if (string.IsNullOrWhiteSpace(entry))
                {
                    continue;
                }
                int split = entry.IndexOf('=');
                if (split <= 0)
                {
                    continue;
                }
                plan.Add(new KeyValuePair<string, string>(
                    entry.Substring(0, split).Trim(),
                    entry.Substring(split + 1).Trim()));
            }
            return plan;
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
