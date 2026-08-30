using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Misery.ModAPI;

namespace Misery.ModHost
{
    /// <summary>
    /// The Stage 5A acceptance, run inside the hosted runtime.
    /// </summary>
    /// <remarks>
    /// It lives in the host rather than in a test project because it has to run
    /// in the SAME process as the mods it loads -- that is the whole gate. The
    /// native harness runs it with no game attached; the in-game runtime runs
    /// the same code with the real items backend installed.
    /// <para>
    /// Mods are named by the caller through the args, from the Stage 4 load
    /// plan. No fixture is hardcoded here.
    /// </para>
    /// </remarks>
    internal static class Acceptance
    {
        private sealed class Checks
        {
            private readonly StringBuilder _json = new StringBuilder();
            internal int Passed;
            internal int Failed;

            internal bool Add(string label, bool ok, string detail = null)
            {
                if (_json.Length > 0)
                {
                    _json.Append(',');
                }

                _json.Append("{\"check\":\"").Append(Json.Escape(label))
                     .Append("\",\"pass\":").Append(ok ? "true" : "false");
                if (!string.IsNullOrEmpty(detail))
                {
                    _json.Append(",\"detail\":\"").Append(Json.Escape(detail)).Append('"');
                }

                _json.Append('}');
                if (ok)
                {
                    Passed++;
                }
                else
                {
                    Failed++;
                }

                return ok;
            }

            public override string ToString() => _json.ToString();
        }

        /// <summary>
        /// args is "modId=path;modId=path;..." taken from the Stage 4 load plan.
        /// </summary>
        private static List<KeyValuePair<string, string>> ParsePlan(string args)
        {
            var plan = new List<KeyValuePair<string, string>>();
            foreach (string entry in (args ?? string.Empty).Split(';'))
            {
                if (string.IsNullOrWhiteSpace(entry))
                {
                    continue;
                }

                int eq = entry.IndexOf('=');
                if (eq <= 0)
                {
                    continue;
                }

                plan.Add(new KeyValuePair<string, string>(
                    entry.Substring(0, eq).Trim(), entry.Substring(eq + 1).Trim()));
            }

            return plan;
        }

        internal static string Run(HostController host, string args)
        {
            var checks = new Checks();
            List<KeyValuePair<string, string>> plan = ParsePlan(args);

            checks.Add("the load plan named at least two mods", plan.Count >= 2,
                       plan.Count + " entries");
            if (plan.Count < 2)
            {
                return Wrap(checks, host, "the harness needs two mods");
            }

            string alphaId = plan[0].Key;
            string betaId = plan[1].Key;
            string alphaPath = plan[0].Value;
            string betaPath = plan[1].Value;

            // ---- 1. load both, from the plan --------------------------------
            HostController.LoadedMod alpha =
                host.Load(alphaId, alphaPath);
            checks.Add("mod A loaded from the plan", !alpha.Failed, alpha.LastError);
            HostController.LoadedMod beta =
                host.Load(betaId, betaPath);
            checks.Add("mod B loaded from the plan", !beta.Failed, beta.LastError);

            if (alpha.Failed || beta.Failed)
            {
                return Wrap(checks, host, "the healthy fixtures did not load");
            }

            // ---- 2. C# -> native semantic calls happened --------------------
            string snapshot = host.Snapshot();
            checks.Add("the bridge recorded log records from C#",
                       snapshot.Contains("\"log_records\":") &&
                       !snapshot.Contains("\"log_records\":0"), snapshot);
            checks.Add("each mod owns resources natively",
                       snapshot.Contains("\"owned\":") &&
                       !snapshot.Contains("\"owned\":0,\"released\":0,\"revoked\":0,\"faults\":0,\"active_frames\":0,\"reclaimable\":false"),
                       snapshot);

            // ---- 3. native -> trampoline -> the right mod's callback --------
            Trampoline.ResetCounters();
            long before = Trampoline.Delivered;
            int ran = host.HostPublish(alpha.Handle, alphaId + ":ready",
                                       "{\"from\":\"host\"}");
            checks.Add("a host-raised event reached a managed callback",
                       ran >= 1 && Trampoline.Delivered > before,
                       "ran=" + ran + " delivered=" + Trampoline.Delivered);
            checks.Add("the dispatch reached exactly one registration",
                       Trampoline.Delivered - before == 1,
                       (Trampoline.Delivered - before).ToString());

            // A second mod's event must not reach the first mod's handler.
            long beforeBeta = Trampoline.Delivered;
            host.HostPublish(beta.Handle, betaId + ":ready", "{\"from\":\"host\"}");
            checks.Add("each event reached only its own subscriber",
                       Trampoline.Delivered - beforeBeta == 1,
                       (Trampoline.Delivered - beforeBeta).ToString());

            // ---- 4. threading contract -------------------------------------
            Exception offThread = null;
            Task.Run(() =>
            {
                try
                {
                    host.LogWrite(alpha.Handle, 2, "from a pool thread", null);
                }
                catch (Exception failure)
                {
                    offThread = failure;
                }
            }).Wait();
            checks.Add("a bridge call from another managed thread is refused",
                       offThread is ModException modError &&
                       modError.Code == ModErrorCode.WrongThread,
                       offThread?.Message ?? "no exception was thrown");

            // ---- 5. unload A ------------------------------------------------
            int alphaDelegatesBefore = Trampoline.CountFor(alphaId);
            checks.Add("mod A had managed callbacks registered",
                       alphaDelegatesBefore > 0,
                       alphaDelegatesBefore.ToString());

            string teardown = host.Unload(alphaId);
            checks.Add("unload reported a native teardown",
                       teardown.Contains("\"released\""), teardown);
            checks.Add("mod A's managed callbacks were forgotten",
                       Trampoline.CountFor(alphaId) == 0,
                       Trampoline.CountFor(alphaId).ToString());
            checks.Add("the native side says mod A is reclaimable",
                       host.IsReclaimableNative(alphaId, out string why), why);

            // The runtime's answer, not the host's opinion.
            checks.Add("mod A's AssemblyLoadContext was actually COLLECTED",
                       host.IsContextCollected(alphaId),
                       "Unload() was called; this asks the GC whether it worked");

            // ---- 6. B is untouched ------------------------------------------
            long beforeSurvivor = Trampoline.Delivered;
            int survivorRan = host.HostPublish(beta.Handle, betaId + ":ready",
                                               "{\"after\":\"a-unload\"}");
            checks.Add("mod B still receives events after A unloaded",
                       survivorRan == 1 && Trampoline.Delivered - beforeSurvivor == 1,
                       "ran=" + survivorRan);
            checks.Add("mod B is NOT reclaimable while loaded",
                       !host.IsReclaimableNative(betaId, out string betaWhy), betaWhy);

            // A's events must be gone entirely.
            bool alphaEventRefused = false;
            try
            {
                host.HostPublish(beta.Handle, alphaId + ":ready", "{}");
            }
            catch (ModException)
            {
                alphaEventRefused = true;
            }

            checks.Add("mod A's event declaration was released with it",
                       alphaEventRefused, "publishing it should now be refused");

            // ---- 7. reload A ------------------------------------------------
            host.ForgetRecord(alphaId);
            HostController.LoadedMod reloaded =
                host.Load(alphaId, alphaPath);
            checks.Add("mod A reloaded into a NEW context", !reloaded.Failed,
                       reloaded.LastError);
            checks.Add("the reloaded A works again",
                       host.HostPublish(reloaded.Handle, alphaId + ":ready",
                                        "{\"reloaded\":true}") == 1);
            host.Unload(alphaId);
            host.ForgetRecord(alphaId);

            // ---- 8. cycles: nothing is retained -----------------------------
            int cycles = 25;
            var leaked = new List<string>();
            for (int i = 0; i < cycles; i++)
            {
                HostController.LoadedMod cycle =
                    host.Load(alphaId, alphaPath);
                if (cycle.Failed)
                {
                    leaked.Add("cycle " + i + " failed to load: " + cycle.LastError);
                    break;
                }

                host.Unload(alphaId);
                if (Trampoline.CountFor(alphaId) != 0)
                {
                    leaked.Add("cycle " + i + " left managed callbacks");
                }

                if (!host.IsReclaimableNative(alphaId, out string reason))
                {
                    leaked.Add("cycle " + i + " left native resources: " + reason);
                }

                host.ForgetRecord(alphaId);
            }

            checks.Add(cycles + " load/unload cycles retained nothing",
                       leaked.Count == 0, string.Join("; ", leaked));
            checks.Add("the managed callback table is empty of A",
                       Trampoline.CountFor(alphaId) == 0);

            string afterCycles = host.Snapshot();
            checks.Add("the native slot table did not grow without bound",
                       SlotsLookSane(afterCycles), afterCycles);

            // ---- 9. failure isolation, one mode at a time -------------------
            //
            // Three of these do NOT fail at load, and treating them as if they
            // did tested nothing: one throws from a callback, one throws on the
            // way out, one is refused by negotiation before its constructor
            // runs. Each is exercised the way it actually fails.
            for (int i = 2; i < plan.Count; i++)
            {
                string badId = plan[i].Key;
                string badPath = plan[i].Value;
                HostController.LoadedMod broken = host.Load(badId, badPath);

                if (badId.Contains("throwincallback"))
                {
                    checks.Add("a mod that throws only from a callback still loads",
                               !broken.Failed, broken.LastError);
                    if (!broken.Failed)
                    {
                        long faultsBefore = Trampoline.Faults;
                        long deliveredBefore = Trampoline.Delivered;
                        int faultingRan = host.HostPublish(broken.Handle,
                                                           badId + ":boom", "{}");
                        checks.Add("a throwing callback is CONTAINED, not " +
                                   "propagated across the ABI",
                                   Trampoline.Faults > faultsBefore,
                                   "faults " + faultsBefore + " -> " +
                                   Trampoline.Faults + ", ran=" + faultingRan);
                        checks.Add("the faulting callback delivered nothing",
                                   Trampoline.Delivered == deliveredBefore,
                                   Trampoline.Delivered.ToString());
                        checks.Add("mod B is unharmed by another mod's faulting " +
                                   "callback",
                                   host.HostPublish(beta.Handle, betaId + ":ready",
                                                    "{}") == 1);
                        host.Unload(badId);
                    }
                }
                else if (badId.Contains("throwonunload"))
                {
                    checks.Add("a mod that throws on the way out still loads",
                               !broken.Failed, broken.LastError);
                    if (!broken.Failed)
                    {
                        string report = host.Unload(badId);
                        checks.Add("a throwing OnUnload does not stop the " +
                                   "teardown", report.Contains("\"released\""),
                                   report);
                        checks.Add("a mod that threw on unload still released " +
                                   "everything",
                                   host.IsReclaimableNative(badId, out string w),
                                   w);
                        checks.Add("its managed callbacks were still forgotten",
                                   Trampoline.CountFor(badId) == 0,
                                   Trampoline.CountFor(badId).ToString());
                    }
                }
                else
                {
                    checks.Add("broken mod '" + badId + "' was refused at load",
                               broken.Failed, broken.LastError ?? "it loaded");
                    checks.Add("refused mod '" + badId + "' left nothing behind",
                               NothingLeft(host, badId), badId);
                }

                if (!broken.Failed && host.Mods.ContainsKey(badId) &&
                    host.IsReclaimableNative(badId, out string _) == false)
                {
                    // Anything still loaded at this point is taken down, so the
                    // final tallies mean what they say.
                    try
                    {
                        host.Unload(badId);
                    }
                    catch (ModException)
                    {
                    }
                }

                checks.Add("no assembly context of '" + badId + "' survives",
                           host.IsContextCollected(badId), badId);
                host.ForgetRecord(badId);
            }

            checks.Add("the healthy mod B survived every broken neighbour",
                       host.HostPublish(beta.Handle, betaId + ":ready", "{}") == 1);

            // ---- 10. shutdown -----------------------------------------------
            host.Unload(betaId);
            checks.Add("mod B's AssemblyLoadContext was collected too",
                       host.IsContextCollected(betaId),
                       "every context must go, not just the one that was " +
                       "unloaded early");
            string shutdown = host.ShutdownAll();
            checks.Add("shutdown left no live native slot",
                       shutdown.Contains("\"live_slots\":0"), shutdown);
            checks.Add("the managed callback table is empty",
                       Trampoline.Count == 0, Trampoline.Count.ToString());
            checks.Add("no assembly load context is still alive",
                       host.AliveContextCount() == 0,
                       host.AliveContextCount().ToString());

            return Wrap(checks, host, null);
        }

        /// <summary>
        /// True when the platform holds nothing for this mod.
        /// </summary>
        /// <remarks>
        /// A mod refused BEFORE mod_begin is not known to the native side at
        /// all, and "unknown" is the strongest possible form of "left nothing
        /// behind" -- so an UnknownMod refusal counts as clean rather than as a
        /// failure to answer.
        /// </remarks>
        private static bool NothingLeft(HostController host, string modId)
        {
            if (Trampoline.CountFor(modId) != 0)
            {
                return false;
            }

            try
            {
                return host.IsReclaimableNative(modId, out string _);
            }
            catch (ModException error)
            {
                return error.Code == ModErrorCode.UnknownMod;
            }
        }

        private static bool SlotsLookSane(string snapshot)
        {
            int index = snapshot.IndexOf("\"live_slots\":", StringComparison.Ordinal);
            if (index < 0)
            {
                return false;
            }

            int start = index + "\"live_slots\":".Length;
            int end = start;
            while (end < snapshot.Length && char.IsDigit(snapshot[end]))
            {
                end++;
            }

            return int.TryParse(snapshot.Substring(start, end - start), out int live) &&
                   live <= 8;
        }

        private static string Wrap(Checks checks, HostController host, string fatal)
        {
            string snapshot;
            try
            {
                snapshot = host.Snapshot();
            }
            catch (Exception)
            {
                snapshot = "{}";
            }

            return "{\"ok\":" + (checks.Failed == 0 && fatal == null ? "true" : "false") +
                   ",\"passed\":" + checks.Passed +
                   ",\"failed\":" + checks.Failed +
                   (fatal == null ? string.Empty :
                    ",\"fatal\":\"" + Json.Escape(fatal) + "\"") +
                   ",\"trampoline\":{\"delivered\":" + Trampoline.Delivered +
                   ",\"orphaned\":" + Trampoline.Orphaned +
                   ",\"faults\":" + Trampoline.Faults +
                   ",\"registrations\":" + Trampoline.Count + "}" +
                   ",\"native\":" + snapshot +
                   ",\"checks\":[" + checks + "]}";
        }
    }
}
