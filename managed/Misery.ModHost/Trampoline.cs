using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Misery.ModHost
{
    /// <summary>
    /// The single managed entry point native ever holds.
    /// </summary>
    /// <remarks>
    /// <para>
    /// THIS TYPE IS WHY A MOD'S ASSEMBLY CONTEXT CAN BE COLLECTED. The obvious
    /// design gives native a callback pointer per subscription. Every one of
    /// those is a pointer into a collectible <c>AssemblyLoadContext</c>, and a
    /// native table holding one roots that context forever -- so
    /// <c>ALC.Unload()</c> never completes and the mod's memory is never
    /// reclaimed, however carefully everything else was released.
    /// </para>
    /// <para>
    /// So native holds exactly one function pointer, to a static method in the
    /// DEFAULT load context whose lifetime is the process. Dispatch arrives with
    /// the subscription HANDLE; this table resolves it to the mod's delegate.
    /// Native therefore holds integers, and unloading a mod is a dictionary
    /// removal here plus an epoch bump there.
    /// </para>
    /// <para>
    /// The map holds the delegate strongly, which is correct and is the reason
    /// <see cref="Forget"/> must be called for every subscription a mod owned
    /// before its context can collect. The host does that from the unload path,
    /// and the acceptance measures the map's size afterwards rather than
    /// trusting it.
    /// </para>
    /// </remarks>
    internal static class Trampoline
    {
        // Handle -> the mod's delegate. Keyed by the native subscription handle,
        // which is an integer, so nothing native ever holds a managed reference.
        private static readonly Dictionary<ulong, Registration> Registrations =
            new Dictionary<ulong, Registration>();

        private static readonly object Gate = new object();

        internal sealed class Registration
        {
            public Registration(string modId, int kind, Delegate callback)
            {
                ModId = modId;
                Kind = kind;
                Callback = callback;
            }

            public string ModId { get; }

            public int Kind { get; }

            public Delegate Callback { get; }

            public long Invocations;
        }

        internal const int DispatchEvent = 1;
        internal const int DispatchInput = 2;
        internal const int DispatchCommand = 3;

        /// <summary>Total dispatches that reached a live registration.</summary>
        internal static long Delivered;

        /// <summary>Dispatches whose handle had already been forgotten.</summary>
        internal static long Orphaned;

        /// <summary>Callbacks that threw and were contained here.</summary>
        internal static long Faults;

        internal static int Count
        {
            get
            {
                lock (Gate)
                {
                    return Registrations.Count;
                }
            }
        }

        internal static void Remember(ulong handle, string modId, int kind,
                                      Delegate callback)
        {
            lock (Gate)
            {
                Registrations[handle] = new Registration(modId, kind, callback);
            }
        }

        internal static void Forget(ulong handle)
        {
            lock (Gate)
            {
                Registrations.Remove(handle);
            }
        }

        /// <summary>
        /// Drops every registration belonging to one mod. Called from the unload
        /// path BEFORE the context is unloaded, because a delegate left here
        /// would keep that context alive.
        /// </summary>
        internal static int ForgetMod(string modId)
        {
            lock (Gate)
            {
                var doomed = new List<ulong>();
                foreach (KeyValuePair<ulong, Registration> entry in Registrations)
                {
                    if (entry.Value.ModId == modId)
                    {
                        doomed.Add(entry.Key);
                    }
                }

                foreach (ulong handle in doomed)
                {
                    Registrations.Remove(handle);
                }

                return doomed.Count;
            }
        }

        internal static int CountFor(string modId)
        {
            lock (Gate)
            {
                int count = 0;
                foreach (KeyValuePair<ulong, Registration> entry in Registrations)
                {
                    if (entry.Value.ModId == modId)
                    {
                        count += 1;
                    }
                }

                return count;
            }
        }

        /// <summary>
        /// The function pointer native is given, once, for the process.
        /// </summary>
        /// <remarks>
        /// NOTHING may escape this method. A managed exception unwinding into
        /// C++ frames not compiled to expect it is undefined behaviour, not an
        /// error, so every path is caught here and turned into a counter the
        /// diagnostics can report. That is also what makes "one broken mod does
        /// not poison the others" true during dispatch: the loop on the native
        /// side simply continues to the next handle.
        /// </remarks>
        [UnmanagedCallersOnly(CallConvs = new[] { typeof(System.Runtime.CompilerServices.CallConvCdecl) })]
        internal static unsafe void Dispatch(int kind, ulong subscription,
                                             NativeBridge.MbStr a,
                                             NativeBridge.MbStr b, int phase)
        {
            try
            {
                Registration registration;
                lock (Gate)
                {
                    if (!Registrations.TryGetValue(subscription, out registration))
                    {
                        // The handle was forgotten between native capturing it
                        // and this call. Not an error: it is exactly what an
                        // unload looks like from here.
                        Orphaned += 1;
                        return;
                    }
                }

                string first = a.ToString();
                string second = b.ToString();

                switch (kind)
                {
                    case DispatchEvent:
                        ((Action<string, string>)registration.Callback)(first, second);
                        break;
                    case DispatchInput:
                        ((Action<string, int>)registration.Callback)(first, phase);
                        break;
                    case DispatchCommand:
                        ((Action<string>)registration.Callback)(second);
                        break;
                    default:
                        return;
                }

                registration.Invocations += 1;
                Delivered += 1;
            }
            catch (Exception)
            {
                // Contained. The mod that faulted is not identified here on
                // purpose: doing so would mean touching the registration again
                // after an arbitrary failure. The native side counts the fault
                // against the owning mod, which it can do safely.
                Faults += 1;
            }
        }

        internal static void ResetCounters()
        {
            Delivered = 0;
            Orphaned = 0;
            Faults = 0;
        }
    }
}
