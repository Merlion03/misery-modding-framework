using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Misery.ModHost
{
    /// <summary>
    /// The raw boundary. Every unsafe construct in the framework lives behind
    /// this type and nothing above it ever sees one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Misery.ModAPI -- what mods compile against -- has no P/Invoke, no IntPtr
    /// and no unsafe code, and a test asserts that. That split is the whole
    /// point of having two assemblies: the interop has to exist somewhere, and
    /// "somewhere" must not be third-party mod code.
    /// </para>
    /// <para>
    /// Function pointers rather than <c>DllImport</c>, because the bridge is
    /// reached through a table returned by one exported symbol. A wide DllImport
    /// surface would make a missing export a TypeLoadException at an arbitrary
    /// later moment; one symbol plus a table makes a version mismatch a clean,
    /// readable refusal at acquire time.
    /// </para>
    /// </remarks>
    internal static unsafe class NativeBridge
    {
        internal const uint AbiEpoch = 1;

        // Mirrors MbStr. Counted UTF-8, never assumed NUL-terminated.
        [StructLayout(LayoutKind.Sequential)]
        internal struct MbStr
        {
            public byte* Data;
            public int Length;

            public override string ToString()
            {
                if (Data == null || Length <= 0)
                {
                    return string.Empty;
                }

                return Encoding.UTF8.GetString(Data, Length);
            }
        }

        // Mirrors MbError.
        [StructLayout(LayoutKind.Sequential)]
        internal struct MbError
        {
            public int Subsystem;
            public int Code;
            public MbStr Detail;
            public MbStr ModId;
        }

        // Mirrors the FROZEN MbRoot. Its size is asserted against the header's
        // MB_ROOT_EXPECTED_SIZE, because a silent mismatch here would be two
        // sides reading different fields of the same memory.
        [StructLayout(LayoutKind.Sequential)]
        internal struct MbRoot
        {
            public uint StructSize;
            public uint AbiEpoch;
            public uint ApiMajor;
            public uint ApiMinor;
            public delegate* unmanaged[Cdecl]<byte*, int, uint*, uint*, int> QueryCapability;
            public delegate* unmanaged[Cdecl]<ulong, byte*, int, uint, void**, MbError*, int> AcquireCapability;
            public delegate* unmanaged[Cdecl]<MbError*, int> LastError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct MbLogTable
        {
            public uint StructSize;
            public uint VersionMajor;
            public uint VersionMinor;
            public delegate* unmanaged[Cdecl]<ulong, int, MbStr, MbStr, MbError*, int> Write;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct MbEventsTable
        {
            public uint StructSize;
            public uint VersionMajor;
            public uint VersionMinor;
            public delegate* unmanaged[Cdecl]<ulong, MbStr, MbStr, ulong*, MbError*, int> Declare;
            public delegate* unmanaged[Cdecl]<ulong, MbStr, ulong*, MbError*, int> Subscribe;
            public delegate* unmanaged[Cdecl]<ulong, MbError*, int> Unsubscribe;
            public delegate* unmanaged[Cdecl]<ulong, MbStr, MbStr, int*, MbError*, int> Publish;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct MbItemsTable
        {
            public uint StructSize;
            public uint VersionMajor;
            public uint VersionMinor;
            public delegate* unmanaged[Cdecl]<ulong, MbStr, MbStr*, ulong*, MbError*, int> RegisterItem;
            public delegate* unmanaged[Cdecl]<ulong, MbError*, int> UnregisterItem;
            // v2. Present only when the table reports version >= 2, which
            // is why the caller checks before reaching past UnregisterItem.
            public delegate* unmanaged[Cdecl]<ulong, int, int*, MbError*, int> GrantItem;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct MbServicesTable
        {
            public uint StructSize;
            public uint VersionMajor;
            public uint VersionMinor;
            public delegate* unmanaged[Cdecl]<ulong, MbStr, MbStr, MbStr, ulong*, MbError*, int> Publish;
            public delegate* unmanaged[Cdecl]<ulong, MbStr, MbStr, ulong*, MbError*, int> Bind;
            public delegate* unmanaged[Cdecl]<ulong, int*, MbError*, int> IsAvailable;
            public IntPtr Call;
            public IntPtr Release;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct MbSettingsTable
        {
            public uint StructSize;
            public uint VersionMajor;
            public uint VersionMinor;
            public delegate* unmanaged[Cdecl]<ulong, MbStr, MbError*, int> Declare;
            public IntPtr GetBool;
            public IntPtr GetInt;
            public IntPtr GetFloat;
            public IntPtr GetString;
            public IntPtr SetBool;
            public IntPtr SetInt;
            public IntPtr SetFloat;
            public IntPtr SetString;
            public IntPtr Save;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct MbDiagnosticsTable
        {
            public uint StructSize;
            public uint VersionMajor;
            public uint VersionMinor;
            public delegate* unmanaged[Cdecl]<MbStr*, MbError*, int> Snapshot;
            public delegate* unmanaged[Cdecl]<MbStr, int*, MbError*, int> ModState;
            public delegate* unmanaged[Cdecl]<MbStr, int*, MbStr*, MbError*, int> ModIsReclaimable;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct MbHostTable
        {
            public uint StructSize;
            public uint VersionMajor;
            public uint VersionMinor;
            public delegate* unmanaged[Cdecl]<delegate* unmanaged[Cdecl]<int, ulong, MbStr, MbStr, int, void>, MbError*, int> SetTrampoline;
            public delegate* unmanaged[Cdecl]<MbStr, MbStr, MbStr, MbStr, ulong*, MbStr*, MbError*, int> ModBegin;
            public delegate* unmanaged[Cdecl]<ulong, MbError*, int> ModLoaded;
            public delegate* unmanaged[Cdecl]<ulong, MbStr, MbError*, int> ModFailed;
            public delegate* unmanaged[Cdecl]<ulong, MbStr*, MbError*, int> ModUnload;
            public delegate* unmanaged[Cdecl]<MbStr*, MbError*, int> Shutdown;
        }

        /// <summary>
        /// Pins a UTF-8 copy of a string for the duration of one call. IN
        /// parameters are borrowed by contract, so the native side must not keep
        /// them -- and it does not: it copies anything it stores.
        /// </summary>
        internal readonly struct Utf8 : IDisposable
        {
            private readonly IntPtr _buffer;
            private readonly int _length;

            public Utf8(string text)
            {
                if (text == null)
                {
                    _buffer = IntPtr.Zero;
                    _length = 0;
                    return;
                }

                byte[] bytes = Encoding.UTF8.GetBytes(text);
                _buffer = Marshal.AllocHGlobal(bytes.Length + 1);
                Marshal.Copy(bytes, 0, _buffer, bytes.Length);
                Marshal.WriteByte(_buffer, bytes.Length, 0);
                _length = bytes.Length;
            }

            public MbStr Str => new MbStr
            {
                Data = (byte*)_buffer,
                Length = _length
            };

            public void Dispose()
            {
                if (_buffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(_buffer);
                }
            }
        }

        /// <summary>
        /// Turns a failing status into a <see cref="ModException"/>.
        /// </summary>
        /// <remarks>
        /// This is the ONE place a native failure becomes a managed exception,
        /// and the direction only ever goes this way: an exception never travels
        /// back down. Every managed callback the native side can reach is
        /// wrapped by the trampoline, which catches before returning.
        /// </remarks>
        internal static void Check(int status, in MbError error, string what)
        {
            if (status == 0)
            {
                return;
            }

            string detail = error.Detail.ToString();
            string modId = error.ModId.ToString();
            throw new ModAPI.ModException(
                (ModAPI.ModSubsystem)(error.Subsystem == 0 ? 1 : error.Subsystem),
                error.Code,
                string.IsNullOrEmpty(detail) ? what + " failed with status " + status : detail,
                string.IsNullOrEmpty(modId) ? default : new ModAPI.ModId(modId));
        }
    }
}
