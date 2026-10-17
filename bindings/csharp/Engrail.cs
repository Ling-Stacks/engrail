//
// Engrail.cs -- C# / .NET binding for Engrail (offline licensing +
// SM2/SM3/Ed25519 crypto suite) via P/Invoke. Single file, no packages.
//
//     using Engrail;
//     var act = new Activation(pubkeyHex, dsaltHex, productId: 1);
//     Console.WriteLine(act.MachineCode());
//     var (ok, info) = act.VerifyCode("08000-...");
//     act.Activate("08000-...", "app.act");
//     Console.WriteLine(act.VerifySaved("app.act"));
//
// Native library: ./configure --enable-shared && make  produces
// libactivation.so (Linux/Android/macOS) / activation.dll (Windows).
// Resolution order: $ACTIVATION_LIB -> "activation" default probe.
//
// MIT licensed -- Copyright (c) 2026 Engrail Contributors.
// Community: https://t.me/Stack_Traces
//

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Engrail
{
    /// <summary>Verification outcome; truthy only when Ok.</summary>
    public enum Status
    {
        Ok = 0,
        BadArgument = -1,
        BadFormat = -2,
        BadVersion = -3,
        ProductMismatch = -4,
        BadSignature = -5,
        MachineMismatch = -6,
        Expired = -7,
        StateMissing = -8,
        StateIoError = -9,
        StateCorrupt = -10,
        Revoked = -11,
        DebuggerDetected = -12,
        IntegrityFailure = -13,
        VerificationMismatch = -14,
        EntropyFailure = -15,
    }

    /// <summary>Decoded license metadata.</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct LicenseInfo
    {
        public uint ProductId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] MachineCode;
        public uint ExpiryDays;
        public byte Flags;
        public int Perpetual;
        public int Trial;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Serial;
        public ushort Features;

        public bool IsPerpetual => Perpetual != 0;
        public bool IsTrial => Trial != 0;
    }

    /// <summary>Application-side verifier (mirrors act::Verifier).</summary>
    public sealed class Activation
    {
        const int PubkeySize = 32;
        const int DsaltSize = 32;
        const int MachineCodeSize = 16;
        const int CodeMaxChars = 200;

        readonly byte[] _pubkey;
        readonly byte[] _dsalt;
        readonly uint _productId;

        public Activation(string pubkeyHex, string dsaltHex, uint productId)
        {
            _pubkey = Hex.Decode(pubkeyHex, PubkeySize);
            _dsalt = Hex.Decode(dsaltHex, DsaltSize);
            _productId = productId;
        }

        /// <summary>This machine's code, "XXXXXXXX-XXXXXXXX".</summary>
        public string MachineCode()
        {
            var fp = new byte[MachineCodeSize];
            act_fingerprint(_pubkey, _dsalt, _productId, null, 0, fp);
            var sb = new StringBuilder(32);
            var hex = Hex.Encode(fp);
            sb.Append(hex, 0, 16).Append('-').Append(hex, 16, 16);
            return sb.ToString();
        }

        /// <summary>Verify a user-entered code (no persistence).</summary>
        public (Status status, LicenseInfo info) VerifyCode(string code)
        {
            var info = new LicenseInfo();
            var st = act_license_verify(code, _pubkey, _productId,
                                        MachineFingerprint(),
                                        DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                                        ref info);
            return ((Status)st, info);
        }

        /// <summary>Verify + persist activation state to disk.</summary>
        public Status Activate(string code, string statePath)
        {
            var (st, _) = VerifyCode(code);
            if (st != Status.Ok)
            {
                return st;
            }
            var payload = new byte[36];
            var sig = new byte[64];
            if (act_license_decode(code, payload, sig) != 0)
            {
                return Status.BadFormat;
            }
            return (Status)act_state_save(statePath, payload, sig);
        }

        /// <summary>Re-verify the saved state (call at every startup).</summary>
        public Status VerifySaved(string statePath)
        {
            return (Status)act_state_check(statePath, _pubkey, _productId,
                                           MachineFingerprint(),
                                           DateTimeOffset.UtcNow
                                                         .ToUnixTimeSeconds(),
                                           IntPtr.Zero);
        }

        byte[] MachineFingerprint()
        {
            var fp = new byte[MachineCodeSize];
            act_fingerprint(_pubkey, _dsalt, _productId, null, 0, fp);
            return fp;
        }

        [DllImport(Lib, CharSet = CharSet.Ansi)]
        static extern int act_fingerprint(byte[] pk, byte[] dsalt, uint pid,
                                          byte[] salt, ulong saltLen,
                                          [Out] byte[] fp);

        [DllImport(Lib, CharSet = CharSet.Ansi)]
        static extern int act_license_verify(string code, byte[] pk, uint pid,
                                             byte[] machine, long now,
                                             ref LicenseInfo info);

        [DllImport(Lib, CharSet = CharSet.Ansi)]
        static extern int act_state_check(string path, byte[] pk, uint pid,
                                          byte[] machine, long now,
                                          IntPtr info);

        [DllImport(Lib, CharSet = CharSet.Ansi)]
        static extern int act_license_decode(string code,
                                             [Out] byte[] payload,
                                             [Out] byte[] sig);

        [DllImport(Lib, CharSet = CharSet.Ansi)]
        static extern int act_state_save(string path, byte[] payload,
                                         byte[] sig);

        internal const string Lib = "activation";
    }

    /// <summary>Crypto primitives for direct use (vendor side included).</summary>
    public static class Crypto
    {
        /// <summary>Fresh Ed25519 keypair from the OS CSPRNG.</summary>
        public static (byte[] pub, byte[] priv) Ed25519Keypair()
        {
            var pub = new byte[32];
            var priv = new byte[64];
            act_ed25519_keypair(IntPtr.Zero, pub, priv);
            return (pub, priv);
        }

        public static byte[] Ed25519Sign(byte[] msg, byte[] priv)
        {
            var sig = new byte[64];
            act_ed25519_sign(sig, msg, (ulong)msg.Length, priv);
            return sig;
        }

        public static bool Ed25519Verify(byte[] sig, byte[] msg, byte[] pub)
        {
            return act_ed25519_verify(sig, msg, (ulong)msg.Length, pub) == 0;
        }

        public static byte[] Sm3(byte[] data)
        {
            var d = new byte[32];
            act_sm3(data, (ulong)data.Length, d);
            return d;
        }

        public static (byte[] pub, byte[] priv) Sm2Keypair()
        {
            var pub = new byte[64];
            var priv = new byte[32];
            act_sm2_keypair(IntPtr.Zero, pub, priv);
            return (pub, priv);
        }

        public static byte[] Sm2Sign(byte[] msg, byte[] priv, string id = null)
        {
            var sig = new byte[64];
            if (act_sm2_sign(sig, msg, (ulong)msg.Length, priv, id) != 0)
                return null;
            return sig;
        }

        public static bool Sm2Verify(byte[] sig, byte[] msg, byte[] pub,
                                     string id = null)
        {
            return act_sm2_verify(sig, msg, (ulong)msg.Length, pub, id) == 0;
        }

        public static byte[] Sm2Encrypt(byte[] pub, byte[] msg)
        {
            var ct = new byte[97 + msg.Length];
            ulong len = 0;
            unsafe
            {
                if (act_sm2_encrypt(pub, msg, (ulong)msg.Length, ct,
                                    (ulong)ct.Length, &len) != 0)
                    return null;
            }
            if (len == (ulong)ct.Length) return ct;
            var trimmed = new byte[len];
            Array.Copy(ct, trimmed, (long)len);
            return trimmed;
        }

        public static byte[] Sm2Decrypt(byte[] ct, byte[] priv)
        {
            var pt = new byte[Math.Max(1, ct.Length - 97)];
            ulong len = 0;
            unsafe
            {
                if (act_sm2_decrypt(ct, (ulong)ct.Length, priv, pt,
                                    (ulong)pt.Length, &len) != 0)
                    return null;
            }
            if (len == (ulong)pt.Length) return pt;
            var trimmed = new byte[len];
            Array.Copy(pt, trimmed, (long)len);
            return trimmed;
        }

        [DllImport(Activation.Lib)] static extern void act_ed25519_keypair(
            IntPtr seed, [Out] byte[] pk, [Out] byte[] priv);
        [DllImport(Activation.Lib)] static extern void act_ed25519_sign(
            [Out] byte[] sig, byte[] msg, ulong len, byte[] priv);
        [DllImport(Activation.Lib)] static extern int act_ed25519_verify(
            byte[] sig, byte[] msg, ulong len, byte[] pub);
        [DllImport(Activation.Lib)] static extern void act_sm3(
            byte[] data, ulong len, [Out] byte[] digest);
        [DllImport(Activation.Lib, CharSet = CharSet.Ansi)]
        static extern void act_sm2_keypair(
            IntPtr seed, [Out] byte[] pub, [Out] byte[] priv);
        [DllImport(Activation.Lib, CharSet = CharSet.Ansi)]
        static extern int act_sm2_sign(
            [Out] byte[] sig, byte[] msg, ulong len, byte[] priv, string id);
        [DllImport(Activation.Lib, CharSet = CharSet.Ansi)]
        static extern int act_sm2_verify(
            byte[] sig, byte[] msg, ulong len, byte[] pub, string id);
        [DllImport(Activation.Lib)]
        static unsafe extern int act_sm2_encrypt(
            byte[] pub, byte[] msg, ulong len, [Out] byte[] ct,
            ulong cap, ulong* outLen);
        [DllImport(Activation.Lib)]
        static unsafe extern int act_sm2_decrypt(
            byte[] ct, ulong len, byte[] priv, [Out] byte[] pt,
            ulong cap, ulong* outLen);
    }

    /// <summary>Vendor-side issuance (also usable from a vendor tool).</summary>
    public static class Vendor
    {
        public static string MakeLicense(byte[] priv, uint productId,
                                         byte[] machineCode, uint expiryDays,
                                         bool perpetual, ushort features)
        {
            var payload = new byte[36];
            var sig = new byte[64];
            act_license_make(payload, sig, productId, machineCode,
                             expiryDays, perpetual ? 1u : 0u, IntPtr.Zero,
                             features, priv);
            var sb = new StringBuilder(200);
            act_license_encode(payload, sig, sb, 200);
            return sb.ToString();
        }

        [DllImport(Activation.Lib)]
        static extern void act_license_make(
            [Out] byte[] payload, [Out] byte[] sig, uint pid, byte[] machine,
            uint expiry, uint flags, IntPtr serial, ushort features,
            byte[] priv);
        [DllImport(Activation.Lib)]
        static extern int act_license_encode(
            byte[] payload, byte[] sig, StringBuilder sb, ulong cap);
    }

    internal static class Hex
    {
        public static byte[] Decode(string hex, int expect)
        {
            if (hex == null || hex.Length != expect * 2)
                throw new ArgumentException(
                    $"expected {expect * 2} hex chars, got {hex?.Length ?? 0}");
            var b = new byte[expect];
            for (int i = 0; i < expect; i++)
                b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return b;
        }

        public static string Encode(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
    }
}
