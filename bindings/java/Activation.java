/*
 * MIT License
 *
 * Copyright (c) 2026 ActivationSystem Contributors
 *
 * Java bindings for ActivationSystem via a thin JNI layer over the
 * pure-C ABI. Works on desktop JVMs and Android (same .so).
 *
 * Build (from bindings/java, after ./configure --enable-shared && make):
 *   javac Activation.java Demo.java
 *   cc -shared -fPIC -I"$JAVA_HOME/include" \
 *      -I"$JAVA_HOME/include/linux" -I../../include \
 *      native/ActivationJNI.c [the C sources, see Makefile target "java"] \
 *      -o libactivation_jni.so
 *   java -Djava.library.path=. Demo
 *
 * Community: https://t.me/Stack_Traces
 */

import java.nio.file.Files;
import java.nio.file.Path;

public final class Activation {

    /** Verification outcome, 1:1 with the C act_status codes. */
    public enum Status {
        OK, BAD_ARGUMENT, BAD_FORMAT, BAD_VERSION, PRODUCT_MISMATCH,
        BAD_SIGNATURE, MACHINE_MISMATCH, EXPIRED, STATE_MISSING,
        STATE_IO, STATE_CORRUPT, REVOKED, DEBUGGER_DETECTED,
        INTEGRITY_FAILURE, VERIFICATION_MISMATCH, UNKNOWN;

        static Status of(int code) {
            switch (code) {
                case 0: return OK;
                case -1: return BAD_ARGUMENT;
                case -2: return BAD_FORMAT;
                case -3: return BAD_VERSION;
                case -4: return PRODUCT_MISMATCH;
                case -5: return BAD_SIGNATURE;
                case -6: return MACHINE_MISMATCH;
                case -7: return EXPIRED;
                case -8: return STATE_MISSING;
                case -9: return STATE_IO;
                case -10: return STATE_CORRUPT;
                case -11: return REVOKED;
                case -12: return DEBUGGER_DETECTED;
                case -13: return INTEGRITY_FAILURE;
                case -14: return VERIFICATION_MISMATCH;
                default: return UNKNOWN;
            }
        }

        public boolean ok() { return this == OK; }
    }

    /** Decoded license metadata. */
    public static final class LicenseInfo {
        public int productId;
        public String machineCode;   /* hex */
        public int expiryDays;
        public boolean perpetual;
        public boolean trial;
        public String serial;        /* hex */
        public int features;
    }

    static {
        String lib = System.getProperty("activation.lib", "activation_jni");
        try {
            System.loadLibrary(lib);
        } catch (UnsatisfiedLinkError e) {
            // fall back to an explicit path (dev workflow)
            try {
                System.load(System.getProperty("user.dir")
                            + java.io.File.separator + "libactivation_jni.so");
            } catch (UnsatisfiedLinkError e2) {
                throw new IllegalStateException(
                    "libactivation_jni.so not loadable: " + e2.getMessage()
                    + " (build it: see Activation.java header comment)", e2);
            }
        }
    }

    private final byte[] pubkey = new byte[32];
    private final byte[] dsalt = new byte[32];
    private final int productId;

    public Activation(String pubkeyHex, String dsaltHex, int productId) {
        byte[] pk = hex(pubkeyHex);
        byte[] ds = hex(dsaltHex);
        if (pk == null || pk.length != 32 || ds == null || ds.length != 32) {
            throw new IllegalArgumentException(
                "pubkey/dsalt must each be 64 hex chars");
        }
        System.arraycopy(pk, 0, pubkey, 0, 32);
        System.arraycopy(ds, 0, dsalt, 0, 32);
        this.productId = productId;
    }

    /** This machine's fingerprint, "XXXXXXXXXXXXXXXX-XXXXXXXXXXXXXXXX". */
    public String machineCode() {
        byte[] out = new byte[34];
        nMachineCode(pubkey, dsalt, productId, out);
        int end = 0;
        while (end < out.length && out[end] != 0) end++;
        return new String(out, 0, end);
    }

    /** Full offline verification; returns status, fills info on success. */
    public Status verifyCode(String code, LicenseInfo info) {
        byte[] mc = hex(machineCode().replace("-", ""));
        int rc = nVerifyCode(code.getBytes(), pubkey, productId, mc, info);
        return Status.of(rc);
    }

    /** Verify + persist the signed state file. */
    public Status activate(String code, String statePath) {
        byte[] mc = hex(machineCode().replace("-", ""));
        return Status.of(nActivate(code.getBytes(), pubkey, productId, mc,
                                   statePath.getBytes()));
    }

    /** Startup check of a saved state file. */
    public Status verifySaved(String statePath) {
        byte[] mc = hex(machineCode().replace("-", ""));
        return Status.of(nVerifySaved(statePath.getBytes(), pubkey,
                                      productId, mc));
    }

    // SM2 (GB/T 32918)

    public static final class Sm2KeyPair {
        public final String privHex;
        public final String pubHex;
        Sm2KeyPair(String p, String b) { privHex = p; pubHex = b; }
    }

    public static Sm2KeyPair sm2KeyPair() {
        byte[] pub = new byte[64];
        byte[] priv = new byte[32];
        nSm2Keypair(pub, priv);
        return new Sm2KeyPair(hex(priv), hex(pub));
    }

    /** SM2 sign -> hex signature, or null on failure. */
    public static String sm2Sign(String privHex, byte[] message) {
        byte[] sig = new byte[64];
        if (nSm2Sign(sig, message, hex(privHex)) != 0) return null;
        return hex(sig);
    }

    public static boolean sm2Verify(String pubHex, byte[] message, String sigHex) {
        return nSm2Verify(hex(sigHex), message, hex(pubHex)) == 0;
    }

    /** SM2 encrypt -> ciphertext bytes (C1C3C2), or null. */
    public static byte[] sm2Encrypt(String pubHex, byte[] message) {
        byte[] out = new byte[message.length + 97];
        long[] outLen = new long[1];
        if (nSm2Encrypt(hex(pubHex), message, out, outLen) != 0) return null;
        byte[] trim = new byte[(int) outLen[0]];
        System.arraycopy(out, 0, trim, 0, trim.length);
        return trim;
    }

    /** SM2 decrypt -> plaintext, or null on failure. */
    public static byte[] sm2Decrypt(String privHex, byte[] ciphertext) {
        byte[] out = new byte[Math.max(ciphertext.length - 97, 1)];
        long[] outLen = new long[1];
        if (nSm2Decrypt(ciphertext, hex(privHex), out, outLen) != 0) return null;
        byte[] trim = new byte[(int) outLen[0]];
        System.arraycopy(out, 0, trim, 0, trim.length);
        return trim;
    }

    // helpers

    static byte[] hex(String s) {
        if (s == null || s.length() % 2 != 0) return null;
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int v = Character.digit(s.charAt(2 * i), 16) * 16
                  + Character.digit(s.charAt(2 * i + 1), 16);
            if (v < 0) return null;
            out[i] = (byte) v;
        }
        return out;
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    // native

    private static native void nMachineCode(byte[] pubkey, byte[] dsalt,
                                            int productId, byte[] out);
    private static native int nVerifyCode(byte[] code, byte[] pubkey,
                                          int productId, byte[] machine,
                                          LicenseInfo info);
    private static native int nActivate(byte[] code, byte[] pubkey,
                                        int productId, byte[] machine,
                                        byte[] statePath);
    private static native int nVerifySaved(byte[] statePath, byte[] pubkey,
                                           int productId, byte[] machine);
    private static native void nSm2Keypair(byte[] pub, byte[] priv);
    private static native int nSm2Sign(byte[] sigOut, byte[] msg, byte[] priv);
    private static native int nSm2Verify(byte[] sig, byte[] msg, byte[] pub);
    private static native int nSm2Encrypt(byte[] pub, byte[] msg,
                                          byte[] out, long[] outLen);
    private static native int nSm2Decrypt(byte[] in, byte[] priv,
                                          byte[] out, long[] outLen);
}
