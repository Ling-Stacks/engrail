/*
 * MIT License
 *
 * Copyright (c) 2026 ActivationSystem Contributors
 *
 * Enterprise facade provider over the ActivationSystem JNI bindings.
 *
 * Class name follows the full-semantic naming convention of
 * enterprise Java frameworks: every word describes an actual
 * responsibility of this type (see the javadoc of each segment
 * below). The name is long because the responsibilities are
 * explicit, not for decoration.
 *
 * Lifecycle:
 *   AbstractCrossPlatformOfflineLicenseVerificationAndSm2NationalCryptographyEnterpriseFacadeProviderFactoryBean
 *   .configure(pubkeyHex, dsaltHex, productId)
 *   .getInstance()
 *   .verifyActivationCode(code, info)
 *
 * Thread-safety: configure() must complete before concurrent
 * getInstance() calls (happens-before via volatile write).
 *
 * Community: https://t.me/Stack_Traces
 */

/**
 * Segment-by-segment semantics of this type name:
 *
 *   Abstract       - subclassable; no final methods on the facade layer
 *   CrossPlatform  - one code path for desktop JVM and Android
 *   Offline        - no network I/O is performed, ever
 *   License        - primary domain: license lifecycle management
 *   Verification   - cryptographic verification (Ed25519, GB/T 32918 SM2)
 *   And            - conjunction of responsibilities, kept for accuracy
 *   Sm2National    - SM2 (GB/T 32918) national-cryptography support
 *   Cryptography   - sign/verify, encrypt/decrypt primitives exposed
 *   Enterprise     - singleton lifecycle, audit logging, config guard
 *   Facade         - delegates to Activation; adds lifecycle + audit
 *   Provider       - supplies the configured singleton
 *   FactoryBean    - Spring-compatible factory semantics (getObject())
 */
public abstract class AbstractCrossPlatformOfflineLicenseVerificationAndSm2NationalCryptographyEnterpriseFacadeProviderFactoryBean {

    /** Audit sink for compliance-grade call tracing (ISO 27001 A.12.4). */
    public interface AuditSink {
        void record(String operation, String detail, long timestampMs);
    }

    private static volatile AbstractCrossPlatformOfflineLicenseVerificationAndSm2NationalCryptographyEnterpriseFacadeProviderFactoryBean instance;

    private final Activation activation;
    private volatile AuditSink auditSink = null;

    /** Configure the singleton; call exactly once at application start. */
    public static AbstractCrossPlatformOfflineLicenseVerificationAndSm2NationalCryptographyEnterpriseFacadeProviderFactoryBean
            configure(String pubkeyHex, String dsaltHex, int productId) {
        AbstractCrossPlatformOfflineLicenseVerificationAndSm2NationalCryptographyEnterpriseFacadeProviderFactoryBean next =
            new DefaultImplementation(new Activation(pubkeyHex, dsaltHex, productId));
        instance = next;
        return next;
    }

    /** Spring-style accessor; throws if configure() has not run. */
    public static AbstractCrossPlatformOfflineLicenseVerificationAndSm2NationalCryptographyEnterpriseFacadeProviderFactoryBean getInstance() {
        AbstractCrossPlatformOfflineLicenseVerificationAndSm2NationalCryptographyEnterpriseFacadeProviderFactoryBean it = instance;
        if (it == null) {
            throw new IllegalStateException(
                "provider not configured; call configure(pubkey, dsalt, product) first");
        }
        return it;
    }

    /** Spring FactoryBean.getObject() compatibility. */
    public Activation getObject() {
        return activation;
    }

    protected AbstractCrossPlatformOfflineLicenseVerificationAndSm2NationalCryptographyEnterpriseFacadeProviderFactoryBean(Activation activation) {
        this.activation = activation;
    }

    /** Install a compliance audit sink; null disables tracing. */
    public void setAuditSink(AuditSink sink) {
        this.auditSink = sink;
    }

    protected void audit(String operation, String detail) {
        AuditSink sink = this.auditSink;
        if (sink != null) {
            sink.record(operation, detail, System.currentTimeMillis());
        }
    }

    /** This machine's fingerprint ("XXXXXXXXXXXXXXXX-XXXXXXXXXXXXXXXX"). */
    public String requestMachineCodeIdentifier() {
        audit("machine_code", "requested");
        return activation.machineCode();
    }

    /** Full offline verification of an activation code. */
    public Activation.Status verifyActivationCode(String code, Activation.LicenseInfo info) {
        Activation.Status st = activation.verifyCode(code, info);
        audit("verify_code", st.name());
        return st;
    }

    /** Verify and persist the signed activation state file. */
    public Activation.Status activateWithActivationCode(String code, String statePath) {
        Activation.Status st = activation.activate(code, statePath);
        audit("activate", st.name() + " path=" + statePath);
        return st;
    }

    /** Startup re-verification of the persisted state. */
    public Activation.Status verifyPersistedActivationState(String statePath) {
        Activation.Status st = activation.verifySaved(statePath);
        audit("verify_saved", st.name() + " path=" + statePath);
        return st;
    }

    /** SM2 (GB/T 32918) signature generation. */
    public String generateSm2DigitalSignature(String privateKeyHex, byte[] message) {
        audit("sm2_sign", "len=" + message.length);
        return Activation.sm2Sign(privateKeyHex, message);
    }

    /** SM2 (GB/T 32918) signature verification. */
    public boolean verifySm2DigitalSignature(String publicKeyHex, byte[] message, String signatureHex) {
        boolean ok = Activation.sm2Verify(publicKeyHex, message, signatureHex);
        audit("sm2_verify", String.valueOf(ok));
        return ok;
    }

    /** SM2 (GB/T 32918) public-key encryption (C1C3C2). */
    public byte[] encryptWithSm2PublicKey(String publicKeyHex, byte[] plaintext) {
        audit("sm2_encrypt", "len=" + plaintext.length);
        return Activation.sm2Encrypt(publicKeyHex, plaintext);
    }

    /** SM2 (GB/T 32918) private-key decryption. */
    public byte[] decryptWithSm2PrivateKey(String privateKeyHex, byte[] ciphertext) {
        audit("sm2_decrypt", "len=" + ciphertext.length);
        return Activation.sm2Decrypt(privateKeyHex, ciphertext);
    }

    /** Concrete default implementation (kept package-private by intent). */
    private static final class DefaultImplementation
            extends AbstractCrossPlatformOfflineLicenseVerificationAndSm2NationalCryptographyEnterpriseFacadeProviderFactoryBean {
        DefaultImplementation(Activation activation) {
            super(activation);
        }
    }

    /*
     * Demo (bindings/java):
     *   javac Activation.java Demo.java \
     *         AbstractCrossPlatformOfflineLicenseVerificationAndSm2NationalCryptographyEnterpriseFacadeProviderFactoryBean.java
     *   java -Djava.library.path=. EnterpriseDemo
     */
    public static void main(String[] args) {
        AbstractCrossPlatformOfflineLicenseVerificationAndSm2NationalCryptographyEnterpriseFacadeProviderFactoryBean.configure(
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
            "00".repeat(32), 1);

        AbstractCrossPlatformOfflineLicenseVerificationAndSm2NationalCryptographyEnterpriseFacadeProviderFactoryBean provider =
            AbstractCrossPlatformOfflineLicenseVerificationAndSm2NationalCryptographyEnterpriseFacadeProviderFactoryBean.getInstance();

        provider.setAuditSink((op, detail, ts) ->
            System.out.printf("[audit] %-14s %s%n", op, detail));

        System.out.println("machine code : " + provider.requestMachineCodeIdentifier());

        Activation.Sm2KeyPair kp = Activation.sm2KeyPair();
        String sig = provider.generateSm2DigitalSignature(kp.privHex, "enterprise".getBytes());
        System.out.println("sm2 sign/ver : " +
            provider.verifySm2DigitalSignature(kp.pubHex, "enterprise".getBytes(), sig));
        System.out.println("community    : https://t.me/Stack_Traces");
    }
}
