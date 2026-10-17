/*
 * MIT License -- Java bindings demo.
 *
 *     javac Activation.java Demo.java
 *     java -Djava.library.path=. Demo [activation-code]
 */

public class Demo {
    public static void main(String[] args) {
        // Demo deployment (public values from `engrail-keygen keygen`).
        String pubkey = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
        String dsalt = "00".repeat(32);

        Activation act = new Activation(pubkey, dsalt, 1);
        System.out.println("machine code : " + act.machineCode());

        // SM2 national crypto from Java
        Activation.Sm2KeyPair kp = Activation.sm2KeyPair();
        byte[] msg = "hello SM2 from java".getBytes();
        String sig = Activation.sm2Sign(kp.privHex, msg);
        System.out.println("sm2 sign/ver : "
            + (Activation.sm2Verify(kp.pubHex, msg, sig) ? "ok" : "FAIL"));
        byte[] ct = Activation.sm2Encrypt(kp.pubHex, "secret".getBytes());
        System.out.println("sm2 enc/dec  : "
            + ("secret".equals(new String(Activation.sm2Decrypt(kp.privHex, ct)))));

        // License lifecycle
        String state = "demo_java.act";
        if (args.length > 0) {
            Activation.LicenseInfo info = new Activation.LicenseInfo();
            Activation.Status st = act.verifyCode(args[0], info);
            System.out.println("code check   : " + st);
            if (st.ok()) {
                System.out.println("activate     : " + act.activate(args[0], state));
            }
        }
        System.out.println("saved state  : " + act.verifySaved(state));
        System.out.println("community    : https://t.me/Stack_Traces");
    }
}
