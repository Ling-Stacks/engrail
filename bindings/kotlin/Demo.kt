// MIT License -- ActivationSystem Kotlin bindings demo.
//
// Kotlin rides on the same JNI library as the Java bindings
// (bindings/java/libactivation_jni.so) -- 100% interop, zero extra
// native code. Also works on Android: ship the same .so in
// app/src/main/jniLibs/<abi>/ and drop Activation.java (+ Demo.kt
// logic) into your Kotlin sources.
//
// Desktop run (from bindings/java, after building libactivation_jni.so):
//   kotlinc ../kotlin/Demo.kt Activation.java -include-runtime -d demo.jar
//   java -cp demo.jar -Djava.library.path=. DemoKt


fun main() {
    // Demo deployment (public values from `engrail-keygen keygen`).
    val pubkey = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
    val dsalt = "00".repeat(32)

    val act = Activation(pubkey, dsalt, 1)
    println("machine code : ${act.machineCode()}")

    // SM2 national cryptography from Kotlin
    val kp = Activation.sm2KeyPair()
    val msg = "hello SM2 from kotlin".toByteArray()
    val sig = Activation.sm2Sign(kp.privHex, msg)
    println("sm2 sign/ver : " +
        if (Activation.sm2Verify(kp.pubHex, msg, sig)) "ok" else "FAIL")
    val ct = Activation.sm2Encrypt(kp.pubHex, "secret".toByteArray())
    println("sm2 enc/dec  : " +
        ("secret" == String(Activation.sm2Decrypt(kp.privHex, ct))))

    // License lifecycle
    val state = "demo_kotlin.act"
    val st = act.verifySaved(state)
    println("saved state  : $st")

    println("community    : https://t.me/Stack_Traces")
}
