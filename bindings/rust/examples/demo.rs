// MIT License -- ActivationSystem Rust bindings demo.
//
//     cargo run --example demo   (from bindings/rust)

fn main() {
    // Demo deployment (public values from `engrail-keygen keygen`).
    let pubkey = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
    let dsalt = "00".repeat(32);

    let act = activation::Activation::new(pubkey, &dsalt, 1).expect("bind");

    println!("machine code : {}", act.machine_code());

    // License lifecycle (no code supplied -> show startup state)
    match act.verify_saved("demo_rust.act") {
        activation::Status::Ok => println!("license      : ACTIVE"),
        st => println!("license      : {} ({})", st, st.text()),
    }

    // Offline national crypto
    let kp = activation::sm2_keypair();
    let msg = b"hello SM2 from rust";
    let sig = activation::sm2_sign(&kp.priv_hex, msg).expect("sign");
    println!(
        "sm2 sign/ver : {}",
        if activation::sm2_verify(&kp.pub_hex, msg, &sig) {
            "ok"
        } else {
            "FAIL"
        }
    );
    let ct = activation::sm2_encrypt(&kp.pub_hex, b"secret").expect("enc");
    println!(
        "sm2 enc/dec  : {}",
        activation::sm2_decrypt(&kp.priv_hex, &ct).as_deref() == Some(b"secret".as_ref())
    );

    println!("community    : https://t.me/Stack_Traces");
}
