/**
 * demo.mjs -- node demo for the Engrail WASM build.
 * Exercises: Ed25519, SM2, SM3, and the full license issue->verify
 * cycle, all inside WebAssembly.
 *
 * Run: node demo.mjs   (after build.sh)
 */

import { Engrail } from "./engrail_wasm.mjs";

const hex = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
let failed = 0;
const ok = (name, cond) => {
    console.log(`${cond ? "  [PASS]" : "  [FAIL]"} ${name}`);
    if (!cond) failed++;
};

const eng = await Engrail.load();
console.log("engrail-wasm demo (node)");

/* SM3 standard vector */
ok("SM3(\"abc\") GB/T 32905",
   hex(eng.sm3(new TextEncoder().encode("abc"))) ===
   "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");

/* Ed25519: keypair -> sign -> verify -> tamper */
const kp = eng.ed25519Keypair();
const msg = new TextEncoder().encode("wasm works");
const sig = eng.ed25519Sign(msg, kp.privkey);
ok("Ed25519 sign/verify", eng.ed25519Verify(sig, msg, kp.pubkey));
sig[0] ^= 1;
ok("Ed25519 tamper rejected", !eng.ed25519Verify(sig, msg, kp.pubkey));

/* SM2: keypair -> sign/verify + encrypt/decrypt */
const s2 = eng.sm2Keypair();
const m2 = new TextEncoder().encode("国密 in the browser");
const sig2 = eng.sm2Sign(m2, s2.priv);
ok("SM2 sign/verify", eng.sm2Verify(sig2, m2, s2.pub));
const ct = eng.sm2Encrypt(s2.pub, m2);
ok("SM2 encrypt/decrypt round-trip",
   hex(eng.sm2Decrypt(ct, s2.priv)) === hex(m2));

/* License engine: issue -> encode -> verify -> tamper -> expired */
const machine = new Uint8Array(16).fill(7);
const days = 30;
const { payload, sig: lsig } =
    eng.licenseMake(kp.privkey, 42, machine, 27340, false, 0xffff);
const code = eng.licenseEncode(payload, lsig);
console.log(`  license code: ${code.slice(0, 30)}...`);
const now = Math.floor(Date.now() / 1000);
const v = eng.licenseVerify(code, kp.pubkey, 42, machine, now);
ok("license verify ok", v.ok && v.info.features === 0xffff);
const bad = eng.licenseVerify(code, kp.pubkey, 43, machine, now);
ok("wrong product rejected", !bad.ok && bad.status === -4);
const tampered = code.replace(/[^-]/, c =>
    c === "A" ? "B" : "A");
ok("tampered code rejected", !eng.licenseVerify(tampered, kp.pubkey, 42,
                                                machine, now).ok);

/* Offline tokens with TTL */
const token = eng.tokenCreate(kp.privkey, 42,
                              new TextEncoder().encode("premium-tier"),
                              3600);
const tv = eng.tokenVerify(token, kp.pubkey, 42, now + 3599);
ok("token valid inside TTL",
   tv.ok && new TextDecoder().decode(tv.payload) === "premium-tier");
ok("token expired after TTL",
   !eng.tokenVerify(token, kp.pubkey, 42, now + 3601).ok);

if (failed === 0) {
    console.log("engrail-wasm: ALL DEMO CHECKS PASSED");
} else {
    console.log(`engrail-wasm: ${failed} CHECK(S) FAILED`);
    process.exit(1);
}
