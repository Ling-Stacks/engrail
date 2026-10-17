/**
 * bench.mjs -- WASM benchmark for the Engrail crypto suite.
 *
 * Run after build.sh produced dist/engrail_wasm.{js,wasm}:
 *     node bench.mjs
 *
 * Timing: performance.now() wall clock around fixed iteration counts
 * (same counts as crypto/bench/bench.c where meaningful).
 *
 * Paste real output into docs/BENCHMARKS.md -- never hand-edit numbers.
 */

import { Engrail } from "./engrail_wasm.mjs";

const eng = await Engrail.load();
const hex = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");

let failed = 0;
const ok = (name, cond) => {
    if (!cond) { console.log(`  sanity FAIL: ${name}`); failed++; }
};

function bench(name, iters, fn) {
    fn(); /* warmup + sanity path */
    const t0 = performance.now();
    for (let i = 0; i < iters; i++) fn();
    const ms = performance.now() - t0;
    console.log(`${name.padEnd(28)} ${String(iters).padStart(10)} iters ` +
                `${ms.toFixed(1).padStart(10)} ms ` +
                `${(ms * 1000 / iters).toFixed(3).padStart(11)} us/op`);
}

const small = new TextEncoder().encode(
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV");
const kp = eng.ed25519Keypair();
const sig = eng.ed25519Sign(small, kp.privkey);
ok("ed25519 verify sanity", eng.ed25519Verify(sig, small, kp.pubkey));

const s2 = eng.sm2Keypair();
const sig2 = eng.sm2Sign(small, s2.priv);
ok("sm2 verify sanity", eng.sm2Verify(sig2, small, s2.pub));
const ct = eng.sm2Encrypt(s2.pub, small.subarray(0, 32));
ok("sm2 decrypt sanity", eng.sm2Decrypt(ct, s2.priv) !== null);

const big = new Uint8Array(1 << 20).fill(0x42);

console.log("operation                     iters        total        per-op");
console.log("------------------------     ------       ------       -------");

bench("sha512/64B", 200000, () => eng.sha512(small));
bench("sha512/1MiB", 200, () => eng.sha512(big));
bench("sm3/64B", 200000, () => eng.sm3(small));
bench("ed25519/keypair", 200, () => eng.ed25519Keypair(kp.privkey.subarray(0, 32)));
bench("ed25519/sign/64B", 200, () => eng.ed25519Sign(small, kp.privkey));
bench("ed25519/verify/64B", 200, () => eng.ed25519Verify(sig, small, kp.pubkey));
bench("sm2/keypair", 200, () => eng.sm2Keypair(s2.priv));
bench("sm2/sign/64B", 200, () => eng.sm2Sign(small, s2.priv));
bench("sm2/verify/64B", 200, () => eng.sm2Verify(sig2, small, s2.pub));
bench("sm2/encrypt/32B", 200, () => eng.sm2Encrypt(s2.pub, small.subarray(0, 32)));
bench("sm2/decrypt/64B", 200, () => eng.sm2Decrypt(ct, s2.priv));

if (failed) {
    console.log(`\nbench: ${failed} SANITY FAILURE(S) -- results invalid`);
    process.exit(1);
}
console.log("\nbench(wasm): DONE");
