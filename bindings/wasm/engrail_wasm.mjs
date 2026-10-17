/**
 * engrail_wasm.mjs -- clean ES-module API over the Engrail WebAssembly
 * build (crypto suite + license engine, no file system access).
 *
 *     import { Engrail } from "./engrail_wasm.mjs";
 *     const eng = await Engrail.load();
 *     const kp  = eng.ed25519Keypair();
 *     const sig = eng.ed25519Sign(msg, kp.privkey);
 *     eng.ed25519Verify(sig, msg, kp.pubkey);   // true
 *
 * Works in browsers and node (Emscripten MODULARIZE build).
 *
 * MIT licensed -- Copyright (c) 2026 Engrail Contributors.
 * Community: https://t.me/Stack_Traces
 */

import createModule from "./dist/engrail_wasm.js";

export class Engrail {
    #mod;

    constructor(mod) {
        this.#mod = mod;
    }

    /** Instantiate the wasm module (async; call once). */
    static async load() {
        return new Engrail(await createModule());
    }

    /* -- internal: heap views -------------------------------------- */

    #u8(ptr, len) {
        return new Uint8Array(this.#mod.HEAPU8.buffer, ptr, len);
    }

    #alloc(bytes) {
        /* +1 byte and a NUL terminator: several exported functions take
         * `const char *` and strlen() the buffer (license/token text).
         * Without it they read past the heap block -- UB, intermittently
         * failing with ACT_ERR_FORMAT (B15). */
        const ptr = this.#mod._malloc(bytes.length + 1);
        if (ptr === 0) {
            throw new Error("engrail: out of memory");
        }
        this.#u8(ptr, bytes.length).set(bytes);
        this.#mod.HEAPU8[ptr + bytes.length] = 0;
        return ptr;
    }

    #take(ptr, len) {
        const out = new Uint8Array(len);
        out.set(this.#u8(ptr, len));
        return out;
    }

    /* -- hashes ----------------------------------------------------- */

    sha512(data) {
        const p = this.#alloc(data);
        const out = this.#mod._malloc(64);
        this.#mod._act_sha512(p, data.length, out);
        const d = this.#take(out, 64);
        this.#mod._free(p);
        this.#mod._free(out);
        return d;
    }

    hmacSha512(key, data) {
        const kp = this.#alloc(key);
        const dp = this.#alloc(data);
        const out = this.#mod._malloc(64);
        this.#mod._act_hmac_sha512(kp, key.length, dp, data.length, out);
        const d = this.#take(out, 64);
        [kp, dp, out].forEach(x => this.#mod._free(x));
        return d;
    }

    sm3(data) {
        const p = this.#alloc(data);
        const out = this.#mod._malloc(32);
        this.#mod._act_sm3(p, data.length, out);
        const d = this.#take(out, 32);
        this.#mod._free(p);
        this.#mod._free(out);
        return d;
    }

    /* -- Ed25519 ----------------------------------------------------- */

    ed25519Keypair(seed) {
        const sp = seed ? this.#alloc(seed) : 0;
        const pk = this.#mod._malloc(32);
        const sk = this.#mod._malloc(64);
        this.#mod._act_ed25519_keypair(sp, pk, sk);
        const pair = { pubkey: this.#take(pk, 32), privkey: this.#take(sk, 64) };
        if (sp) this.#mod._free(sp);
        [pk, sk].forEach(x => this.#mod._free(x));
        return pair;
    }

    ed25519Sign(msg, privkey) {
        const mp = this.#alloc(msg);
        const sp = this.#alloc(privkey);
        const out = this.#mod._malloc(64);
        this.#mod._act_ed25519_sign(out, mp, msg.length, sp);
        const sig = this.#take(out, 64);
        [mp, sp, out].forEach(x => this.#mod._free(x));
        return sig;
    }

    /** @return true when the signature is valid. */
    ed25519Verify(sig, msg, pubkey) {
        const gp = this.#alloc(sig);
        const mp = this.#alloc(msg);
        const pp = this.#alloc(pubkey);
        const r = this.#mod._act_ed25519_verify(gp, mp, msg.length, pp);
        [gp, mp, pp].forEach(x => this.#mod._free(x));
        return r === 0;
    }

    /* -- SM2 ---------------------------------------------------------- */

    sm2Keypair(seed) {
        const sp = seed ? this.#alloc(seed) : 0;
        const pub = this.#mod._malloc(64);
        const priv = this.#mod._malloc(32);
        this.#mod._act_sm2_keypair(sp, pub, priv);
        const pair = { pub: this.#take(pub, 64), priv: this.#take(priv, 32) };
        if (sp) this.#mod._free(sp);
        [pub, priv].forEach(x => this.#mod._free(x));
        return pair;
    }

    sm2Sign(msg, priv, id) {
        const mp = this.#alloc(msg);
        const pp = this.#alloc(priv);
        const ip = id ? this.#alloc(new TextEncoder().encode(id)) : 0;
        const out = this.#mod._malloc(64);
        const r = this.#mod._act_sm2_sign(out, mp, msg.length, pp, ip);
        const sig = r === 0 ? this.#take(out, 64) : null;
        [mp, pp, ip, out].filter(Boolean).forEach(x => this.#mod._free(x));
        return sig;
    }

    /** @return true when the signature is valid. */
    sm2Verify(sig, msg, pub, id) {
        const gp = this.#alloc(sig);
        const mp = this.#alloc(msg);
        const pp = this.#alloc(pub);
        const ip = id ? this.#alloc(new TextEncoder().encode(id)) : 0;
        const r = this.#mod._act_sm2_verify(gp, mp, msg.length, pp, ip);
        [gp, mp, pp, ip].filter(Boolean).forEach(x => this.#mod._free(x));
        return r === 0;
    }

    /** SM2 encrypt (C1C3C2). @return ciphertext bytes or null. */
    sm2Encrypt(pub, msg) {
        const pp = this.#alloc(pub);
        const mp = this.#alloc(msg);
        const out = this.#mod._malloc(97 + msg.length);
        const lenP = this.#mod._malloc(8);
        const r = this.#mod._act_sm2_encrypt(pp, mp, msg.length, out,
                                             97 + msg.length, lenP);
        let ct = null;
        if (r === 0) {
            const dv = new DataView(this.#mod.HEAPU8.buffer);
            ct = this.#take(out, dv.getUint32(lenP, true));
        }
        [pp, mp, out, lenP].forEach(x => this.#mod._free(x));
        return ct;
    }

    /** SM2 decrypt. @return plaintext bytes or null. */
    sm2Decrypt(ct, priv) {
        const cp = this.#alloc(ct);
        const pp = this.#alloc(priv);
        const out = this.#mod._malloc(ct.length);
        const lenP = this.#mod._malloc(8);
        const r = this.#mod._act_sm2_decrypt(cp, ct.length, pp, out,
                                             ct.length, lenP);
        let pt = null;
        if (r === 0) {
            const dv = new DataView(this.#mod.HEAPU8.buffer);
            pt = this.#take(out, dv.getUint32(lenP, true));
        }
        [cp, pp, out, lenP].forEach(x => this.#mod._free(x));
        return pt;
    }

    /* -- license engine (browser-safe: no file system) --------------- */

    /**
     * Issue a license (vendor side, in the browser/node).
     * @param privkey  64-byte Ed25519 private key
     * @param machineCode 16-byte machine fingerprint the code binds to
     */
    licenseMake(privkey, productId, machineCode, expiryDays, perpetual,
                features) {
        const sk = this.#alloc(privkey);
        const mc = this.#alloc(machineCode);
        const payload = this.#mod._malloc(36);
        const sig = this.#mod._malloc(64);
        this.#mod._act_license_make(payload, sig, productId >>> 0, mc,
                                    expiryDays >>> 0,
                                    perpetual ? 1 : 0, 0, features | 0, sk);
        const out = { payload: this.#take(payload, 36),
                      sig: this.#take(sig, 64) };
        [sk, mc, payload, sig].forEach(x => this.#mod._free(x));
        return out;
    }

    /** payload+sig -> activation code string ("XXXXX-XXXXX-..."). */
    licenseEncode(payload, sig) {
        const pp = this.#alloc(payload);
        const sp = this.#alloc(sig);
        const out = this.#mod._malloc(200);
        const r = this.#mod._act_license_encode(pp, sp, out, 200);
        const s = r === 0 ? this.#mod.UTF8ToString(out) : null;
        [pp, sp, out].forEach(x => this.#mod._free(x));
        return s;
    }

    /**
     * Verify an activation code entirely in wasm.
     * @return {ok, status, info?} -- info carries serial/features/days.
     */
    licenseVerify(code, pubkey, productId, machineCode, nowUnix) {
        const enc = new TextEncoder();
        const bytes = enc.encode(code);
        const cp = this.#alloc(bytes);
        const pp = this.#alloc(pubkey);
        const mc = this.#alloc(machineCode);
        /* act_license_info: u32 + u8[16] + u32 + u8 + int*2 + u8[8] + u16 */
        const info = this.#mod._malloc(64);
        const r = this.#mod._act_license_verify(cp, pp, productId >>> 0, mc,
                                                BigInt(nowUnix), info);
        [cp, pp, mc].forEach(x => this.#mod._free(x));
        const result = { ok: r === 0, status: r };
        if (r === 0) {
            /* act_license_info layout (32-bit wasm, little-endian):
             * u32 product_id @0; u8[16] machine @4; u32 expiry @20;
             * u8 flags @24; int perpetual @28; int trial @32;
             * u8[8] serial @36; u16 features @44 */
            const dv = new DataView(this.#mod.HEAPU8.buffer);
            result.info = {
                productId: dv.getUint32(info, true),
                expiryDays: dv.getUint32(info + 20, true),
                flags: this.#mod.HEAPU8[info + 24],
                perpetual: dv.getInt32(info + 28, true) !== 0,
                trial: dv.getInt32(info + 32, true) !== 0,
                serial: this.#take(info + 36, 8),
                features: dv.getUint16(info + 44, true),
            };
        }
        this.#mod._free(info);
        return result;
    }

    /* -- signed offline tokens ---------------------------------------- */

    tokenCreate(privkey, productId, payload, ttlSeconds) {
        const sk = this.#alloc(privkey);
        const pp = this.#alloc(payload);
        const out = this.#mod._malloc(8192);
        const r = this.#mod._act_token_create(sk, productId >>> 0, pp,
                                              payload.length, ttlSeconds >>> 0,
                                              out, 8192);
        const tok = r === 0 ? this.#mod.UTF8ToString(out) : null;
        [sk, pp, out].forEach(x => this.#mod._free(x));
        return tok;
    }

    /** @return {ok, status, payload?} */
    tokenVerify(token, pubkey, productId, nowUnix) {
        const enc = new TextEncoder();
        const tp = this.#alloc(enc.encode(token));
        const pp = this.#alloc(pubkey);
        const out = this.#mod._malloc(4096);
        const lenP = this.#mod._malloc(8);
        const r = this.#mod._act_token_verify(tp, pp, productId >>> 0,
                                              BigInt(nowUnix), out, 4096,
                                              lenP, 0);
        const dv = new DataView(this.#mod.HEAPU8.buffer);
        const res = { ok: r === 0, status: r };
        if (r === 0) {
            res.payload = this.#take(out, dv.getUint32(lenP, true));
        }
        [tp, pp, out, lenP].forEach(x => this.#mod._free(x));
        return res;
    }
}

export default Engrail;
