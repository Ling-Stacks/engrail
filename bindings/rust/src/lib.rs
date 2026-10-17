// MIT License
//
// Copyright (c) 2026 ActivationSystem Contributors
//
// Safe Rust bindings over the C ABI of ActivationSystem.
//
//     use activation::{Activation, Status};
//
//     let act = Activation::new(PUBKEY, DSALT, 1)?;
//     println!("{}", act.machine_code()?);
//     match act.verify_code("08000-...") {
//         (Status::Ok, Some(info)) => { /* licensed */ }
//         (st, _) => eprintln!("rejected: {}", st),
//     }
//
// Community: https://t.me/Stack_Traces

#![forbid(unsafe_op_in_unsafe_fn)]

use std::ffi::c_char;

// FFI

#[allow(non_camel_case_types)]
type act_status = i32;

const ACT_OK: act_status = 0;
const ACT_MACHINE_CODE_STR_SIZE: usize = 34;
const ACT_SM2_PUB_SIZE: usize = 64;
const ACT_SM2_PRIV_SIZE: usize = 32;
const ACT_SM2_SIG_SIZE: usize = 64;

extern "C" {
    fn act_fingerprint(
        pubkey: *const u8,
        dsalt: *const u8,
        product_id: u32,
        salt: *const u8,
        salt_len: usize,
        out16: *mut u8,
    );
    fn act_fp_to_string(code16: *const u8, buf: *mut c_char);
    fn act_license_verify(
        code: *const c_char,
        pubkey: *const u8,
        product_id: u32,
        machine_code: *const u8,
        now_unix: i64,
        info: *mut LicenseInfoRaw,
    ) -> act_status;
    fn act_state_save(
        path: *const c_char,
        payload: *const u8,
        sig: *const u8,
    ) -> act_status;
    fn act_license_decode(
        code: *const c_char,
        payload: *mut u8,
        sig: *mut u8,
    ) -> act_status;
    fn act_state_check(
        path: *const c_char,
        pubkey: *const u8,
        product_id: u32,
        machine_code: *const u8,
        now_unix: i64,
        info: *mut LicenseInfoRaw,
    ) -> act_status;
    fn act_sm2_keypair(seed: *mut u8, pub_: *mut u8, priv_: *mut u8);
    fn act_sm2_sign(
        sig: *mut u8,
        msg: *const u8,
        len: usize,
        priv_: *const u8,
        id: *const c_char,
    ) -> act_status;
    fn act_sm2_verify(
        sig: *const u8,
        msg: *const u8,
        len: usize,
        pub_: *const u8,
        id: *const c_char,
    ) -> act_status;
    fn act_sm2_encrypt(
        pub_: *const u8,
        msg: *const u8,
        len: usize,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
    ) -> act_status;
    fn act_sm2_decrypt(
        input: *const u8,
        in_len: usize,
        priv_: *const u8,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
    ) -> act_status;
}

#[repr(C)]
struct LicenseInfoRaw {
    product_id: u32,
    machine_code: [u8; 16],
    expiry_days: u32,
    flags: u8,
    perpetual: i32,
    trial: i32,
    serial: [u8; 8],
    features: u16,
}

// public API

/// Verification outcome. `Status::Ok` is success; each failure maps
/// 1:1 to the C `act_status` codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    BadArgument,
    BadFormat,
    BadVersion,
    ProductMismatch,
    BadSignature,
    MachineMismatch,
    Expired,
    StateMissing,
    StateIo,
    StateCorrupt,
    Revoked,
    DebuggerDetected,
    IntegrityFailure,
    VerificationMismatch,
    Other(i32),
}

impl Status {
    fn from_raw(v: act_status) -> Self {
        match v {
            0 => Status::Ok,
            -1 => Status::BadArgument,
            -2 => Status::BadFormat,
            -3 => Status::BadVersion,
            -4 => Status::ProductMismatch,
            -5 => Status::BadSignature,
            -6 => Status::MachineMismatch,
            -7 => Status::Expired,
            -8 => Status::StateMissing,
            -9 => Status::StateIo,
            -10 => Status::StateCorrupt,
            -11 => Status::Revoked,
            -12 => Status::DebuggerDetected,
            -13 => Status::IntegrityFailure,
            -14 => Status::VerificationMismatch,
            other => Status::Other(other),
        }
    }

    pub fn text(&self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::BadArgument => "bad argument",
            Status::BadFormat => "malformed activation code",
            Status::BadVersion => "unsupported license version",
            Status::ProductMismatch => "license issued for another product",
            Status::BadSignature => "signature check failed (forged or tampered)",
            Status::MachineMismatch => "license bound to another machine",
            Status::Expired => "license expired",
            Status::StateMissing => "no activation state found",
            Status::StateIo => "activation state i/o error",
            Status::StateCorrupt => "activation state corrupt",
            Status::Revoked => "license revoked",
            Status::DebuggerDetected => "debugger detected",
            Status::IntegrityFailure => "executable integrity failure",
            Status::VerificationMismatch => "redundant verification mismatch",
            Status::Other(_) => "unknown status",
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.text())
    }
}

/// Decoded license metadata.
#[derive(Debug, Clone)]
pub struct LicenseInfo {
    pub product_id: u32,
    pub machine_code: [u8; 16],
    pub expiry_days: u32,
    pub perpetual: bool,
    pub trial: bool,
    pub serial: [u8; 8],
    pub features: u16,
}

/// A verifier bound to one deployment (pubkey + dsalt + product id).
pub struct Activation {
    pubkey: [u8; 32],
    dsalt: [u8; 32],
    product_id: u32,
}

/// 32-byte value parsed from 64 hex chars.
fn parse32(s: &str, what: &str) -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    let bytes = hex_decode(s).ok_or(format!("{}: not valid hex", what))?;
    if bytes.len() != 32 {
        return Err(format!("{}: expected 64 hex chars", what));
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok())
        .collect()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Activation {
    /// Bind to a deployment. `pubkey_hex` / `dsalt_hex` are the public
    /// values printed by `engrail-keygen keygen`.
    pub fn new(pubkey_hex: &str, dsalt_hex: &str, product_id: u32) -> Result<Self, String> {
        Ok(Activation {
            pubkey: parse32(pubkey_hex, "pubkey")?,
            dsalt: parse32(dsalt_hex, "dsalt")?,
            product_id,
        })
    }

    /// This machine's fingerprint, "XXXXXXXXXXXXXXXX-XXXXXXXXXXXXXXXX".
    pub fn machine_code(&self) -> String {
        let mut mc = [0u8; 16];
        unsafe {
            act_fingerprint(
                self.pubkey.as_ptr(),
                self.dsalt.as_ptr(),
                self.product_id,
                std::ptr::null(),
                0,
                mc.as_mut_ptr(),
            );
        }
        self.machine_code_string(&mc)
    }

    fn machine_code_string(&self, mc: &[u8; 16]) -> String {
        let mut buf = [0u8; ACT_MACHINE_CODE_STR_SIZE];
        unsafe {
            act_fp_to_string(mc.as_ptr(), buf.as_mut_ptr() as *mut c_char);
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..end]).into_owned()
    }

    fn machine_bytes(&self) -> [u8; 16] {
        let mut mc = [0u8; 16];
        unsafe {
            act_fingerprint(
                self.pubkey.as_ptr(),
                self.dsalt.as_ptr(),
                self.product_id,
                std::ptr::null(),
                0,
                mc.as_mut_ptr(),
            );
        }
        mc
    }

    /// Full offline verification of an activation code.
    pub fn verify_code(&self, code: &str) -> (Status, Option<LicenseInfo>) {
        self.verify_code_at(code, now())
    }

    pub fn verify_code_at(&self, code: &str, now_unix: i64) -> (Status, Option<LicenseInfo>) {
        let mc = self.machine_bytes();
        let mut raw = LicenseInfoRaw {
            product_id: 0,
            machine_code: [0; 16],
            expiry_days: 0,
            flags: 0,
            perpetual: 0,
            trial: 0,
            serial: [0; 8],
            features: 0,
        };
        let st = unsafe {
            act_license_verify(
                code.as_ptr() as *const c_char,
                self.pubkey.as_ptr(),
                self.product_id,
                mc.as_ptr(),
                now_unix,
                &mut raw,
            )
        };
        let status = Status::from_raw(st);
        if matches!(status, Status::Ok) {
            (
                status,
                Some(LicenseInfo {
                    product_id: raw.product_id,
                    machine_code: raw.machine_code,
                    expiry_days: raw.expiry_days,
                    perpetual: raw.perpetual != 0,
                    trial: raw.trial != 0,
                    serial: raw.serial,
                    features: raw.features,
                }),
            )
        } else {
            (status, None)
        }
    }

    /// Verify + persist the signed state file.
    pub fn activate(&self, code: &str, state_path: &str) -> Status {
        let (st, _) = self.verify_code(code);
        if !matches!(st, Status::Ok) {
            return st;
        }
        let mut payload = [0u8; 36];
        let mut sig = [0u8; 64];
        let rc = unsafe {
            act_license_decode(code.as_ptr() as *const c_char, payload.as_mut_ptr(), sig.as_mut_ptr())
        };
        if rc != ACT_OK {
            return Status::from_raw(rc);
        }
        let rc = unsafe {
            act_state_save(
                state_path.as_ptr() as *const c_char,
                payload.as_ptr(),
                sig.as_ptr(),
            )
        };
        Status::from_raw(rc)
    }

    /// Re-verify the saved state (startup check).
    pub fn verify_saved(&self, state_path: &str) -> Status {
        let mc = self.machine_bytes();
        let rc = unsafe {
            act_state_check(
                state_path.as_ptr() as *const c_char,
                self.pubkey.as_ptr(),
                self.product_id,
                mc.as_ptr(),
                now(),
                std::ptr::null_mut(),
            )
        };
        Status::from_raw(rc)
    }
}

// SM2

/// SM2 (GB/T 32918) key pair.
pub struct Sm2KeyPair {
    pub priv_hex: String,
    pub pub_hex: String,
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Generate a random SM2 key pair.
pub fn sm2_keypair() -> Sm2KeyPair {
    let mut pub_ = [0u8; ACT_SM2_PUB_SIZE];
    let mut priv_ = [0u8; ACT_SM2_PRIV_SIZE];
    // NULL seed = draw a fresh key from the OS CSPRNG (C ABI contract).
    unsafe { act_sm2_keypair(std::ptr::null_mut(), pub_.as_mut_ptr(), priv_.as_mut_ptr()) };
    Sm2KeyPair {
        priv_hex: hex_encode(&priv_),
        pub_hex: hex_encode(&pub_),
    }
}

/// SM2 sign (hex output). Returns None on failure.
pub fn sm2_sign(priv_hex: &str, message: &[u8]) -> Option<String> {
    let priv_ = hex_decode(priv_hex)?;
    if priv_.len() != ACT_SM2_PRIV_SIZE {
        return None;
    }
    let mut sig = [0u8; ACT_SM2_SIG_SIZE];
    let rc = unsafe {
        act_sm2_sign(
            sig.as_mut_ptr(),
            message.as_ptr(),
            message.len(),
            priv_.as_ptr(),
            std::ptr::null(),
        )
    };
    if rc == ACT_OK {
        Some(hex_encode(&sig))
    } else {
        None
    }
}

/// SM2 verify (hex signature).
pub fn sm2_verify(pub_hex: &str, message: &[u8], sig_hex: &str) -> bool {
    let (pub_, sig) = match (hex_decode(pub_hex), hex_decode(sig_hex)) {
        (Some(p), Some(s)) if p.len() == ACT_SM2_PUB_SIZE && s.len() == ACT_SM2_SIG_SIZE => (p, s),
        _ => return false,
    };
    let rc = unsafe {
        act_sm2_verify(
            sig.as_ptr(),
            message.as_ptr(),
            message.len(),
            pub_.as_ptr(),
            std::ptr::null(),
        )
    };
    rc == ACT_OK
}

/// SM2 encrypt -> ciphertext bytes (C1C3C2).
pub fn sm2_encrypt(pub_hex: &str, message: &[u8]) -> Option<Vec<u8>> {
    let pub_ = hex_decode(pub_hex)?;
    if pub_.len() != ACT_SM2_PUB_SIZE {
        return None;
    }
    let mut out = vec![0u8; message.len() + 97];
    let mut out_len = 0usize;
    let rc = unsafe {
        act_sm2_encrypt(
            pub_.as_ptr(),
            message.as_ptr(),
            message.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        )
    };
    if rc == ACT_OK {
        out.truncate(out_len);
        Some(out)
    } else {
        None
    }
}

/// SM2 decrypt (C1C3C2 ciphertext).
pub fn sm2_decrypt(priv_hex: &str, ciphertext: &[u8]) -> Option<Vec<u8>> {
    let priv_ = hex_decode(priv_hex)?;
    if priv_.len() != ACT_SM2_PRIV_SIZE || ciphertext.len() < 98 {
        return None;
    }
    let mut out = vec![0u8; ciphertext.len() - 97];
    let mut out_len = 0usize;
    let rc = unsafe {
        act_sm2_decrypt(
            ciphertext.as_ptr(),
            ciphertext.len(),
            priv_.as_ptr(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        )
    };
    if rc == ACT_OK {
        out.truncate(out_len);
        Some(out)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sm2_roundtrip() {
        let kp = sm2_keypair();
        let msg = b"rust bindings sm2";
        let sig = sm2_sign(&kp.priv_hex, msg).expect("sign");
        assert!(sm2_verify(&kp.pub_hex, msg, &sig));
        assert!(!sm2_verify(&kp.pub_hex, b"other", &sig));
        let ct = sm2_encrypt(&kp.pub_hex, b"secret").expect("enc");
        assert_eq!(sm2_decrypt(&kp.priv_hex, &ct).unwrap(), b"secret");
    }

    #[test]
    fn machine_code_shape() {
        let act = Activation::new(&"11".repeat(32), &"22".repeat(32), 1).unwrap();
        let mc = act.machine_code();
        assert_eq!(mc.len(), 33);
        assert_eq!(mc.as_bytes()[16], b'-');
    }
}
