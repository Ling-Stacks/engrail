"""
ActivationSystem Python bindings (pure ctypes, zero build steps).

    import sys; sys.path.insert(0, "bindings/python")
    from activation import Activation

    act = Activation(pubkey_hex, dsalt_hex, product_id=1)
    print(act.machine_code())
    ok, info = act.verify_code("08000-...")
    act.activate("08000-...", "app.act")
    print(act.verify_saved("app.act"))

Library resolution order:
    $ACTIVATION_LIB  ->  package-local  ->  <repo>/build/libactivation.so
    ->  <repo>/dist/libactivation.so  ->  plain "libactivation.so"

Shared library build:
    ./configure --enable-shared && make
    (or) make amalgamation && cc -shared -fPIC -Idist dist/activation.c \\
         -o build/libactivation.so

MIT licensed -- Copyright (c) 2026 ActivationSystem Contributors.
Community: https://t.me/Stack_Traces
"""

import ctypes as C
import os
import sys
import time

__all__ = ["Activation", "Status", "LicenseInfo", "STATUS_TEXT"]

ACT_OK = 0
ACT_PAYLOAD_SIZE = 36
ACT_SIG_SIZE = 64
ACT_PUBKEY_SIZE = 32
ACT_DSALT_SIZE = 32
ACT_MACHINE_CODE_SIZE = 16
ACT_SM2_PUB_SIZE = 64
ACT_SM2_PRIV_SIZE = 32
ACT_SM2_SIG_SIZE = 64

STATUS_TEXT = {
    0: "ok",
    -1: "bad argument",
    -2: "malformed activation code",
    -3: "unsupported license version",
    -4: "license issued for another product",
    -5: "signature check failed (forged or tampered)",
    -6: "license bound to another machine",
    -7: "license expired",
    -8: "no activation state found",
    -9: "activation state i/o error",
    -10: "activation state corrupt",
    -11: "license revoked",
    -12: "debugger detected",
    -13: "executable integrity failure",
    -14: "redundant verification mismatch",
}


class Status(int):
    """Verification outcome; truthy only when ACT_OK."""

    def __bool__(self):
        return int(self) == ACT_OK

    @property
    def text(self):
        return STATUS_TEXT.get(int(self), "unknown")


class LicenseInfo(C.Structure):
    _fields_ = [
        ("product_id", C.c_uint32),
        ("machine_code", C.c_ubyte * ACT_MACHINE_CODE_SIZE),
        ("expiry_days", C.c_uint32),
        ("flags", C.c_ubyte),
        ("perpetual", C.c_int),
        ("trial", C.c_int),
        ("serial", C.c_ubyte * 8),
        ("features", C.c_uint16),
    ]

    def as_dict(self):
        return {
            "product_id": self.product_id,
            "machine_code": bytes(self.machine_code).hex(),
            "expiry_days": self.expiry_days,
            "perpetual": bool(self.perpetual),
            "trial": bool(self.trial),
            "serial": bytes(self.serial).hex(),
            "features": self.features,
        }


_u8p = C.POINTER(C.c_ubyte)


def _load_library():
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(os.path.dirname(os.path.dirname(here)))
    # shared-library suffix is platform-derived since v1.7.2
    # (configure emits libactivation.so / .dylib / activation.dll)
    suffix = ".dll" if os.name == "nt" else (
        ".dylib" if sys.platform == "darwin" else ".so")
    libname = ("libactivation" + suffix) if suffix != ".dll" \
        else "activation.dll"
    candidates = [
        os.environ.get("ACTIVATION_LIB", ""),
        os.path.join(here, libname),
        os.path.join(repo, "build", libname),
        os.path.join(repo, "dist", libname),
        libname,
    ]
    for path in candidates:
        if path and (os.path.sep in path or os.path.exists(path)):
            try:
                return C.CDLL(path)
            except OSError:
                continue
    raise OSError(
        "libactivation.so not found; build it with "
        "`./configure --enable-shared && make` or set $ACTIVATION_LIB"
    )


def _bind(lib):
    b = lib
    u8 = lambda n: (C.c_ubyte * n)()

    b.act_fingerprint.argtypes = [_u8p, _u8p, C.c_uint32, _u8p, C.c_size_t, _u8p]
    b.act_fp_to_string.argtypes = [_u8p, C.c_char_p]
    b.act_license_verify.argtypes = [C.c_char_p, _u8p, C.c_uint32, _u8p,
                                     C.c_longlong, C.c_void_p]
    b.act_license_verify.restype = C.c_int
    b.act_license_decode.argtypes = [C.c_char_p, _u8p, _u8p]
    b.act_license_decode.restype = C.c_int
    b.act_state_save.argtypes = [C.c_char_p, _u8p, _u8p]
    b.act_state_save.restype = C.c_int
    b.act_state_check.argtypes = [C.c_char_p, _u8p, C.c_uint32, _u8p,
                                  C.c_longlong, C.c_void_p]
    b.act_state_check.restype = C.c_int
    b.act_days_remaining.argtypes = [C.c_void_p, C.c_longlong]
    b.act_days_remaining.restype = C.c_longlong
    b.act_has_feature.argtypes = [C.c_void_p, C.c_int]
    b.act_has_feature.restype = C.c_int
    b.act_token_verify.argtypes = [C.c_char_p, _u8p, C.c_uint32, C.c_longlong,
                                   _u8p, C.c_size_t, C.c_void_p, C.c_void_p]
    b.act_token_verify.restype = C.c_int
    b.act_sm2_keypair.argtypes = [_u8p, _u8p, _u8p]
    b.act_sm2_sign.argtypes = [_u8p, _u8p, C.c_size_t, _u8p, C.c_char_p]
    b.act_sm2_sign.restype = C.c_int
    b.act_sm2_verify.argtypes = [_u8p, _u8p, C.c_size_t, _u8p, C.c_char_p]
    b.act_sm2_verify.restype = C.c_int
    b.act_sm2_encrypt.argtypes = [_u8p, _u8p, C.c_size_t, _u8p, C.c_size_t,
                                  C.POINTER(C.c_size_t)]
    b.act_sm2_encrypt.restype = C.c_int
    b.act_sm2_decrypt.argtypes = [_u8p, C.c_size_t, _u8p, _u8p, C.c_size_t,
                                  C.POINTER(C.c_size_t)]
    b.act_sm2_decrypt.restype = C.c_int
    b.act_sm3.argtypes = [C.c_void_p, C.c_size_t, _u8p]
    return b


def _hex(bytes_or_str):
    if isinstance(bytes_or_str, str):
        b = bytes.fromhex(bytes_or_str)
    else:
        b = bytes_or_str
    return (C.c_ubyte * len(b)).from_buffer_copy(b)


class Activation:
    """High-level verifier bound to one product deployment."""

    def __init__(self, pubkey_hex: str, dsalt_hex: str,
                 product_id: int = 1, lib=None):
        self.lib = lib or _bind(_load_library())
        self.pubkey = _hex(pubkey_hex)
        self.dsalt = _hex(dsalt_hex)
        if len(self.pubkey) != ACT_PUBKEY_SIZE or len(self.dsalt) != ACT_DSALT_SIZE:
            raise ValueError("pubkey/dsalt must each be 32 bytes (64 hex)")
        self.product_id = product_id

    # licensing
    def machine_code(self, salt_hex: str = None) -> str:
        """This machine's fingerprint as XXXXXXXXXXXXXXXX-XXXXXXXXXXXXXXXX."""
        salt = _hex(salt_hex) if salt_hex else None
        mc = (C.c_ubyte * ACT_MACHINE_CODE_SIZE)()
        self.lib.act_fingerprint(self.pubkey, self.dsalt, self.product_id,
                                 salt, len(salt) if salt else 0, mc)
        out = C.create_string_buffer(ACT_MACHINE_CODE_SIZE * 2 + 2)
        self.lib.act_fp_to_string(mc, out)
        return out.value.decode()

    def verify_code(self, code: str, now=None):
        """(Status, LicenseInfo|None) -- full offline verification."""
        now = int(time.time()) if now is None else now
        mc = _hex(bytes.fromhex(self.machine_code().replace("-", "")))
        info = LicenseInfo()
        st = Status(self.lib.act_license_verify(code.encode(), self.pubkey,
                                                self.product_id, mc, now,
                                                C.byref(info)))
        return st, (info.as_dict() if st else None)

    def activate(self, code: str, state_path: str, now=None) -> Status:
        """Verify + persist the signed state file. Returns Status."""
        st, _ = self.verify_code(code, now=now)
        if not st:
            return st
        payload = (C.c_ubyte * ACT_PAYLOAD_SIZE)()
        sig = (C.c_ubyte * ACT_SIG_SIZE)()
        self.lib.act_license_decode(code.encode(), payload, sig)
        return Status(self.lib.act_state_save(state_path.encode(), payload, sig))

    def verify_saved(self, state_path: str, now=None) -> Status:
        now = int(time.time()) if now is None else now
        mc = _hex(bytes.fromhex(self.machine_code().replace("-", "")))
        return Status(self.lib.act_state_check(state_path.encode(),
                                               self.pubkey,
                                               self.product_id, mc, now,
                                               None))

    def days_remaining(self, code: str, now=None) -> int:
        st, info = self.verify_code(code, now=now)
        if not st:
            return 0
        info_c = LicenseInfo(**{k: info[k] if k != "machine_code" else
                                (C.c_ubyte * 16).from_buffer_copy(
                                    bytes.fromhex(info["machine_code"]))
                                for k in ("product_id", "machine_code",
                                          "expiry_days")})
        info_c.flags = 1 if info["perpetual"] else 0
        return self.lib.act_days_remaining(C.byref(info_c),
                                           int(time.time()) if now is None else now)

    # offline tokens
    def token_verify(self, token: str, now=None):
        """(Status, payload bytes) for a vendor-signed offline token."""
        now = int(time.time()) if now is None else now
        buf = (C.c_ubyte * 4096)()
        n = C.c_size_t(0)
        st = Status(self.lib.act_token_verify(token.encode(), self.pubkey,
                                              self.product_id, now, buf,
                                              len(buf), C.byref(n), None))
        return st, (bytes(buf[: n.value]) if st else b"")

    # SM2 (GB/T 32918)
    @staticmethod
    def sm2_keypair():
        """(priv_hex, pub_hex) from the OS CSPRNG."""
        lib = _bind(_load_library())
        pub = (C.c_ubyte * ACT_SM2_PUB_SIZE)()
        priv = (C.c_ubyte * ACT_SM2_PRIV_SIZE)()
        lib.act_sm2_keypair(None, pub, priv)
        return bytes(priv).hex(), bytes(pub).hex()

    def sm2_sign(self, priv_hex: str, message: bytes, sm2: bool = True):
        lib = _bind(_load_library())
        priv = _hex(priv_hex)
        msg = (C.c_ubyte * len(message)).from_buffer_copy(message)
        sig = (C.c_ubyte * ACT_SM2_SIG_SIZE)()
        fn = lib.act_sm2_sign if sm2 else None
        st = fn(sig, msg, len(message), priv, None)
        return bytes(sig).hex() if st == ACT_OK else None

    def sm2_verify(self, pub_hex: str, message: bytes, sig_hex: str) -> bool:
        lib = _bind(_load_library())
        pub = _hex(pub_hex)
        msg = (C.c_ubyte * len(message)).from_buffer_copy(message)
        sig = _hex(sig_hex)
        return lib.act_sm2_verify(sig, msg, len(message), pub, None) == ACT_OK

    def sm2_encrypt(self, pub_hex: str, message: bytes) -> bytes:
        lib = _bind(_load_library())
        pub = _hex(pub_hex)
        msg = (C.c_ubyte * len(message)).from_buffer_copy(message)
        ct = (C.c_ubyte * (len(message) + 97))()
        n = C.c_size_t(0)
        st = lib.act_sm2_encrypt(pub, msg, len(message), ct, len(ct),
                                 C.byref(n))
        return bytes(ct[: n.value]) if st == ACT_OK else b""

    def sm2_decrypt(self, priv_hex: str, ciphertext: bytes) -> bytes:
        lib = _bind(_load_library())
        priv = _hex(priv_hex)
        ct = (C.c_ubyte * len(ciphertext)).from_buffer_copy(ciphertext)
        pt = (C.c_ubyte * max(len(ciphertext) - 97, 1))()
        n = C.c_size_t(0)
        st = lib.act_sm2_decrypt(ct, len(ciphertext), priv, pt, len(pt),
                                 C.byref(n))
        return bytes(pt[: n.value]) if st == ACT_OK else b""

    # misc
    @staticmethod
    def sm3(data: bytes) -> bytes:
        lib = _bind(_load_library())
        buf = (C.c_ubyte * 32)()
        lib.act_sm3((C.c_ubyte * len(data)).from_buffer_copy(data),
                    len(data), buf) if len(data) else lib.act_sm3(None, 0, buf)
        return bytes(buf)
