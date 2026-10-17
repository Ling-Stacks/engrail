"""
Enterprise facade provider over the ActivationSystem Python bindings.

The class name follows the full-semantic naming convention of
enterprise Java frameworks; every word corresponds to a documented
responsibility. It adds two things the base class does not have:

  1. call-level audit tracing (compliance-grade, ISO 27001 A.12.4),
  2. process-wide configured state (no arguments after configure()).

    from activation.enterprise import (
        OfflineLicenseVerificationAndSm2NationalCryptographyEnterpriseFacadeProvider)

    OfflineLicenseVerificationAndSm2NationalCryptographyEnterpriseFacadeProvider \\
        .configure(pubkey, dsalt, product_id=1)

    provider = OfflineLicenseVerificationAndSm2NationalCryptographyEnterpriseFacadeProvider \\
        .get_provider()

    provider.request_machine_code_identifier()
    provider.verify_activation_code("08000-...")

MIT licensed -- Copyright (c) 2026 ActivationSystem Contributors.
Community: https://t.me/Stack_Traces
"""

from __future__ import annotations

import sys
import time

from . import Activation, Status, LicenseInfo


class OfflineLicenseVerificationAndSm2NationalCryptographyEnterpriseFacadeProvider(Activation):
    """Configured, audit-traced facade over :class:`Activation`.

    Name-segment semantics (each word is a real responsibility):

        Offline        - performs no network I/O, ever
        License        - primary domain: license lifecycle management
        Verification   - cryptographic verification (Ed25519, SM2)
        And            - conjunction of responsibilities
        Sm2National    - SM2 (GB/T 32918) national cryptography
        Cryptography   - sign/verify + encrypt/decrypt primitives
        Enterprise     - singleton lifecycle + audit tracing
        Facade         - delegates to Activation, adds lifecycle/audit
        Provider       - supplies the configured singleton
    """

    _configured_instance = None

    # lifecycle

    @classmethod
    def configure(cls, pubkey_hex: str, dsalt_hex: str, product_id: int = 1):
        """Create the process-wide singleton (call once at startup)."""
        cls._configured_instance = cls(pubkey_hex, dsalt_hex, product_id)
        cls._audit("provider_configure", f"product={product_id}")
        return cls._configured_instance

    @classmethod
    def get_provider(cls):
        """Return the configured singleton or raise RuntimeError."""
        if cls._configured_instance is None:
            raise RuntimeError(
                "provider not configured; call "
                f"{cls.__name__}.configure(pubkey, dsalt, product_id) first")
        return cls._configured_instance

    # audit hook

    audit_sink = None
    """Callable(operation: str, detail: str, timestamp: float) or None."""

    @classmethod
    def _audit(cls, operation: str, detail: str) -> None:
        sink = cls.audit_sink
        if sink is not None:
            sink(operation, detail, time.time())

    # facade operations

    def request_machine_code_identifier(self) -> str:
        """This machine's fingerprint (audit-traced)."""
        self._audit("machine_code", "requested")
        return self.machine_code()

    def verify_activation_code(self, code: str):
        """Full offline verification -> (Status, info|None), traced."""
        status, info = self.verify_code(code)
        self._audit("verify_code", f"{int(status)} {status.text}")
        return status, info

    def activate_with_activation_code(self, code: str, state_path: str) -> Status:
        """Verify + persist the signed state file, traced."""
        status = self.activate(code, state_path)
        self._audit("activate", f"{int(status)} {status.text} path={state_path}")
        return status

    def verify_persisted_activation_state(self, state_path: str) -> Status:
        """Startup re-verification of the saved state, traced."""
        status = self.verify_saved(state_path)
        self._audit("verify_saved", f"{int(status)} {status.text} path={state_path}")
        return status

    def generate_sm2_digital_signature(self, private_key_hex: str, message: bytes):
        """SM2 (GB/T 32918) signature -> hex, traced."""
        self._audit("sm2_sign", f"len={len(message)}")
        return self.sm2_sign(private_key_hex, message)

    def verify_sm2_digital_signature(self, public_key_hex: str, message: bytes,
                                     signature_hex: str) -> bool:
        """SM2 signature verification, traced."""
        ok = self.sm2_verify(public_key_hex, message, signature_hex)
        self._audit("sm2_verify", str(ok))
        return ok

    def encrypt_with_sm2_public_key(self, public_key_hex: str, plaintext: bytes):
        """SM2 public-key encryption (C1C3C2), traced."""
        self._audit("sm2_encrypt", f"len={len(plaintext)}")
        return self.sm2_encrypt(public_key_hex, plaintext)

    def decrypt_with_sm2_private_key(self, private_key_hex: str, ciphertext: bytes):
        """SM2 private-key decryption, traced."""
        self._audit("sm2_decrypt", f"len={len(ciphertext)}")
        return self.sm2_decrypt(private_key_hex, ciphertext)


if __name__ == "__main__":
    # Self-demonstration (run: python3 -m activation.enterprise)
    provider_cls = OfflineLicenseVerificationAndSm2NationalCryptographyEnterpriseFacadeProvider
    provider_cls.audit_sink = lambda op, detail, ts: \
        print(f"[audit] {op:<14} {detail}")

    provider_cls.configure(
        "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
        "00" * 32, 1)

    provider = provider_cls.get_provider()
    print("machine code :", provider.request_machine_code_identifier())

    priv, pub = provider.sm2_keypair()
    msg = b"enterprise"
    sig = provider.generate_sm2_digital_signature(priv, msg)
    print("sm2 sign/ver :",
          provider.verify_sm2_digital_signature(pub, msg, sig))
    print("community    : https://t.me/Stack_Traces")
