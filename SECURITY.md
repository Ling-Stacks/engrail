# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.3.x   | yes       |
| < 1.3   | no        |

## Reporting a vulnerability

**Do not open a public issue for security problems.**

1. Preferably contact us via Telegram DM to the maintainer through
   [@Stack_Traces](https://t.me/Stack_Traces) (mark your message **SECURITY**).
2. Alternatively open a GitHub Security Advisory
   (`Security > Advisories > Report a vulnerability`).

Please include: affected component, reproduction, impact assessment.
You will receive an acknowledgement within 72 hours. Fixes for
accepted issues ship as patch releases with credits (unless you
prefer to stay anonymous).

## Scope

In scope:
- Cryptographic correctness of the primitives (SHA-512, HMAC, HKDF,
  PBKDF2, ChaCha20, Ed25519, SM3, SM2) as implemented here.
- Signature verification bypass, license forgery beyond the documented
  Ed25519/SM2 assumptions.
- State-file / revocation-list integrity weaknesses.
- Key-file (ACTKEY2) confidentiality weaknesses.

Out of scope (documented limitations, see README):
- An attacker with local code-execution patching the verifier out of
  the binary (inherent to all offline licensing).
- Side-channel attacks requiring physical proximity/lab equipment.
- Weak vendor passphrases.

## Cryptographic pedigree

All primitives are implemented from the primary standards and
validated by:

- official test vectors (FIPS 180-4, RFC 4231, RFC 8032, RFC 5869,
  RFC 8439, GB/T 32905, GB/T 32918), and
- bidirectional cross-validation against independent reference
  implementations during development (signatures verified by the
  reference and vice versa, ciphertexts decrypted cross-implementation).

`make test` re-runs the frozen vector suite on every build.
