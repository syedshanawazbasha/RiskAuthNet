# Security model and verification scope

## Authenticated payload and trust boundary

All message fields in `Message.body()` are signed using deterministic ECDSA P-256 with SHA-256, including the pseudonym, sequence, timestamp and certificate digest. The certificate carries a P-256 public key, TA-signed issuer/serial/pseudonym/validity fields, and an 8-byte truncated digest for cache lookup (not as an authentication proof). Unknown pseudonyms need the full TA-authenticated certificate before cache use. A signed CRL update protects revocation information against unsigned substitution and rollback. Missing or stale CRL updates remain an infrastructure freshness limitation.

## Trust and risk

Only **successfully authenticated** messages affect online trust. Replays and corrupted signatures are discarded before the trust engine. Authenticated nonce reuse, same-sequence conflicting signed contents, explicit revocations and authenticated RSU misbehaviour reports require quarantine. Bounded buffers, capacity limits and per-sender/global escalation rate limits are modelled. In this prototype, denial of service against the cryptographic verification service and pseudonym churn remain residual threats.

## Session protocol

`mutual_handshake` uses fresh P-256 ephemeral keys and four P-256 ECDH terms matching the paper. Each participant signs the full role-specific transcript, derives a session key using HKDF-SHA256 with transcript binding, and explicitly confirms the key using HMAC-SHA256. Signatures and key confirmations are checked in Python. No hardware key isolation is implemented; secrets are Python objects.

## Threat test coverage

Tests include deterministic signatures, signature tampering, certificate tampering/expiry, unknown signer, stale timestamps, replay, conflicting sequences, signed revocation, P-256 session key confirmation and ratchet, RSU trust token tampering/replay, bounded escalation, synthetic signed insider anomalies, cold-start floors, channel-aware loss handling, split leakage protections and end-to-end benchmark execution.

## Out of scope

Real HSM implementation, IEEE 1609.2 message encoding/compliance, certificate-enrollment policy, secure hardware, real-world collision intervention, location privacy adversarial audits, native ProVerif model validation, quantified PQ security, and hardware-in-the-loop safety certification. Do not use these prototype keys or decisions to protect real vehicles.
