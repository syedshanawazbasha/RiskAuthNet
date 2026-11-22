# Symbolic verification status

The uploaded manuscript reports a ProVerif security analysis, but the formal
model or proof logs are not part of the supplied 31-page file. This repository
does not claim a completed ProVerif proof. The executable Python security tests
cover message authenticity, tamper detection, transcript binding, authenticated
4-DH session agreement, replay prevention, tokens, signed revocation and bounded
escalation. A formally verified ProVerif model requires independently specifying
and checking the Dolev–Yao attacker model, certificate revocation, nonce secrecy,
and weak/strong agreement events, then retaining the actual ProVerif output.

Do not interpret passing unit tests as proof of the paper's claimed security theorem.
