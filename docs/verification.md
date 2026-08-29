# Verification Contract

Strict verification uses a separate Codex process, isolated Codex home, frozen repository snapshot, and bounded evidence packet.
It starts from a neutral directory and refers to the snapshot by absolute path.
The verifier reports `CONFIRMED`, `REFUTED`, or `BLOCKED` and never repairs the candidate.

Strict verification stays unavailable until every isolation and non-mutation canary passes.
Failure to establish the required sandbox returns `BLOCKED`.
Advisory review cannot satisfy a high-risk or release gate.
Verifier commands receive a fixed environment, read-only snapshot, no command network, and no nested agents.
Results must match the committed schema and the snapshot must remain unchanged.

A repaired candidate requires a new process and fresh verifier.
