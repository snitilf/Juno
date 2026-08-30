# Verification Contract

Strict verification uses a separate Codex process, isolated Codex home, frozen repository snapshot, and bounded evidence packet.
It starts from a neutral directory and refers to the snapshot by absolute path.
The verifier reports `CONFIRMED`, `REFUTED`, or `BLOCKED` and never repairs the candidate.

Strict verification stays unavailable until every isolation and non-mutation canary passes.
The internal gate tool accepts evidence only when all 15 raw artifacts match the frozen candidate and client binaries.
Canaries and installed verification use the same strict launch path.
The installed release evidence must also contain passing CLI and desktop certification and a confirmed independent review.
Failure to establish the required sandbox returns `BLOCKED`.
Advisory review cannot satisfy a high-risk or release gate.
Verifier commands receive a fixed environment, read-only snapshot, no command network, and no nested agents.
Strict mode requires Codex service traffic to cross an outer loopback-only proxy that permits OpenAI service hosts.
The exact pinned client must prove this transport before strict mode becomes available.
Results must match the committed schema and the snapshot must remain unchanged.

A repaired candidate requires a new process and fresh verifier.
