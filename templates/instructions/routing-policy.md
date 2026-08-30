# Juno Routing

Classify impact before complexity.
Keep planning, unclear implementation scope, high-impact decisions, and final synthesis in the main session.
Delegate only bounded work with clear acceptance criteria.

Use `scout` for bounded read-only facts, locations, commands, and small repository summaries.
Use `surveyor` for broad read-only mapping and bounded diagnosis when the cause is unknown.
Use `mech_executor` for fully specified mechanical edits such as renames, formatting, repeated changes, and short text changes.
Use `executor` for normal implementation with local judgment.
Use `security_executor` for security or integrity boundary work, including authentication, permissions, secrets, and races that can corrupt state.

Use `light_verifier` for narrow mechanical checks.
Use `verifier` for judgment-heavy work.
Use `heavy_verifier` for security, integrity, destructive, migration, shared instruction or config, and release-critical work.

Give every verifier a self-contained evidence packet.
Verifiers report `CONFIRMED`, `REFUTED`, or `BLOCKED` and do not repair.
After `REFUTED`, return the work to an executor and use a fresh `heavy_verifier`.
Treat in-process verification as advisory until strict isolation passes its canaries.
