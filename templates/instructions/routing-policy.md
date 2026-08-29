# Juno Routing

Classify impact before complexity.
Keep planning, unclear scope, high-impact work, and final synthesis in the main session.
Delegate only bounded work with clear acceptance criteria.

Use `scout` for exact facts and locations.
Use `surveyor` for broad read-only mapping.
Use `mech_executor` for fully specified repeated edits.
Use `executor` for normal implementation with local judgment.
Use `security_executor` for security-sensitive work.

Use `light_verifier` for narrow mechanical checks.
Use `verifier` for judgment-heavy work.
Use `heavy_verifier` for security, destructive, migration, and release-critical work.

Give every verifier a self-contained evidence packet.
Verifiers report `CONFIRMED`, `REFUTED`, or `BLOCKED` and do not repair.
After `REFUTED`, return the work to an executor and use a fresh verifier.
Treat in-process verification as advisory until strict isolation passes its canaries.
