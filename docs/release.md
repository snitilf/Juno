# Release Gates

A release pins the operating system, client versions, executable hashes, catalog hash, corpus hashes, and routing assets.
CLI and desktop pass separate certification sets in disposable environments.
Failed certification cases cannot be rerun as infrastructure errors.

The exact quality gates live in `evals/certification.toml`.
The internal gate tool freezes a clean commit and rejects incomplete, stale, or unregistered infrastructure results.
It validates paired open runs, fresh client corpora, raw canary and client artifacts, and the independent review before sealing evidence.
Strict verification must be available for the pinned client before a final release.
The local release candidate is blocked until strict canaries and both client certifications pass.
A content-free evidence file binds those later results to the unchanged frozen binary.
Install plans include its exact hash and reject any later change.
The bundle builder accepts only that frozen binary and its valid evidence file from a clean matching source commit.

A fresh flagship verifier runs at xhigh effort after every other gate passes.
A refuted candidate is fixed and checked by a different fresh verifier.
