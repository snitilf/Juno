# Juno Repository Instructions

Read `README.md`, `docs/design.md`, and `docs/REVALIDATION.md` before changing behavior.
Use only official OpenAI documentation for Codex claims.
Keep concrete model IDs and role effort bindings in `config/model-catalog.toml` only.
Treat settings marked as hypotheses as unproven until the evals promote them.
Do not change files under `notes/`.
Do not read from or write to the real Codex home in tests.
Preserve user-owned files and stop on unknown collisions.
Keep documentation short and use plain words.
Put each full sentence on its own physical line in Markdown files.
Never use em dashes.
Do not commit, push, merge, release, or publish without direct user approval.

Run `tests/contract-test.sh` after changing the contract.
