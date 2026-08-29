# Juno

Juno is a native Codex routing package for assigning bounded coding work to clear roles.
The main Codex session keeps planning, risk decisions, and final synthesis.
After an approved install, normal Codex CLI and desktop sessions load Juno through Codex instructions and custom agents.
Juno does not change Pi.
Juno applies only when Pi launches the real `codex` executable with its normal Codex home.

## Safety

Juno uses official OpenAI models only.
It keeps model IDs and role effort bindings in one catalog.
It must preserve user-owned Codex files and use approval-first, reversible changes.
It does not require a wrapper command for daily use.
Strict verification stays disabled until isolation and non-mutation checks pass.

## Readiness

Juno is not ready to install.
The asset generator, lifecycle binary, snapshot builder, and release gate tools are implemented.
Client certification and strict canaries have not run.

## Layout

- `config/` contains model bindings and routing hypotheses.
- `docs/` contains the design, decisions, and Codex claim checks.
- `evals/` contains the quality rules.
- `schemas/` contains strict verifier data shapes.
- `src/` contains the Rust binary.
- `tests/` checks contracts and safe lifecycle behavior.
