# Juno

Juno is a Codex routing package for assigning bounded coding work to clear roles.
The main Codex session keeps planning, risk decisions, and final synthesis.

## Safety

Juno uses official OpenAI models only.
It keeps model IDs and role effort bindings in one catalog.
It must preserve user-owned Codex files and use approval-first, reversible changes.
Strict verification stays disabled until isolation and non-mutation checks pass.

## Readiness

Juno is not ready to install.
The repository currently contains the product contract, model catalog, safety decisions, and eval quality floor.

## Layout

- `config/` contains model bindings and routing hypotheses.
- `docs/` contains the design, decisions, and Codex claim checks.
- `evals/` contains the quality rules.
- `tests/` checks the repository contract.
