# Design

## Goal

Juno routes bounded coding work to clear roles while the main Codex session keeps planning, risk decisions, and final synthesis.

## Rules

- Role policy uses role names and catalog keys instead of model IDs.
- Model and effort bindings have one source of truth.
- Security work uses a dedicated executor and the strongest verifier.
- High-impact work stays in the main session.
- Verifiers report evidence and do not repair their own findings.
- User-owned Codex files must be preserved.

## Boundaries

- Juno uses official OpenAI models only.
- Hooks, telemetry, and transcript parsing are not required for routing.
- Routing does not commit, push, merge, release, or publish.
- Strict verification cannot be claimed before its canaries pass.

## Flow

The main session classifies the task, selects a role, gives it a bounded packet, checks the result, and reports the final outcome.
A refuted result returns to an executor and then goes to a fresh verifier.
