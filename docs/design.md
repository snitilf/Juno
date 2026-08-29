# Design

## Goal

Juno routes bounded coding work to clear roles while the main Codex session keeps planning, risk decisions, and final synthesis.

## Native loading

Juno uses Codex's own instruction and custom-agent discovery.
An approved install adds a marked routing block to the effective global Codex instruction file and adds personal custom agents under the Codex home.
Normal Codex CLI and desktop sessions then load Juno without a wrapper command.
Loaded project instructions remain closer in scope and can override global routing guidance.
Juno must fit inside the configured `project_doc_max_bytes` instruction limit.
New or changed instructions take effect in a new Codex session.

Pi is outside Juno's runtime boundary.
Juno does not change Pi or make model selection inside Pi load Codex instructions.
If Pi launches the real `codex` executable with its normal Codex home, that Codex process can load Juno through the same native path.

## Rules

- Role policy uses role names and catalog keys instead of model IDs.
- Model and effort bindings have one source of truth.
- Security work uses a dedicated executor and the strongest verifier.
- High-impact work stays in the main session.
- Verifiers report evidence and do not repair their own findings.
- User-owned Codex files must be preserved.

## Boundaries

- Juno uses official OpenAI models only.
- Daily routing runs inside normal Codex CLI and desktop sessions.
- Lifecycle tools may install, update, check, or remove Juno, but they are not a daily entry point.
- Hooks, telemetry, and transcript parsing are not required for routing.
- Routing does not commit, push, merge, release, or publish.
- Strict verification cannot be claimed before its canaries pass.
- A client build is unverified until its exact version and executable hash pass the compatibility checks.

## Flow

The main session classifies the task, selects a role, gives it a bounded packet, checks the result, and reports the final outcome.
A refuted result returns to an executor and then goes to a fresh verifier.
