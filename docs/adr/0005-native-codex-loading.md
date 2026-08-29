# 0005: Native Codex Loading

## Context

Codex already discovers global instructions and personal custom agents.

## Decision

Install Juno into those native locations and keep normal Codex CLI and desktop as the daily entry points.
Do not add a daily wrapper or a second routing runtime.
Do not change Pi.

## Result

Juno needs lifecycle helpers and an isolated strict verifier, but it does not need a daily wrapper or a second routing runtime.
Pi receives Juno behavior only when it already launches the real `codex` executable with its normal Codex home.
