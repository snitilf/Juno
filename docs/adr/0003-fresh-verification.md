# 0003: Fresh Verification

## Context

A verifier can repeat an executor's blind spots when it shares context or permissions.

## Decision

Strict verification must use a separate Codex process, a bounded evidence packet, a new identity, and enforced read-only access.
In-process review is advisory only.

## Result

Strict verification stays disabled until every required canary passes.
