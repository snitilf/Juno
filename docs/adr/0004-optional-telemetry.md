# 0004: Optional Telemetry

## Context

Routing must work without logs or unstable transcript data.

## Decision

Keep telemetry off by default and limit it to documented metadata.
Keep transcript parsing separate, optional, and non-gating.

## Result

Telemetry failure cannot block a coding session or weaken routing.
