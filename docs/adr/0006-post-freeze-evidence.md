# 0006: Post-Freeze Evidence

## Context

Certification happens after the candidate binary is frozen.

## Decision

Keep the binary unchanged and place content-free release evidence beside it.
Bind the evidence hash into the install plan and installed manifest.

## Result

Certification can be added without changing the binary that was tested.
