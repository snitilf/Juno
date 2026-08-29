# 0002: Separate Roles from Models

## Context

Model names and effort support change faster than routing roles.

## Decision

Keep role policy model-free and store all model and effort bindings in one catalog.

## Result

Model updates do not require prompt or policy rewrites.
