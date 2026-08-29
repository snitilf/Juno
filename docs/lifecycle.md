# Lifecycle Contract

Mutation commands create an immutable plan before changing files.
Applying a plan requires its exact ID.
Changes to shared files require separate approval.
Juno preserves original values, stops on drift, and records a durable recovery journal.
Plans record binary, release asset, catalog, preimage, ownership, link, and backup data.
Tests use injected fake homes and never use the real Codex home.

An incomplete journal blocks every command except recovery, diagnostics, and version output.
Recovery first creates a new plan.
Conflict overwrite requires a separate flag.

Juno never edits shell startup files.
Juno never commits, pushes, merges, releases, or publishes.
