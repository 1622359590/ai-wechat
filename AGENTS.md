# Codex / Agent Instructions

Before changing anything, read these files in order:

1. `AI_CONTEXT.md` — canonical project rules and architecture boundaries.
2. `PROJECT_STATUS.md` — current facts, active work, and next tasks.
3. The active `docs/tasks/TASK-xxxx.md` — scope, acceptance criteria, and handoff.
4. Documents directly relevant to the requested subsystem.

All work must have a task document. Update it while working and record exact verification results before claiming completion. Update `PROJECT_STATUS.md` and, for user-visible or architectural changes, `CHANGELOG.md`.

This repository is public. Never commit credentials, customer chats, personal or device identifiers, databases, dumps, logs, packet captures, production payloads, or sensitive binary files. Inspect both the working tree and staged diff before every commit.

Shared policy belongs in `AI_CONTEXT.md`; keep this file as a thin Codex-compatible entry point.
