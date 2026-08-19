# Project Governance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Initialize the public AI WeChat customer-service repository with portable AI instructions, project status tracking, architecture and cost documentation, and secret-safe defaults.

**Architecture:** A canonical `AI_CONTEXT.md` owns shared rules, while tool-specific files are thin adapters. Focused documents under `docs/` describe architecture, protocol, data, deployment, AI routing, costs, decisions, and task history without importing legacy source code.

**Tech Stack:** Markdown, Git, Go gateway (planned), PHP business service (retained initially), Python AI workers (planned), PostgreSQL, Redis.

**Spec:** `docs/design/2026-08-18-project-governance.md`

## Global Constraints

- The repository is public, but secrets, credentials, customer chats, databases, logs, device identifiers, and sensitive binary files must never be committed.
- This task creates documentation and AI instruction files only; it must not import the legacy PHP source or generated Protobuf files.
- `AI_CONTEXT.md` is the canonical shared instruction source; tool-specific adapters must not duplicate its full contents.
- Every future change must update its `docs/tasks/TASK-xxxx.md`; material milestone changes must update `PROJECT_STATUS.md` and `CHANGELOG.md`.

---

### Task 1: Canonical Governance and Status

**Files:**
- Create: `AI_CONTEXT.md`
- Create: `PROJECT_STATUS.md`
- Create: `CHANGELOG.md`
- Create: `docs/tasks/TASK-0001.md`

**Interfaces:**
- Consumes: approved design in `docs/design/2026-08-18-project-governance.md`
- Produces: canonical AI rules and current project state referenced by every adapter and future task

- [x] **Step 1: Create the canonical rules**

Write `AI_CONTEXT.md` with mandatory reading order, architecture boundaries, security rules, task lifecycle, documentation requirements, testing expectations, and cross-computer Git workflow.

- [x] **Step 2: Create project tracking files**

Write `PROJECT_STATUS.md`, `CHANGELOG.md`, and `docs/tasks/TASK-0001.md`. Record the approved scope, completed investigation, current implementation, acceptance criteria, and excluded legacy source.

- [x] **Step 3: Verify canonical references**

Run: `rg -n "AI_CONTEXT.md|TASK-0001|公开|敏感" AI_CONTEXT.md PROJECT_STATUS.md CHANGELOG.md docs/tasks/TASK-0001.md`

Expected: every tracking file is readable, `TASK-0001` is present, and public-repository security boundaries are explicit.

### Task 2: Architecture and Operating-Cost Documentation

**Files:**
- Create: `docs/architecture.md`
- Create: `docs/module-map.md`
- Create: `docs/protocol.md`
- Create: `docs/database-schema.md`
- Create: `docs/deployment.md`
- Create: `docs/ai-model-routing.md`
- Create: `docs/memory-and-knowledge.md`
- Create: `docs/cost-estimate.md`
- Create: `docs/decisions/0001-progressive-rewrite.md`

**Interfaces:**
- Consumes: architecture and cost assumptions from the approved design
- Produces: bounded specifications for later gateway, AI, memory, storage, and deployment implementation plans

- [x] **Step 1: Document system boundaries**

Describe the planned Go gateway, retained PHP business layer, Python AI workers, PostgreSQL, Redis, object storage, and external model providers. Mark proposed components clearly so documentation does not claim they already exist.

- [x] **Step 2: Document protocol and data findings**

Record the known four-byte-length plus Protobuf transport, the generated PHP descriptor location, unresolved framing/security questions, and a proposed minimal schema without copying private source code.

- [x] **Step 3: Document model, memory, and knowledge strategy**

Define cheap-model classification, confidence-based escalation, daily batch consolidation, a provider-neutral `MemoryService`, TencentDB Agent Memory evaluation boundaries, and the later Graphiti/Neo4j evaluation.

- [x] **Step 4: Document deployment tiers and cost assumptions**

Provide development, 1,000-device, 10,000-device, and 50,000-device ranges. Explain that daily active devices, message rate, token volume, media, retention, and redundancy drive cost.

- [x] **Step 5: Verify proposal language and coverage**

Run: `rg -n "计划|建议|尚未|假设|日活|MemoryService|Protobuf" docs/*.md docs/decisions/*.md`

Expected: planned systems are not represented as deployed, cost assumptions are explicit, and protocol uncertainties remain visible.

### Task 3: Cross-AI Adapters and Secret-Safe Defaults

**Files:**
- Create: `AGENTS.md`
- Create: `CLAUDE.md`
- Create: `GEMINI.md`
- Create: `.github/copilot-instructions.md`
- Create: `.cursor/rules/ai-wechat.mdc`
- Create: `.gitignore`

**Interfaces:**
- Consumes: `AI_CONTEXT.md`, `PROJECT_STATUS.md`, and the active task file
- Produces: stable entry points for major AI development tools and default exclusion of sensitive local artifacts

- [x] **Step 1: Create thin AI adapters**

Each adapter must direct the tool to read `AI_CONTEXT.md`, `PROJECT_STATUS.md`, and the active task before editing. Keep the adapter tool-specific and leave shared policy in the canonical file.

- [x] **Step 2: Add secret-safe ignore patterns**

Ignore environment files, keys, certificates, databases, dumps, logs, runtime data, customer/chat exports, IDE caches, build output, dependency directories, and `sensitive_*.bin`; retain a future `.env.example` with `!.env.example`.

- [x] **Step 3: Verify adapters and ignores**

Run: `for file in AGENTS.md CLAUDE.md GEMINI.md .github/copilot-instructions.md .cursor/rules/ai-wechat.mdc; do rg -q "AI_CONTEXT.md" "$file" || exit 1; done && git check-ignore .env customer_chats.json runtime/app.log sensitive_payload.bin`

Expected: all adapters reference the canonical file and every sample sensitive path is ignored.

### Task 4: Final Documentation Audit and Git Handoff

**Files:**
- Modify: `PROJECT_STATUS.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/tasks/TASK-0001.md`

**Interfaces:**
- Consumes: all files produced by Tasks 1–3
- Produces: verified completion record suitable for commit, push, and Draft PR review

- [x] **Step 1: Scan for secrets and accidental legacy files**

Run: `git status --short && git diff --check && if git grep --cached -nIiE '(BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|AKID[[:alnum:]]+|password[[:space:]]*[:=][[:space:]]*[^<[:space:]]+|api[_-]?key[[:space:]]*[:=][[:space:]]*[^<[:space:]]+)' -- .; then echo 'potential credential found'; exit 1; else test "$?" -eq 1; fi`

Expected: only intended documentation/configuration files are present, `git diff --check` emits no errors, and the pattern scan finds no real credentials.

- [x] **Step 2: Record verification results**

Set `TASK-0001` to complete, list the exact verification commands and outcomes, update `PROJECT_STATUS.md` with the next task, and add the initialization entry to `CHANGELOG.md`.

- [x] **Step 3: Commit the reviewed scope**

Run: `git add -- .cursor/rules/ai-wechat.mdc .github/copilot-instructions.md .gitignore AGENTS.md AI_CONTEXT.md CHANGELOG.md CLAUDE.md GEMINI.md PROJECT_STATUS.md docs/ai-model-routing.md docs/architecture.md docs/cost-estimate.md docs/database-schema.md docs/decisions/0001-progressive-rewrite.md docs/deployment.md docs/design/2026-08-18-project-governance.md docs/memory-and-knowledge.md docs/module-map.md docs/protocol.md docs/superpowers/plans/2026-08-18-project-governance.md docs/tasks/TASK-0001.md && git diff --cached --name-status && git diff --cached --check && git commit -m "docs: initialize AI project governance"`

Expected: one initial commit containing only the approved governance and planning files.

- [x] **Step 4: Publish for review**

Push branch `agent/project-governance` to `1622359590/ai-wechat` and open a Draft PR titled `docs: initialize AI project governance`.

Expected: the remote branch and Draft PR exist; no direct write is made to `main`.
