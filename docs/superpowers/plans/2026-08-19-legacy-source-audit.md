# Legacy Source Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a reproducible, redacted audit of the legacy PHP server that is safe to publish and sufficient to plan Protobuf recovery and Go gateway implementation.

**Architecture:** Treat the legacy tree as immutable external input. Collect structural metadata and relative paths only, classify findings into migration actions, and store no source, secret value, customer data, runtime artifact, or third-party vendor code in the public repository.

**Tech Stack:** POSIX shell, `find`, `rg`, PHP Composer metadata, Markdown, Git.

**Spec:** `docs/design/2026-08-18-project-governance.md`, `docs/protocol.md`, and `docs/tasks/TASK-0002.md`

## Global Constraints

- The source tree is read-only external input and must not be copied into this public repository.
- Secret scans may report relative file paths and categories, never matched values or file contents.
- `vendor/`, runtime data, databases, logs, customer exports, and sensitive binaries are never staged.
- Counts must state exclusions and be reproducible with documented commands.
- Generated Protobuf classes are evidence for recovery, not automatically accepted as maintainable source.

---

### Task 1: Structural Inventory

**Files:**
- Create: `docs/audits/legacy-source-inventory.md`
- Modify: `docs/tasks/TASK-0002.md`

**Interfaces:**
- Consumes: external legacy server tree
- Produces: sanitized module, language, size, entry-point, and generated-code inventory

- [x] **Step 1: Count first-party and dependency files separately**

Run `find` and `rg --files` with `vendor/`, `runtime/`, `.git/`, database, log, and sensitive binary exclusions. Record exact filters with every count.

- [x] **Step 2: Identify application entry points and service runners**

Inspect filenames and configuration references for ThinkPHP HTTP, Workerman, GatewayWorker, Swoole, queue workers, scheduled jobs, and CLI commands. Record relative paths and symbols without copying large code sections.

- [x] **Step 3: Inventory protocol assets**

Count generated Jubo messages, `GPBMetadata` descriptors, message-type enums, and protocol handler files. Record the first recovery targets by relative path.

- [x] **Step 4: Verify inventory contains no absolute local path or secret value**

Run: `if rg -n '/U[s]ers/|BEGIN .*PRIVATE KEY|password[[:space:]]*[:=]|api[_-]?key[[:space:]]*[:=]' docs/audits/legacy-source-inventory.md; then exit 1; else test "$?" -eq 1; fi`

Expected: exit 0 with no matching output.

### Task 2: Dependency and License Audit

**Files:**
- Create: `docs/audits/legacy-dependencies-and-licenses.md`
- Modify: `docs/tasks/TASK-0002.md`

**Interfaces:**
- Consumes: `composer.json`, installed package metadata, repository license files
- Produces: direct dependency list, runtime constraints, license evidence, and public-migration decision

- [x] **Step 1: Parse direct Composer requirements**

Record package names and version constraints from `require`/`require-dev`, but redact repository credentials, private URLs, tokens, and author contact data.

- [x] **Step 2: Check lock and reproducibility state**

Record whether `composer.lock` exists, whether platform requirements are declared, and whether installed `vendor/` can be reproduced from committed metadata.

- [x] **Step 3: Locate license evidence**

Record project-level `LICENSE`/`COPYING` presence and aggregate installed-package license identifiers without copying license bodies.

- [x] **Step 4: Classify migration rights**

Classify first-party code as “ownership confirmation required” unless repository history or license evidence proves otherwise; never assume that local possession permits publication.

### Task 3: Secret and Configuration Risk Audit

**Files:**
- Create: `docs/audits/legacy-security-findings.md`
- Modify: `docs/tasks/TASK-0002.md`

**Interfaces:**
- Consumes: filenames, safe configuration keys, and non-value pattern counts
- Produces: redacted risk register and remediation requirements before any source import

- [x] **Step 1: Classify sensitive filenames**

Find environment files, key/certificate formats, databases, dumps, logs, captures, archives, and filenames containing `secret`, `sensitive`, `credential`, `token`, or `key`. Record relative paths and type only.

- [x] **Step 2: Scan text files without printing matches**

Use file lists plus per-file boolean pattern checks. Aggregate counts by risk category; do not use commands that print matching lines or values.

- [x] **Step 3: Review configuration loading paths**

Record which config files read environment variables, contain literal defaults, or reference external services. Do not record actual default values.

- [x] **Step 4: Define import gate**

Require secret removal/rotation, ownership confirmation, generated/runtime separation, and a clean staged-index scan before any legacy file can enter the public repository.

### Task 4: Migration and Protocol-Recovery Handoff

**Files:**
- Create: `docs/audits/legacy-migration-map.md`
- Modify: `docs/protocol.md`
- Modify: `PROJECT_STATUS.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/tasks/TASK-0002.md`

**Interfaces:**
- Consumes: outputs of Tasks 1–3
- Produces: migration decisions and exact inputs/acceptance criteria for `TASK-0003`

- [x] **Step 1: Classify modules**

Assign each major module one action: reference only, reimplement, migrate after redaction/license proof, retain temporarily in PHP, or discard as runtime/generated data.

- [x] **Step 2: Define first protocol slice**

List exact generated classes and metadata for `TransportMessage`, message enum, authentication, heartbeat, friend message notice, and outbound friend-message task.

- [x] **Step 3: Define compatibility fixtures**

Require synthetic or irreversibly redacted binary frames with expected decoded fields, plus PHP decode/encode and Go decode/encode equality tests.

- [x] **Step 4: Run final public-repository gate**

Run Markdown format/link checks, `git diff --cached --check`, approved-path validation, and staged-index credential scanning before commit.

- [x] **Step 5: Publish and continue**

Commit only the roadmap, plans, task/status updates, and sanitized audit reports; push, review, merge, sync `main`, then create `TASK-0003` without waiting for another routine approval.
