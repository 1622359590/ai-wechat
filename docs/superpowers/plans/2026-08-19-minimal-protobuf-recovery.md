# Minimal Protobuf Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recover a compilable five-message Protobuf 3 subset and prove Go/PHP wire compatibility with public-safe synthetic frames.

**Architecture:** Keep protocol source in `proto/minimal` and compatibility tooling in an isolated `proto/compat` Go module. Tests compile source dynamically with `protocompile`, instantiate messages through `dynamicpb`, and compare deterministic golden frames; a PHP verifier reads only those fixtures and the external legacy generated classes selected by `LEGACY_SOURCE_ROOT`.

**Tech Stack:** Protobuf 3, Go 1.24+, `protocompile v0.14.1`, `google.golang.org/protobuf v1.36.12`, PHP 8 CLI with the external legacy Composer tree.

**Spec:** `docs/tasks/TASK-0003.md`

## Global Constraints

- The public repository must not contain credentials, customer chats, personal/device identifiers, databases, dumps, logs, captures, production payloads, sensitive binaries, or copied legacy source.
- The package is exactly `Jubo.JuLiao.IM.Wx.Proto`.
- Legacy source remains read-only and external; tests refer to it only through `LEGACY_SOURCE_ROOT`.
- Fixtures use only fixed `synthetic-*` identifiers and non-business byte strings.
- TASK-0004 owns production frame parsing and networking; this plan only verifies fixture framing.

---

### Task 1: Establish the descriptor contract test

**Files:**
- Create: `proto/compat/go.mod`
- Create: `proto/compat/schema_test.go`
- Create: `proto/minimal/TransportMessage.proto`
- Create: `proto/minimal/DeviceAuthReq.proto`
- Create: `proto/minimal/HeartBeat.proto`
- Create: `proto/minimal/FriendTalkNotice.proto`
- Create: `proto/minimal/TalkToFriendTask.proto`

**Interfaces:**
- Consumes: field and enum evidence in `docs/audits/legacy-migration-map.md` and the external `GPBMetadata` files.
- Produces: compiled descriptors keyed by full names such as `Jubo.JuLiao.IM.Wx.Proto.TransportMessage`.

- [x] **Step 1: Create the compatibility module and write the schema test before any `.proto` exists**

  The test loads `../minimal/*.proto`, requires package `Jubo.JuLiao.IM.Wx.Proto`, and table-tests every message field number/kind plus the four `EnumMsgType` values and four nested `EnumAuthType` values.

- [x] **Step 2: Run the schema test and verify RED**

  Run: `cd proto/compat && go test ./... -run TestRecoveredSchema -count=1`

  Expected: FAIL because `../minimal/TransportMessage.proto` is absent.

- [x] **Step 3: Add the minimum Protobuf sources**

  Define `TransportMessage` fields `Id=1 int64`, `AccessToken=2 string`, `MsgType=3 EnumMsgType`, `Content=4 google.protobuf.Any`, `RefMessageId=5 int64`; define the four inner message schemas with the exact field gaps and scalar types from GPBMetadata. Define only `UnknownMsg=0`, the four accepted message values, `UnknownContent=0`, `Text=1`, and the complete four-value nested auth enum needed by the recovered class.

- [x] **Step 4: Run the schema test and verify GREEN**

  Run: `cd proto/compat && go test ./... -run TestRecoveredSchema -count=1`

  Expected: PASS with one schema contract test.

- [x] **Step 5: Commit the schema slice**

  Stage only the task/plan, module, schema test and five `.proto` files; inspect the index and commit with `feat(proto): recover minimal message schema`.

### Task 2: Add deterministic synthetic frame fixtures

**Files:**
- Create: `proto/compat/fixtures_test.go`
- Create: `proto/testdata/synthetic_frames.json`

**Interfaces:**
- Consumes: compiled message descriptors from Task 1.
- Produces: 15 manifest entries with `case`, `message_type`, `msg_type`, `frame_hex`, and expected semantic fields.

- [x] **Step 1: Write a failing golden fixture test**

  Add three cases for each of the five message classes: normal values, empty/boundary values, and an inner message with unknown field 127 encoded as varint 1. For inner messages, pack the payload into `google.protobuf.Any` using `type.googleapis.com/<full-message-name>` and then into `TransportMessage`. For the transport-only trio, use `UnknownMsg` and empty/synthetic `Any` variants. Prefix every serialized transport body with a four-byte big-endian body length.

- [x] **Step 2: Run the fixture test and verify RED**

  Run: `cd proto/compat && go test ./... -run TestSyntheticFramesMatchGolden -count=1`

  Expected: FAIL because `../testdata/synthetic_frames.json` is absent.

- [x] **Step 3: Generate the checked-in golden file through the test update flag**

  Run: `cd proto/compat && go test ./... -run TestSyntheticFramesMatchGolden -count=1 -update`

  The update path writes deterministic, indented JSON and refuses values that do not match the `synthetic-*` allowlist or allowed fixed byte strings.

- [x] **Step 4: Verify framing and unknown-field round trips**

  Run: `cd proto/compat && go test ./... -run 'TestSyntheticFramesMatchGolden|TestFrameLengthPrefix|TestUnknownFieldRoundTrip' -count=1`

  Expected: PASS; 15 entries exist, every prefix equals body length, and field 127 survives decode → encode.

- [x] **Step 5: Commit the fixture slice**

  Stage the fixture test and JSON after secret/identifier scans, then commit with `test(proto): add synthetic compatibility frames`.

### Task 3: Verify the legacy PHP implementation

**Files:**
- Create: `proto/compat/verify_legacy_php.php`
- Modify: `proto/compat/fixtures_test.go`

**Interfaces:**
- Consumes: `LEGACY_SOURCE_ROOT`, external Composer autoload/generated classes, and `proto/testdata/synthetic_frames.json`.
- Produces: a zero exit code and `legacy-php-fixtures=15` without printing frame contents.

- [ ] **Step 1: Add the failing Go integration test**

  When `LEGACY_SOURCE_ROOT` is present, execute `php verify_legacy_php.php ../testdata/synthetic_frames.json`; require exit 0 and the exact aggregate count. When the variable is absent, report an explicit Go test skip.

- [ ] **Step 2: Run the integration test and verify RED**

  Run: `cd proto/compat && test -n "$LEGACY_SOURCE_ROOT" && go test ./... -run TestLegacyPHPCompatibility -count=1`

  Expected: FAIL because `verify_legacy_php.php` is absent.

- [ ] **Step 3: Implement the PHP verifier**

  Validate the environment path, require only Composer autoload plus the five approved GPBMetadata/generated-class pairs, decode the four-byte frame prefix and outer `TransportMessage`, decode inner `Any.value` according to the manifest message type, reserialize both layers, and assert semantic equality plus unknown field 127 retention. Never log decoded values or hex payloads.

- [ ] **Step 4: Run Go and PHP compatibility tests**

  Run: `cd proto/compat && test -n "$LEGACY_SOURCE_ROOT" && go test ./... -count=1`

  Expected: PASS and `legacy-php-fixtures=15` appears in the integration test output when run with `-v`.

- [ ] **Step 5: Commit the PHP compatibility slice**

  Stage only the verifier and integration-test change; run the staged-index credential scan and commit with `test(proto): verify legacy PHP compatibility`.

### Task 4: Document and integrate the result

**Files:**
- Modify: `docs/protocol.md`
- Modify: `docs/tasks/TASK-0003.md`
- Modify: `PROJECT_STATUS.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/superpowers/plans/2026-08-19-minimal-protobuf-recovery.md`

**Interfaces:**
- Consumes: exact test output and the committed schema/fixtures.
- Produces: the TASK-0004 protocol handoff and a complete public audit trail.

- [ ] **Step 1: Record only verified protocol facts**

  Add exact field tables, enum values, fixture count, Any type URL convention, unknown-field result, and limitations to `docs/protocol.md` and this task document.

- [ ] **Step 2: Update project state and changelog**

  Mark TASK-0003 complete only after all Go tests and the PHP integration pass; set TASK-0004 as the next active candidate.

- [ ] **Step 3: Run the complete verification gate**

  Run Go tests once without the environment variable to prove portable skip behavior and once with `LEGACY_SOURCE_ROOT` to prove 15-fixture PHP compatibility. Then check `git diff --check`, Markdown formatting/links, approved staged paths, staged-index credential patterns, forbidden file classes, and scan fixture JSON for non-synthetic identifiers.

- [ ] **Step 4: Request independent review and fix findings**

  Require zero unresolved Critical or Important findings for schema accuracy, fixture safety, TDD evidence and PHP/Go compatibility.

- [ ] **Step 5: Commit, push, open a ready PR, merge and sync main**

  Use the standing GitHub authorization after fresh verification; do not deploy or change production state.
