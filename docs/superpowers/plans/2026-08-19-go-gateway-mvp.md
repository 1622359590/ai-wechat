# Go Gateway MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and locally deploy a security-default Go TCP gateway that replays the recovered protocol and supports the first authenticated message loop.

**Architecture:** Use one root Go module. `proto/schema` embeds and compiles the approved minimal schema; focused internal packages own framing, protocol mapping, connection state, TCP serving and health. The runnable binary wires deny-all authentication and a no-op responder until TASK-0005 supplies a real controlled adapter.

**Tech Stack:** Go 1.24+, protocompile v0.14.1, google.golang.org/protobuf v1.36.12, standard-library TCP/HTTP, Docker multi-stage build and Compose.

**Spec:** `docs/superpowers/specs/2026-08-19-go-gateway-mvp-design.md`

## Global Constraints

- No credentials, real identifiers, chats, databases, logs, captures or production payloads enter Git.
- Default authentication rejects every device; there is no accept-any runtime mode.
- Maximum configured body is 16 MiB; default is 1 MiB; allocation occurs only after checking length.
- Container ports bind to `127.0.0.1` in the staging Compose file.
- No remote TCP exposure without TLS/network controls and an identified test server.

---

### Task 1: Root module and reusable schema loader

**Files:**
- Move: `proto/compat/go.mod` to `go.mod`
- Move: `proto/compat/go.sum` to `go.sum`
- Create: `proto/schema/schema.go`
- Create: `proto/schema/schema_test.go`
- Create: `proto/minimal/embed.go`
- Modify: `proto/compat/schema_test.go`

**Interfaces:**
- Produces: `schema.Load() (*protoregistry.Files, error)` with cached, concurrency-safe descriptors.
- Consumes: embedded `proto/minimal/*.proto` and standard Protobuf imports.

- [x] Write a failing loader test for five files, package and concurrent pointer reuse.
- [x] Run `go test ./proto/schema -count=1` and verify RED because `schema.Load` is absent.
- [x] Implement embed FS resolver, protocompile compiler and `sync.Once` cache.
- [x] Move the module files to repository root, update compatibility imports, run `go mod tidy`.
- [x] Run `go test ./... -count=1` and commit `feat(gateway): add reusable protocol schema`.

### Task 2: Frame and protocol codecs

**Files:**
- Create: `internal/frame/codec.go`
- Create: `internal/frame/codec_test.go`
- Create: `internal/protocol/codec.go`
- Create: `internal/protocol/codec_test.go`

**Interfaces:**
- Produces: `frame.NewDecoder(io.Reader, uint32).Read() ([]byte, error)` and `frame.Write(io.Writer, []byte, uint32) error`.
- Produces: `protocol.NewCodec(*protoregistry.Files)`, `Decode([]byte) (*Decoded, error)`, and `EncodeTalkToFriend(Reply) ([]byte, error)`.
- `Decoded` exposes only message ID, ref ID, MsgType, type URL and dynamic payload; callers do not log payload fields.

- [x] Write frame tests for valid, half reads, two concatenated frames, zero, oversized, truncated header/body and writer limit.
- [x] Verify frame tests RED, implement exact reads and typed sentinel errors, then verify GREEN.
- [x] Write protocol tests that replay all 15 fixtures, reject mismatched/missing Any and preserve unknown fields.
- [x] Verify protocol tests RED, implement the four-value mapping and talk-to-friend encoder, then verify GREEN.
- [x] Run `go test ./internal/frame ./internal/protocol -count=1` and commit `feat(gateway): add frame and protocol codecs`.

### Task 3: Connection state, TCP server and health

**Files:**
- Create: `internal/gateway/handler.go`
- Create: `internal/gateway/handler_test.go`
- Create: `internal/server/server.go`
- Create: `internal/server/server_test.go`
- Create: `internal/health/handler.go`
- Create: `internal/health/handler_test.go`
- Create: `cmd/gateway/main.go`

**Interfaces:**
- `gateway.Authenticator.Authenticate(context.Context, *dynamicpb.Message) error`.
- `gateway.Responder.OnFriendTalk(context.Context, *dynamicpb.Message) (*protocol.Reply, error)`.
- `gateway.Handler.Handle(context.Context, *Session, []byte) ([]byte, error)`.
- `server.Server.Serve(net.Listener) error`, `Shutdown(context.Context) error`, readiness callback.

- [ ] Write handler tests for pre-auth rejection, deny-all, successful auth, heartbeat, friend event and optional reply.
- [ ] Verify handler RED; implement session state and message dispatch; verify GREEN.
- [ ] Write localhost server tests for one complete synthetic flow, connection error isolation and shutdown.
- [ ] Verify server RED; implement deadlines/accept loop; verify GREEN.
- [ ] Write health tests, implement live/ready handlers and wire `cmd/gateway`; run `go test ./... -race -count=1` and commit `feat(gateway): serve authenticated protocol loop`.

### Task 4: Containerize, stage and document

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`
- Create: `deploy/compose.yaml`
- Modify: `docs/deployment.md`
- Modify: `docs/tasks/TASK-0004.md`
- Modify: `PROJECT_STATUS.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Produces: `ai-wechat-gateway` static binary, TCP `19090`, HTTP `/livez` and `/readyz` on `18080`.
- Compose service runs non-root, read-only, `cap_drop: [ALL]`, `no-new-privileges`, resource limits and loopback-only published ports.

- [ ] Write a container smoke script/test that requires live/ready 200 and verifies the process UID is non-zero.
- [ ] Add a multi-stage Dockerfile and hardened Compose definition; validate `docker compose config`.
- [ ] Start Docker Desktop if needed, build with no secrets, deploy local staging and run the smoke check.
- [ ] If a remote target is discoverable, deploy the same immutable image to that test target; otherwise record the exact missing target information without exposing TCP publicly.
- [ ] Run full tests, race detector, static checks, image inspection, public-repo security gate and independent review; then commit, push, PR and merge.
