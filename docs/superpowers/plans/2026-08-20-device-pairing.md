# Secure Device Pairing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pair one real staging device safely, return the legacy-compatible authentication response, and enforce its per-connection access token.

**Architecture:** Recover only the missing authentication-response wire contract, then add a focused `internal/pairing` authenticator backed by an atomic server-local credential fingerprint. The gateway owns session-token issuance and validation; the TCP server supplies the peer IP, while command wiring remains deny-all unless every pairing setting is valid.

**Tech Stack:** Go 1.24+, protocompile v0.14.1, google.golang.org/protobuf v1.36.12, standard-library crypto/net/filesystem APIs, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-08-20-device-pairing-design.md`

## Global Constraints

- The repository is public; never commit or log a real Credential, fingerprint, AccessToken, source IP, packet, payload, or server secret.
- Authentication remains deny-all unless a complete pairing configuration is supplied.
- Pairing accepts one Credential and can never overwrite an existing fingerprint state file.
- The running container remains non-root, read-only except for its dedicated pairing-state bind mount, capability-free, and resource-limited.
- Production code follows strict red-green-refactor; each behavior test must be observed failing before implementation.

---

### Task 1: Recover the authentication-response protocol

**Files:**
- Create: `proto/minimal/DeviceAuthRsp.proto`
- Modify: `proto/minimal/TransportMessage.proto`
- Modify: `proto/schema/schema.go`
- Modify: `proto/compat/schema_test.go`
- Modify: `proto/compat/fixtures_test.go`
- Modify: `proto/compat/verify_legacy_php.php`
- Modify: `proto/testdata/synthetic_frames.json`
- Modify: `docs/protocol.md`

**Interfaces:**
- Produces descriptor `Jubo.JuLiao.IM.Wx.Proto.DeviceAuthRspMessage` with `AccessToken=1 string`, optional nested `Extra=2`, and `EnumMsgType.DeviceAuthRsp=1011`.
- Produces three public fixtures named `device-auth-rsp-normal`, `device-auth-rsp-boundary`, and `device-auth-rsp-unknown`.

- [x] **Step 1: Write failing schema and fixture tests**

Add literal field assertions for `DeviceAuthRspMessage`, all six `ExtraMessage` fields, enum 1011, exact type URL, a hand-checked `synthetic-token`, and unknown-field preservation. Extend the legacy verifier to decode and re-encode the same public fixtures.

- [x] **Step 2: Verify RED**

Run: `go test ./proto/schema ./proto/compat -count=1`

Expected: FAIL because `DeviceAuthRspMessage` and enum value 1011 are absent.

- [x] **Step 3: Add the minimal schema and synthetic fixtures**

Use the exact recovered contract:

```proto
message DeviceAuthRspMessage {
  string AccessToken = 1;
  message ExtraMessage {
    int64 SupplierId = 1;
    int64 UnionId = 2;
    EnumAccountType AccountType = 3;
    string SupplierName = 4;
    string NickName = 5;
    string Token = 6;
  }
  ExtraMessage Extra = 2;
}
```

Define only the observed `EnumAccountType` zero/default value needed to compile; record that nonzero values remain outside this task. Build fixtures dynamically in the test helper and persist only reviewed synthetic bytes in JSON.

- [x] **Step 4: Verify GREEN and compatibility**

Run: `go test ./proto/schema ./proto/compat -count=1`

Expected: PASS, including the PHP verifier when its runtime is available.

- [x] **Step 5: Commit**

Commit message: `feat(protocol): recover device auth response`

### Task 2: Implement atomic one-device pairing

**Files:**
- Create: `internal/pairing/authenticator.go`
- Create: `internal/pairing/authenticator_test.go`
- Create: `internal/pairing/store.go`
- Create: `internal/pairing/store_test.go`

**Interfaces:**
- Consumes: `gateway.AuthRequest{AuthType int32, Credential string, PeerIP net.IP}`.
- Produces: `pairing.New(Config) (*Authenticator, error)` and `Authenticate(context.Context, gateway.AuthRequest) (gateway.AuthResult, error)`.
- `pairing.Config` fields: `StateFile string`, `Enrollment bool`, `AllowedCIDRs []*net.IPNet`, `Now func() time.Time`, `Random io.Reader`.

- [x] **Step 1: Write failing store tests**

Test real temporary directories. Assert first creation succeeds, a concurrent second different fingerprint cannot overwrite, reload returns the first fingerprint, the file mode is `0600`, and file bytes do not contain the synthetic Credential.

- [x] **Step 2: Verify store tests RED**

Run: `go test ./internal/pairing -run TestStore -count=1`

Expected: FAIL because the package does not exist.

- [x] **Step 3: Implement the minimal atomic store**

Write versioned JSON to an exclusive temporary file, `Sync`, close, and atomically publish without replacing an existing state. Treat malformed state or unsafe permissions as an error.

- [x] **Step 4: Write failing authenticator tests**

Use literal synthetic credentials and loopback documentation ranges. Cover deny-all without state, invalid auth type, empty/oversized Credential, enrollment source rejection, first enrollment, same-device reload, different-device rejection, and 32-byte random Token encoded as 64 lowercase hex characters.

- [x] **Step 5: Verify authenticator tests RED**

Run: `go test ./internal/pairing -run TestAuthenticator -count=1`

Expected: FAIL because the authenticator is absent.

- [x] **Step 6: Implement and verify GREEN**

Hash Credential with SHA-256 only inside the authenticator, compare with `subtle.ConstantTimeCompare`, never format the Credential or fingerprint into errors, and use stable error categories.

Run: `go test ./internal/pairing -race -count=1`

Expected: PASS.

- [x] **Step 7: Commit**

Commit message: `feat(gateway): add one-device pairing authenticator`

### Task 3: Return auth response and enforce session Token

**Files:**
- Modify: `internal/protocol/codec.go`
- Modify: `internal/protocol/codec_test.go`
- Modify: `internal/gateway/handler.go`
- Modify: `internal/gateway/handler_test.go`
- Modify: `internal/server/server.go`
- Modify: `internal/server/server_test.go`

**Interfaces:**
- `protocol.Decoded` adds `AccessToken string`.
- `protocol.Codec` adds `EncodeDeviceAuth(accessToken string) ([]byte, error)`.
- `gateway.AuthRequest` contains auth type, Credential, and peer IP.
- `gateway.AuthResult` contains `AccessToken string` and `ExpiresAt time.Time`.
- `gateway.NewSession(peerIP net.IP) *Session` stores an immutable copied peer IP and session Token state.

- [x] **Step 1: Write failing protocol tests**

Assert the encoded response decodes to MsgType 1011, exact type URL, literal AccessToken, and default outer Id/Ref/AccessToken fields. Assert `Decode` exposes a literal outer AccessToken from an authenticated heartbeat fixture built in the test.

- [x] **Step 2: Verify protocol RED, implement, and verify GREEN**

Run RED then GREEN: `go test ./internal/protocol -count=1`

- [x] **Step 3: Write failing handler/session tests**

Assert auth success returns a response before authentication becomes usable, failed response encoding leaves the session unauthenticated, correct Token permits heartbeat, and missing/wrong/expired Token returns stable sentinel errors. Use a deterministic fake clock and synthetic Token.

- [x] **Step 4: Verify handler RED, implement, and verify GREEN**

Run RED then GREEN: `go test ./internal/gateway ./internal/server -race -count=1`

The handler sets authenticated state only after `EncodeDeviceAuth` succeeds. Token comparison uses `subtle.ConstantTimeCompare`; the server creates the Session from `connection.RemoteAddr()` without logging it.

- [x] **Step 5: Commit**

Commit message: `feat(gateway): complete device authentication handshake`

### Task 4: Wire safe configuration and deployment state

**Files:**
- Modify: `cmd/gateway/main.go`
- Modify: `cmd/gateway/main_test.go`
- Modify: `.gitignore`
- Modify: `deploy/compose.yaml`
- Modify: `deploy/smoke.sh`
- Modify: `docs/deployment.md`

**Interfaces:**
- Adds `GATEWAY_PAIRING_STATE_FILE`, `GATEWAY_PAIRING_ENABLED`, and `GATEWAY_PAIRING_ALLOWED_CIDRS`.
- `loadConfig` parses CIDRs and returns an error for partial, malformed, or unsafe pairing configuration.
- Default configuration still selects `gateway.DenyAllAuthenticator`.

- [x] **Step 1: Write failing config tests**

Cover empty default, complete pairing config, invalid boolean, missing state file, empty CIDR list, malformed CIDR, and state path outside the configured writable state root.

- [x] **Step 2: Verify config RED, implement, and verify GREEN**

Run RED then GREEN: `go test ./cmd/gateway -count=1`

- [x] **Step 3: Update hardened deployment**

Add a Git-ignored `deploy/state/` bind mount owned by UID/GID 65532 for local smoke only. The checked-in Compose keeps pairing disabled and contains no real CIDR, fingerprint, Token, IP, or domain.

- [x] **Step 4: Run local integration verification**

Run:

```sh
gofmt -w cmd internal proto
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
./deploy/smoke.sh
```

Expected: all commands PASS; the default smoke remains deny-all and healthy.

- [ ] **Step 5: Commit**

Commit message: `feat(deploy): wire secure pairing configuration`

### Task 5: Document, review, and deploy the real-device staging test

**Files:**
- Modify: `docs/tasks/TASK-0005.md`
- Modify: `PROJECT_STATUS.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/deployment.md`
- Modify: `docs/protocol.md`

**Interfaces:**
- Produces a server-only state directory and locked credential fingerprint; no runtime secret becomes a repository artifact.
- Produces a remote verification record containing only pass/fail, durations, health, and restart count.

- [ ] **Step 1: Run repository safety review**

Inspect `git status`, every unstaged/staged diff, ignored state paths, forbidden file classes, local links, Markdown endings, and credential patterns before committing.

- [ ] **Step 2: Update public documentation**

Record exact automated results and clarify that one staging device can pair while file upload, AI processing, and production TLS remain incomplete.

- [ ] **Step 3: Commit documentation**

Commit message: `docs: record secure pairing implementation`

- [x] **Step 4: Build and deploy deny-all candidate**

Cross-compile Linux AMD64, verify SHA-256 locally and remotely, replace only the isolated gateway container, and confirm running/healthy/restart=0 before pairing is enabled.

- [ ] **Step 5: Perform the one-time pairing window**

Determine the current device source IP only on the server, configure a narrow temporary CIDR without echoing it to chat or files under Git, enable enrollment, and observe one successful state creation. Immediately remove enrollment/CIDR settings and restart locked.

- [ ] **Step 6: Verify the real device safely**

Verify authentication response, at least three heartbeat intervals, one disconnect/reconnect, unknown synthetic Credential rejection, container health, and restart count. Do not save payloads or identifiers.

- [ ] **Step 7: Final full verification and status update**

Run `go test ./... -count=1`, `go test -race ./... -count=1`, `go vet ./...`, Markdown link/format checks, secret scan, `git diff --check`, and remote health checks. Record the actual results in TASK-0005 before any completion claim.
