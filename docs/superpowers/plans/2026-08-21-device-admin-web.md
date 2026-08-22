# Device Admin Web Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a domain-independent, password-protected Web service that manages the PostgreSQL device registry without exposing device credentials or coupling HTTP administration to the TCP gateway.

**Architecture:** Add a separate `admin-web` Go binary with an embedded dependency-free UI, PostgreSQL-backed accounts and sessions, Argon2id password verification, CSRF protection, and strict HTTP middleware. Reuse the existing device administration service after making its audit actor explicit; deploy on a loopback-only port behind an operator-managed HTTPS reverse proxy.

**Tech Stack:** Go 1.24+, `golang.org/x/crypto/argon2`, pgx/v5, PostgreSQL 16, `net/http`, `embed`, Docker Compose, Nginx.

**Spec:** `docs/superpowers/specs/2026-08-21-device-admin-web-design.md`

## Global Constraints

- Never commit a real domain, administrator credential, Session/CSRF token, device Credential/fingerprint, DSN, source IP, payload, or server secret.
- `admin-web` is a separate binary and image from `gateway`; the gateway image contains no management program.
- The service defaults to `127.0.0.1:18181`; production UI/API traffic requires HTTPS termination at a trusted local proxy.
- Password hashes use Argon2id with a random 16-byte salt, 64 MiB memory, 3 iterations, parallelism 2, and 32-byte output.
- Session and CSRF tokens are 32 random bytes; PostgreSQL stores only SHA-256 token digests.
- Session maximum lifetime is eight hours, idle lifetime is one hour, and last-use writes occur at most every five minutes.
- Device Credential bytes exist only during add, are HMACed by the existing `devices.Fingerprinter`, and are never returned or logged.
- Every mutating API requires a valid Session, same-origin request, and synchronizer CSRF token.
- Use red-green-refactor and only synthetic credentials in tests.
- Device deletion, public self-registration, email recovery, OAuth, roles, chat, knowledge and model administration are outside scope.

---

### Task 1: Administrator identity and Argon2id passwords

**Files:**
- Create: `internal/adminauth/types.go`
- Create: `internal/adminauth/password.go`
- Create: `internal/adminauth/password_test.go`
- Modify: `go.mod`
- Modify: `go.sum`

**Interfaces:**
- Produces `adminauth.ID`, `adminauth.User`, `NormalizeUsername`, `PasswordParams`, and `PasswordHasher`.
- `PasswordHasher` exposes `Hash([]byte) (string, error)` and `Verify(string, []byte) (bool, error)`.

- [x] **Step 1: Make x/crypto a direct dependency**

Run `go get golang.org/x/crypto@v0.37.0`. Expected: module version unchanged and `x/crypto` moves from indirect to direct.

- [x] **Step 2: Write failing username and password tests**

Cover usernames matching `^[A-Za-z0-9._-]{3,64}$`, lowercase normalization, Unicode/space rejection, 12—128 byte passwords, random salts, valid/invalid verification, malformed encodings and parameter limits. Use:

```go
var ProductionPasswordParams = PasswordParams{
    MemoryKiB: 64 * 1024,
    Iterations: 3,
    Parallelism: 2,
    SaltBytes: 16,
    KeyBytes: 32,
}
```

- [x] **Step 3: Verify RED**

Run `go test ./internal/adminauth -run 'Test(NormalizeUsername|PasswordHasher)' -count=1`. Expected: FAIL because the package API is absent.

- [x] **Step 4: Implement minimal primitives**

Define:

```go
type ID string
type Status string
const StatusActive Status = "active"
const StatusDisabled Status = "disabled"

type User struct {
    ID ID
    Username string
    Status Status
    PasswordVersion int64
    LastLoginAt *time.Time
}
```

Encode hashes as `$argon2id$v=19$m=65536,t=3,p=2$<salt>$<key>`. Copy randomness inputs, use constant-time key comparison, and return stable errors without password details.

- [x] **Step 5: Verify GREEN and commit**

Run `gofmt -w internal/adminauth`, `go test ./internal/adminauth -count=1`, and `git diff --check`. Expected: PASS.

Commit only Task 1 files with message `feat(admin): add password identity primitives`.

### Task 2: PostgreSQL administrator and Session storage

**Files:**
- Create: `internal/devices/postgres/migrations/0002_admin_web.sql`
- Create: `internal/adminauth/repository.go`
- Create: `internal/adminauth/postgres/repository.go`
- Create: `internal/adminauth/postgres/repository_test.go`
- Modify: `internal/devices/postgres/migrate_test.go`

**Interfaces:**
- Consumes Task 1 identity types.
- Produces `adminauth.Repository` and `adminpostgres.NewRepository(*pgxpool.Pool)`.
- Persists account, Session, password-version and fixed security-event data.

- [x] **Step 1: Write failing migration tests**

Require `admin_users`, `admin_sessions`, and `admin_security_events`; extend `device_admin_events` with nullable `admin_user_id` and allow `actor_type='admin_web'` only when the administrator ID is present. Assert unique normalized username, 32-byte digests, status/action constraints, foreign keys, rollback, concurrency and forward-version rejection.

- [x] **Step 2: Verify schema RED**

Run `./scripts/test-postgres.sh go test ./internal/devices/postgres -run TestMigrate -count=1`. Expected: FAIL because migration version 2 does not exist.

- [x] **Step 3: Add migration version 2**

Create tables with these essential columns:

```sql
CREATE TABLE admin_users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username text NOT NULL CHECK (char_length(username) BETWEEN 3 AND 64),
    username_normalized text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    password_version bigint NOT NULL DEFAULT 1 CHECK (password_version > 0),
    last_login_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
```

`admin_sessions` stores token/CSRF digests, administrator ID, password version, created/last-used/expires/revoked times. `admin_security_events` permits only `account_created`, `password_changed`, and `password_reset`, with actor `local_cli` or `admin_web`.

- [x] **Step 4: Verify migration GREEN**

Run the Step 2 command again. Expected: PASS.

- [x] **Step 5: Write failing repository tests**

Define and test:

```go
type SessionRecord struct {
    User User
    PasswordHash string
    TokenHash [32]byte
    CSRFHash [32]byte
    PasswordVersion int64
    CreatedAt time.Time
    LastUsedAt time.Time
    ExpiresAt time.Time
    RevokedAt *time.Time
}

type Repository interface {
    CreateUser(ctx context.Context, username, normalized, passwordHash string, at time.Time) (User, error)
    FindUserByNormalizedUsername(ctx context.Context, normalized string) (User, string, error)
    CreateSession(ctx context.Context, record SessionRecord) error
    FindSession(ctx context.Context, tokenHash [32]byte, now time.Time) (SessionRecord, error)
    TouchSession(ctx context.Context, tokenHash [32]byte, at time.Time) error
    RevokeSession(ctx context.Context, tokenHash [32]byte, at time.Time) error
    ChangePassword(ctx context.Context, id ID, expectedVersion int64, passwordHash string, at time.Time) (User, error)
    ResetPassword(ctx context.Context, normalized, passwordHash string, at time.Time) error
}
```

Cover duplicate users, disabled users, expired/revoked/version-mismatched Sessions, coalesced touches, transactional password changes/resets and security events.

- [x] **Step 6: Verify repository RED, implement, then GREEN**

Run `./scripts/test-postgres.sh go test ./internal/adminauth/postgres -count=1`; observe missing implementation failure. Implement parameterized pgx queries and stable errors, then rerun with `./internal/devices/postgres`; expected PASS.

- [x] **Step 7: Commit**

Commit Task 2 files with message `feat(admin): add postgres accounts and sessions`.

### Task 3: Login, Session, CSRF, and login limiting service

**Files:**
- Create: `internal/adminauth/service.go`
- Create: `internal/adminauth/service_test.go`
- Create: `internal/adminauth/limiter.go`
- Create: `internal/adminauth/limiter_test.go`

**Interfaces:**
- Consumes Task 1 `PasswordHasher` and Task 2 `Repository`.
- Produces `Service.Login`, `Authenticate`, `VerifyCSRF`, `Logout`, and `ChangePassword`.
- Produces a bounded in-memory `LoginLimiter` that persists no IP or username.

- [x] **Step 1: Write failing authentication-service tests**

Cover unknown-user dummy verification, wrong password, disabled user, uniform authentication errors, valid login, random tokens, digest-only persistence, absolute/idle expiry, CSRF constant-time comparison, five-minute touch coalescing, logout, password change, and Session rotation.

Use:

```go
type LoginResult struct {
    User User
    SessionToken string
    CSRFToken string
    ExpiresAt time.Time
}

func NewService(Repository, *PasswordHasher, *LoginLimiter, func() time.Time, io.Reader) (*Service, error)
func (s *Service) Login(context.Context, string, []byte, net.IP) (LoginResult, error)
func (s *Service) Authenticate(context.Context, string) (User, error)
func (s *Service) VerifyCSRF(context.Context, string, string) error
func (s *Service) Logout(context.Context, string) error
func (s *Service) ChangePassword(context.Context, string, []byte, []byte) (LoginResult, error)
```

- [x] **Step 2: Verify RED**

Run `go test ./internal/adminauth -run 'Test(Service|LoginLimiter)' -count=1`. Expected: FAIL because the service and limiter are absent.

- [x] **Step 3: Implement the login limiter**

HMAC normalized usernames with an ephemeral 32-byte process key and combine with canonical IP bytes. Permit five attempts per minute with burst three, expire entries after 30 minutes, and cap retained entries. Errors expose no keyed identifiers.

- [x] **Step 4: Implement Session service**

Generate 32-byte tokens with `io.ReadFull`, encode raw URL-safe base64, store SHA-256 digests, use `subtle.ConstantTimeCompare` for CSRF, clear password buffers, and collapse invalid/expired/revoked/version-mismatched Sessions to one error.

- [x] **Step 5: Verify GREEN and commit**

Run `gofmt -w internal/adminauth` and `go test -race ./internal/adminauth -count=1`. Expected: PASS. Commit Task 3 files with `feat(admin): add secure login sessions`.

### Task 4: Actor-aware device administration and safe audit views

**Files:**
- Modify: `internal/devices/types.go`
- Modify: `internal/devices/repository.go`
- Modify: `internal/devices/postgres/repository.go`
- Modify: `internal/devices/postgres/repository_test.go`
- Modify: `internal/deviceadmin/service.go`
- Modify: `internal/deviceadmin/service_test.go`
- Modify: `cmd/device-admin/main.go`
- Modify: `cmd/device-admin/main_test.go`

**Interfaces:**
- Produces explicit `devices.AdminActor` and `devices.AdminEvent`.
- Preserves `local_cli` behavior while allowing `admin_web` plus administrator UUID.
- Lists safe event fields without Credential, fingerprint, Token, IP, or arbitrary reason text.

- [x] **Step 1: Write failing actor and event tests**

Prove Web events contain `admin_web` and the authenticated administrator UUID, CLI events remain `local_cli` with no UUID, invalid combinations fail, events order newest first, and disable notifications still disconnect devices.

```go
type AdminActor struct {
    Type string
    AdminUserID string
}

type AdminEvent struct {
    ID int64
    DeviceID ID
    Action string
    ActorType string
    AdminUserID string
    ReasonCode string
    CreatedAt time.Time
}
```

- [x] **Step 2: Verify RED**

Run `./scripts/test-postgres.sh go test ./internal/devices/postgres ./internal/deviceadmin -run 'Test.*(Actor|Event)' -count=1`. Expected: FAIL because managed operations are absent.

- [x] **Step 3: Implement managed repository operations**

Add:

```go
AddManaged(context.Context, AddDevice, AdminActor, string, time.Time) (Device, error)
SetStatusManaged(context.Context, ID, Status, AdminActor, string, time.Time) error
SetExpiryManaged(context.Context, ID, *time.Time, AdminActor, string, time.Time) error
ListAdminEvents(context.Context, int) ([]AdminEvent, error)
```

Keep current methods as `local_cli` compatibility wrappers.

- [x] **Step 4: Extend deviceadmin Service**

Add `AddAs`, `EnableAs`, `DisableAs`, `SetExpiryAs`, and `ListEvents`; each receives the explicit authenticated actor. Retain current CLI methods unchanged externally.

- [x] **Step 5: Verify GREEN and commit**

Run PostgreSQL tests for devices/deviceadmin/device-admin, then `go test ./... -count=1`. Expected: PASS. Commit with `feat(admin): audit web device operations`.

### Task 5: Hardened administration HTTP API

**Files:**
- Create: `internal/adminhttp/server.go`
- Create: `internal/adminhttp/server_test.go`
- Create: `internal/adminhttp/middleware.go`
- Create: `internal/adminhttp/middleware_test.go`
- Create: `internal/adminhttp/json.go`
- Create: `internal/adminhttp/json_test.go`

**Interfaces:**
- Consumes `adminauth.Service` and actor-aware `deviceadmin.Service`.
- Produces `adminhttp.New(Config) (http.Handler, error)`.
- Produces `/api/admin/v1` and `/livez`/`/readyz` routes.

- [x] **Step 1: Write failing API/security tests**

Cover login/logout/me/password, device list/add/status/expiry, audit list, invalid Session, Session expiry, CSRF, same-origin checks, 16 KiB body limit, unknown/trailing JSON, methods, generic errors, MIME types and these headers:

```text
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cache-Control: no-store
```

- [x] **Step 2: Verify RED**

Run `go test ./internal/adminhttp -count=1`. Expected: FAIL because the package is absent.

- [x] **Step 3: Implement strict middleware and JSON**

Use `http.MaxBytesReader`, `DisallowUnknownFields`, a second decode requiring EOF, random request IDs, panic recovery with generic 500, and no request-body logging. Trust `X-Forwarded-Proto=https` and the single `X-Real-IP` value only when `RemoteAddr` is loopback; exempt health probes. The proxy example overwrites both headers instead of appending client values.

- [x] **Step 4: Implement versioned routes**

Return only safe device fields:

```go
type deviceView struct {
    ID string `json:"id"`
    Label string `json:"label"`
    Status string `json:"status"`
    ExpiresAt *time.Time `json:"expires_at"`
    LastAuthenticatedAt *time.Time `json:"last_authenticated_at"`
}
```

Implement exactly these API routes: `POST /session`, `DELETE /session`, `GET /me`, `PUT /me/password`, `GET /devices`, `POST /devices`, `PUT /devices/{id}/status`, `PUT /devices/{id}/expiry`, and `GET /device-events`. Set Cookie `__Host-ai_wechat_admin` with `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, and no Domain. Use fixed error codes only.

- [x] **Step 5: Verify GREEN and commit**

Run `gofmt -w internal/adminhttp` and `go test -race ./internal/adminhttp ./internal/adminauth ./internal/deviceadmin -count=1`. Expected: PASS. Commit with `feat(admin): add hardened device API`.

### Task 6: Embedded administration interface

**Files:**
- Create: `internal/adminhttp/ui/assets.go`
- Create: `internal/adminhttp/ui/index.html`
- Create: `internal/adminhttp/ui/app.css`
- Create: `internal/adminhttp/ui/app.js`
- Create: `internal/adminhttp/ui/assets_test.go`
- Modify: `internal/adminhttp/server.go`
- Modify: `internal/adminhttp/server_test.go`

**Interfaces:**
- Produces dependency-free same-origin assets embedded in the Go binary.
- Consumes only Task 5 `/api/admin/v1` routes.

- [x] **Step 1: Write failing asset and page-flow tests**

Assert all assets exist, no CDN/remote URL or inline script/style is present, labels render through `textContent`, Credential/fingerprint never render, and controls exist for login, add, enable, disable, expiry, audit, password change and logout.

- [x] **Step 2: Verify RED**

Run `go test ./internal/adminhttp/ui ./internal/adminhttp -run 'Test.*(Asset|Page|Flow)' -count=1`. Expected: FAIL because assets are absent.

- [x] **Step 3: Implement accessible responsive HTML/CSS**

Use semantic Chinese form labels, keyboard-visible focus, text plus color for status, confirmation for disable/expiry, no analytics, no external font/image, and no Node build chain.

- [x] **Step 4: Implement the minimal JavaScript client**

Use same-origin `fetch`, keep CSRF only in memory, render user content with `textContent`, clear Credential/password inputs immediately after submission, return to login on 401, and show generic retry guidance on 503.

- [x] **Step 5: Verify GREEN and commit**

Run UI and HTTP tests. Expected: PASS. Commit Task 6 files with `feat(admin): add embedded device console`.

### Task 7: Administrator commands and production runtime

**Files:**
- Create: `cmd/admin-user/main.go`
- Create: `cmd/admin-user/main_test.go`
- Create: `cmd/admin-web/main.go`
- Create: `cmd/admin-web/main_test.go`
- Create: `Dockerfile.admin`
- Modify: `Dockerfile.tools`

**Interfaces:**
- Produces `admin-user create|reset-password` with hidden, repeated terminal password input.
- Produces `admin-web` configured by loopback address and secure files only.
- Produces a scratch admin image containing only `admin-web` and CA certificates.

- [ ] **Step 1: Write failing command/configuration tests**

Cover missing/unsafe DSN and pepper files, invalid/non-loopback addresses, database unavailable, hidden password input, mismatch, duplicate user, reset, signals, graceful shutdown and generic console errors.

```text
ADMIN_HTTP_ADDRESS=127.0.0.1:18181
ADMIN_DATABASE_DSN_FILE=/run/secrets/device_database_dsn
ADMIN_DEVICE_PEPPER_FILE=/run/secrets/device_pepper
ADMIN_TRUST_HTTPS_PROXY=true
```

- [ ] **Step 2: Verify RED**

Run `go test ./cmd/admin-user ./cmd/admin-web -count=1`. Expected: FAIL because both commands are absent.

- [ ] **Step 3: Implement admin-user**

Reuse `securefile`, `PasswordHasher`, and the PostgreSQL repository. Require a terminal for production passwords, print only stable success text plus administrator UUID, and never accept passwords in flags/environment.

- [ ] **Step 4: Implement admin-web lifecycle**

Open bounded pools, construct services/handler, apply explicit HTTP timeouts, handle SIGINT/SIGTERM, and allow ten seconds for graceful shutdown. Startup logs include only the loopback address and stable mode.

- [ ] **Step 5: Build and inspect isolated images**

`Dockerfile.admin` builds/copies only `/admin-web` and CA certificates into scratch. `Dockerfile.tools` adds `/admin-user`; the gateway Dockerfile remains unchanged. Build and inspect that admin lacks device-import/gateway and gateway lacks all admin binaries.

- [ ] **Step 6: Verify GREEN and commit**

Run command tests and both image builds. Expected: PASS. Commit with `feat(admin): add web runtime and user tool`.

### Task 8: Compose, smoke, documentation, and remote candidate

**Files:**
- Modify: `deploy/compose.yaml`
- Modify: `deploy/smoke.sh`
- Create: `deploy/admin_smoke_test.go`
- Modify: `docs/deployment.md`
- Create: `docs/nginx/admin-web.conf.example`
- Modify: `docs/tasks/TASK-0007.md`
- Modify: `PROJECT_STATUS.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Produces loopback-only Compose deployment and generic HTTPS reverse-proxy example.
- Produces end-to-end synthetic login/device lifecycle verification.

- [ ] **Step 1: Extend smoke tests and verify RED**

Assert migration v2, administrator creation, login/cookie/CSRF, add/list/disable/enable/expiry/password/logout, Session invalidation, audit, restart persistence, security headers, loopback port, non-root/read-only/cap-drop/resources and image isolation.

Run `./deploy/smoke.sh`. Expected: FAIL because no admin service/image exists.

- [ ] **Step 2: Add hardened Compose service**

Add `admin-web` to `edge` and `registry`; publish `127.0.0.1:${ADMIN_HTTP_HOST_PORT:-18181}:18181`; mount registry secrets read-only; depend on migration; run UID 65532 with read-only root, all capabilities dropped, no-new-privileges, 128 MiB, 50 PIDs and 0.5 CPU.

- [ ] **Step 3: Add domain-independent proxy/deployment docs**

Require the operator to fill `server_name`, redirect HTTP to HTTPS, proxy to loopback, set `X-Forwarded-Proto https`, discard arbitrary client forwarding headers, and set conservative request/time limits. Include no real domain, certificate path, server address, credential or panel path.

- [ ] **Step 4: Run complete local verification**

Run:

```sh
./deploy/smoke.sh
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
./scripts/test-postgres.sh go test ./internal/devices/postgres ./internal/adminauth/postgres -count=1
git diff --check
```

Expected: every command PASS.

- [ ] **Step 5: Perform public/image safety review**

Inspect working/staged diffs, ignored files, build contexts, image histories and binary lists. Search for real domains, server addresses, credentials, `.env`, DB files, logs, dumps, Session tokens, device values and local deployment paths. Expected: no sensitive match and no management binary in the gateway image.

- [ ] **Step 6: Deploy isolated remote candidate**

Build reviewed Linux AMD64 images, compare local/server SHA-256, load without replacing the existing gateway, migrate, create a temporary synthetic administrator through hidden server-terminal input, bind admin to a new loopback port, and execute the synthetic lifecycle. Do not configure the final domain or switch `19090`.

- [ ] **Step 7: Record exact results and commit**

Update TASK-0007 with sanitized commands/results, mark only proven acceptance items, update project status/changelog, inspect staged diff, and commit with `feat(deploy): stage device admin web`.

- [ ] **Step 8: Handoff before public exposure**

Provide the loopback port and generic proxy instructions. The user resolves their domain, configures HTTPS, creates the real administrator locally, adds one real device, and explicitly approves the later `19090` cutover after APK authentication succeeds.
