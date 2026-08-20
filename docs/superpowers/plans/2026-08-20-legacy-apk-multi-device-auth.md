# Legacy APK Multi-Device Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace single-device pairing with a PostgreSQL-backed registry that authenticates up to 100 unchanged legacy APK devices, imports only necessary legacy authorization data once, and supports revocation, connection takeover, and abuse limits.

**Architecture:** Preserve the legacy `1010 -> 1011` wire contract while introducing a keyed Credential fingerprinter, PostgreSQL device repository, registry authenticator, and generation-safe in-memory connection directory. Keep legacy-database access in a separate one-shot import binary; the gateway depends only on the new PostgreSQL database and server-mounted secret files.

**Tech Stack:** Go 1.24+, pgx/v5, go-sql-driver/mysql, PostgreSQL 16, protocompile v0.14.1, google.golang.org/protobuf v1.36.12, standard-library HMAC/rate-limiting primitives, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-08-20-legacy-apk-multi-device-auth-design.md`

## Global Constraints

- The repository is public; never commit or log a real Credential, fingerprint, AccessToken, database DSN, source IP, legacy schema name, query, row, payload, or server secret.
- The unchanged APK wire contract remains TCP with `DeviceAuthReq=1010`, `DeviceAuthRsp=1011`, and the existing Protobuf field numbers and type URLs.
- Runtime authentication must use only the new PostgreSQL registry; it must never fall back to the legacy database or the single-device pairing file.
- Persist `HMAC-SHA-256(server_pepper, exact Credential bytes)`, never a plaintext Credential or unkeyed SHA-256 fingerprint.
- Unknown, disabled, expired, rate-limited, and backend-unavailable devices receive indistinguishable connection-close behavior.
- PostgreSQL or pepper failure is fail-closed; partial configuration prevents gateway startup.
- The first release targets one gateway, at most 100 concurrently expected devices, 150 authenticated-connection capacity, and no public admin HTTP endpoint.
- Production code follows strict red-green-refactor; every new behavior test must be observed failing for the intended reason before implementation.
- All fixtures and integration rows use synthetic documentation-only values.

---

### Task 1: Define device identity and keyed fingerprinting

**Files:**
- Create: `internal/devices/types.go`
- Create: `internal/devices/fingerprint.go`
- Create: `internal/devices/fingerprint_test.go`
- Create: `internal/devices/repository.go`
- Modify: `go.mod`
- Modify: `go.sum`

**Interfaces:**
- Produces `type ID string`, `type Status string`, constants `StatusActive` and `StatusDisabled`, and `const DefaultTenantID = "00000000-0000-0000-0000-000000000001"` for the first single-tenant release.
- Produces `type Device struct { ID ID; TenantID string; Label string; Status Status; AuthExpiresAt *time.Time; LastAuthenticatedAt *time.Time }`.
- Produces `type Fingerprint [32]byte` and `type Fingerprinter struct`.
- Produces `func NewFingerprinter(pepper []byte) (*Fingerprinter, error)`; it accepts exactly 32 bytes and copies the input.
- Produces `func (f *Fingerprinter) Sum(credential string) Fingerprint` using HMAC-SHA-256 over exact Go string bytes.
- Produces repository methods used later: `Authorize`, `TouchAuthenticated`, `Add`, `List`, `SetStatus`, and `SetExpiry`.

- [x] **Step 1: Add the pgx dependency**

Run:

```sh
go get github.com/jackc/pgx/v5@v5.7.6
```

Expected: `go.mod` and `go.sum` add pgx/v5 without changing the Go language version.

- [x] **Step 2: Write failing fingerprint tests**

Create table-driven tests with synthetic values that assert:

```go
func TestNewFingerprinterRequiresExactly32PepperBytes(t *testing.T)
func TestFingerprinterUsesHMACSHA256OverExactCredentialBytes(t *testing.T)
func TestFingerprinterCopiesPepperInput(t *testing.T)
```

The exact-byte test must compare against `hmac.New(sha256.New, pepper)` computed independently in the test and must prove that leading space and case changes produce different fingerprints.

- [x] **Step 3: Verify RED**

Run: `go test ./internal/devices -run 'Test(NewFingerprinter|Fingerprinter)' -count=1`

Expected: FAIL because `Fingerprinter` does not exist.

- [x] **Step 4: Implement the minimal types and fingerprinter**

Use the following signatures:

```go
func NewFingerprinter(pepper []byte) (*Fingerprinter, error)
func (fingerprinter *Fingerprinter) Sum(credential string) Fingerprint
func (fingerprint Fingerprint) Bytes() []byte
```

`Bytes` returns a copy. Errors contain only configuration categories, never secret lengths supplied by a real deployment.

- [x] **Step 5: Define the repository contract**

Use:

```go
type AddDevice struct {
    Fingerprint Fingerprint
    TenantID string
    Label string
    Status Status
    AuthExpiresAt *time.Time
}

type Repository interface {
    Authorize(context.Context, Fingerprint, time.Time) (Device, error)
    TouchAuthenticated(context.Context, ID, time.Time) error
    Add(context.Context, AddDevice) (Device, error)
    List(context.Context, int) ([]Device, error)
    SetStatus(context.Context, ID, Status, string, time.Time) error
    SetExpiry(context.Context, ID, *time.Time, string, time.Time) error
}
```

Define stable sentinels `ErrNotAuthorized`, `ErrAlreadyExists`, `ErrNotFound`, and `ErrInvalidInput`. `Authorize` must collapse unknown, disabled, and expired records to `ErrNotAuthorized`.

- [x] **Step 6: Verify GREEN and commit**

Run:

```sh
gofmt -w internal/devices
go test ./internal/devices -count=1
git diff --check
```

Expected: PASS.

Commit: `feat(devices): add keyed device identity`

### Task 2: Add PostgreSQL schema and repository

**Files:**
- Create: `internal/devices/postgres/migrations/0001_devices.sql`
- Create: `internal/devices/postgres/migrations/embed.go`
- Create: `internal/devices/postgres/migrate.go`
- Create: `internal/devices/postgres/migrate_test.go`
- Create: `internal/devices/postgres/repository.go`
- Create: `internal/devices/postgres/repository_test.go`
- Create: `deploy/compose.test.yaml`
- Create: `scripts/test-postgres.sh`

**Interfaces:**
- Produces `func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error)` with bounded connection settings.
- Produces `func Migrate(ctx context.Context, pool *pgxpool.Pool) error` with an advisory lock and version table.
- Produces `func NewRepository(pool *pgxpool.Pool) *Repository` implementing `devices.Repository`.
- Produces a repeatable real-PostgreSQL test command; integration tests require `TEST_POSTGRES_DSN` and never embed credentials.

- [x] **Step 1: Write the migration SQL and failing migration tests**

The migration creates:

```sql
CREATE TABLE schema_migrations (
    version bigint PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    credential_fingerprint bytea NOT NULL UNIQUE,
    credential_version smallint NOT NULL DEFAULT 1 CHECK (credential_version = 1),
    label text NOT NULL DEFAULT '' CHECK (char_length(label) <= 120),
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    auth_expires_at timestamptz NULL,
    last_authenticated_at timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (octet_length(credential_fingerprint) = 32)
);

CREATE TABLE device_admin_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES devices(id),
    action text NOT NULL CHECK (action IN ('created', 'enabled', 'disabled', 'expiry_changed')),
    actor_type text NOT NULL CHECK (actor_type IN ('migration', 'local_cli')),
    reason_code text NOT NULL CHECK (reason_code IN ('legacy_import', 'manual_add', 'manual_enable', 'manual_disable', 'manual_expiry')),
    created_at timestamptz NOT NULL
);
```

Tests assert one-time migration, concurrent migration serialization, every CHECK constraint, the unique fingerprint, and rollback on a failing migration.

- [x] **Step 2: Create the isolated PostgreSQL test harness and verify RED**

`scripts/test-postgres.sh` must use `mktemp -d`, generate test-only random credentials, start only `deploy/compose.test.yaml`, wait on `pg_isready`, export `TEST_POSTGRES_DSN` only to the test process, and always run `docker compose down -v` in a trap.

Run: `./scripts/test-postgres.sh go test ./internal/devices/postgres -run TestMigrate -count=1`

Expected: FAIL because `Migrate` is absent or constraints are not installed.

- [x] **Step 3: Implement migration runner and verify GREEN**

Embed ordered `.sql` files, acquire one fixed PostgreSQL advisory lock for the transaction, apply each unapplied version once, and reject a database version newer than the binary.

Run: `./scripts/test-postgres.sh go test ./internal/devices/postgres -run TestMigrate -count=1`

Expected: PASS.

- [x] **Step 4: Write failing repository behavior tests**

Cover active/no-expiry, active/future-expiry, exact-expiry rejection, disabled rejection, unknown rejection, duplicate Add, list limit validation, status changes, expiry changes, audit events, and `TouchAuthenticated` write coalescing within one hour.

Tests must assert only stable sentinel errors and synthetic internal UUIDs; no test output may include a fingerprint.

- [x] **Step 5: Verify repository RED, implement, and verify GREEN**

Run RED before implementation, then GREEN:

```sh
./scripts/test-postgres.sh go test ./internal/devices/postgres -run 'TestRepository' -count=1
```

Use parameterized pgx queries. `Authorize` uses one indexed equality lookup and returns `ErrNotAuthorized` for all non-authorized states. Administrative updates and their audit event occur in the same transaction. Insert the event with `RETURNING id`, then publish `pg_notify('device_admin_events', event_id || ':' || device_id::text)`; PostgreSQL releases the notification only after commit.

- [x] **Step 6: Commit**

Run: `./scripts/test-postgres.sh go test ./internal/devices/postgres -count=1`

Expected: PASS.

Commit: `feat(devices): add postgres registry`

### Task 3: Implement registry-backed legacy authentication

**Files:**
- Create: `internal/deviceauth/authenticator.go`
- Create: `internal/deviceauth/authenticator_test.go`
- Modify: `internal/gateway/handler.go`
- Modify: `internal/gateway/handler_test.go`
- Modify: `internal/pairing/authenticator.go`
- Modify: `internal/pairing/authenticator_test.go`

**Interfaces:**
- `gateway.AuthResult` adds `DeviceID devices.ID`; the legacy pairing authenticator leaves it empty because it is staging-only.
- `gateway.Session` stores the authorized internal device ID but never the Credential or fingerprint.
- Produces `deviceauth.New(repository devices.Repository, fingerprinter *devices.Fingerprinter, limiter AttemptLimiter, now func() time.Time, random io.Reader) (*Authenticator, error)`.
- `AttemptLimiter` has `Allow(net.IP, devices.Fingerprint, time.Time) error`, `Failure(devices.Fingerprint, time.Time)`, and `Success(devices.Fingerprint)`.

- [x] **Step 1: Write failing authenticator tests**

Use a real in-memory fake repository, not mock call assertions. Cover:

```go
func TestAuthenticatorAcceptsLegacyAuthTypesZeroAndOne(t *testing.T)
func TestAuthenticatorRejectsOtherAuthTypesAndInvalidCredential(t *testing.T)
func TestAuthenticatorCollapsesUnknownDisabledAndExpired(t *testing.T)
func TestAuthenticatorReturnsInternalDeviceIDAndRandomOneHourToken(t *testing.T)
func TestAuthenticatorFailsClosedWhenRepositoryFails(t *testing.T)
func TestAuthenticatorDoesNotExposeCredentialOrFingerprintInErrors(t *testing.T)
```

- [x] **Step 2: Verify RED**

Run: `go test ./internal/deviceauth ./internal/gateway -count=1`

Expected: FAIL because `internal/deviceauth` and `AuthResult.DeviceID` are absent.

- [x] **Step 3: Implement the minimal authenticator**

Validate Protobuf string input as nonempty valid UTF-8 and at most 4096 bytes without trimming or normalization. Compute the HMAC once, apply the attempt limiter before repository access, authorize against the supplied clock, generate 32 random bytes, and return a 64-character lowercase hexadecimal token expiring in one hour.

Call `Failure` only for authorization rejection; a PostgreSQL outage consumes the IP attempt token but does not extend per-Credential backoff. After authorization and token generation, call `TouchAuthenticated`; failure is fail-closed but does not extend Credential backoff. Call `Success` only after the touch succeeds. Error strings contain categories only.

- [x] **Step 4: Extend session identity without changing wire output**

Store `AuthResult.DeviceID` when the session becomes authenticated and expose:

```go
func (session *Session) DeviceID() (devices.ID, bool)
func (session *Session) TakePendingActivation() (devices.ID, bool)
```

`TakePendingActivation` succeeds once, only for nonempty registry-authenticated IDs. Existing pairing tests continue to pass and never invent a device identifier.

- [x] **Step 5: Verify GREEN and commit**

Run:

```sh
gofmt -w internal/deviceauth internal/gateway internal/pairing
go test ./internal/deviceauth ./internal/gateway ./internal/pairing -race -count=1
```

Expected: PASS.

Commit: `feat(gateway): authenticate registered devices`

### Task 4: Add generation-safe multi-device connection ownership

**Files:**
- Create: `internal/server/device_connections.go`
- Create: `internal/server/device_connections_test.go`
- Modify: `internal/server/server.go`
- Modify: `internal/server/server_test.go`
- Create: `internal/devices/postgres/notifications.go`
- Create: `internal/devices/postgres/notifications_test.go`
- Modify: `cmd/gateway/main.go`
- Modify: `cmd/gateway/main_test.go`

**Interfaces:**
- Produces `newDeviceConnections(max int) *deviceConnections`.
- Produces `Register(deviceID devices.ID, connection net.Conn) (generation uint64, replaced net.Conn, err error)`.
- Produces `Unregister(deviceID devices.ID, generation uint64)` and `CloseDevice(deviceID devices.ID)`.
- `Server` exposes `DisconnectDevice(devices.ID)` and registers a pending session only after the 1011 response is written successfully.
- Produces `postgres.NewAdminEventListener(ctx context.Context, dsn string, onDevice func(devices.ID)) (*AdminEventListener, error)`; construction establishes the initial dedicated pgx connection, subscribes with `LISTEN`, and records the current maximum admin-event ID before any device connection can be accepted.
- Produces `func (listener *AdminEventListener) Run(ctx context.Context) error`; it receives `eventID:deviceUUID` notifications, reconnects with bounded backoff, queries every event newer than its cursor after reconnect, de-duplicates event IDs, and stops on context cancellation.

- [x] **Step 1: Write failing directory tests**

Cover two different simultaneous device IDs, same-device replacement, maximum capacity, old-generation unregister after replacement, explicit device close, and concurrent register/unregister under `go test -race`.

- [x] **Step 2: Verify RED, implement the directory, and verify GREEN**

Run RED then GREEN:

```sh
go test ./internal/server -run TestDeviceConnections -race -count=1
```

The directory never logs device IDs and closes connections outside its mutex.

- [x] **Step 3: Write failing server integration tests**

Use synthetic auth results with internal IDs. Assert:

- failed auth-response write never registers the connection;
- successful auth-response write registers it;
- a second connection for the same ID receives its response before the first closes;
- closing the replaced connection does not unregister the replacement;
- different device IDs stay online together;
- capacity overflow closes the newly authenticated connection without evicting an existing different device.

- [x] **Step 4: Implement post-write activation and verify GREEN**

After `frame.Write` succeeds, call `session.TakePendingActivation`, register the connection, store the returned generation in the serving goroutine, then close any replaced connection. The deferred cleanup unregisters only the exact device ID/generation pair.

Run: `go test ./internal/server -race -count=1`

Expected: PASS.

- [x] **Step 5: Add PostgreSQL admin-event listener tests and implementation**（监听与断线补偿已完成；`cmd/gateway` 接线随任务 6 的安全注册表配置一并完成）

Integration tests publish synthetic event-ID/UUID payloads, duplicate and out-of-order IDs, malformed payloads, disconnect/reconnect the listener with an event committed during the gap, and cancel its context. The gap event must reach the callback through catch-up; malformed payloads increment only a category counter and never reach the callback.

Run RED then GREEN:

```sh
./scripts/test-postgres.sh go test ./internal/devices/postgres -run TestListenAdminEvents -count=1
```

Wire the callback in `cmd/gateway` to `service.DisconnectDevice`. `NewAdminEventListener` failure prevents registry-auth gateway startup; after construction, `Run` executes in the gateway error group. A later connection loss retries from one second to a maximum of 30 seconds while device authorization remains fail-closed through repository queries.

- [x] **Step 6: Commit**

Run:

```sh
go test ./internal/server ./cmd/gateway -race -count=1
./scripts/test-postgres.sh go test ./internal/devices/postgres -count=1
```

Expected: PASS.

Commit: `feat(gateway): manage multi-device connections`

### Task 5: Add connection admission and authentication abuse limits

**Files:**
- Create: `internal/ratelimit/auth.go`
- Create: `internal/ratelimit/auth_test.go`
- Create: `internal/server/admission.go`
- Create: `internal/server/admission_test.go`
- Modify: `internal/server/server.go`
- Modify: `internal/server/server_test.go`
- Modify: `cmd/gateway/main.go`
- Modify: `cmd/gateway/main_test.go`

**Interfaces:**
- Produces `ratelimit.NewAuth(Config) (*Auth, error)` implementing `deviceauth.AttemptLimiter`.
- `ratelimit.Config` contains `AttemptsPerMinute=20`, `Burst=5`, `MaximumBackoff=15*time.Minute`, `Now`, and a 32-byte ephemeral random key.
- Produces `server.NewAdmission(maxUnauthenticated int, maxPerIP int) *Admission` with `Acquire(net.IP) (release func(), error)`.
- Adds gateway config keys `GATEWAY_MAX_UNAUTHENTICATED_CONNECTIONS`, `GATEWAY_MAX_UNAUTHENTICATED_PER_IP`, and `GATEWAY_MAX_AUTHENTICATED_CONNECTIONS` with defaults 50, 5, and 150.

- [x] **Step 1: Write failing auth-limiter tests**

Use a fake clock. Assert initial burst 5, refill rate 20/minute, IP isolation, keyed 16-byte in-memory Credential identifiers, exponential failure delays capped at 15 minutes, success reset, stale-entry cleanup, and no raw IP/fingerprint in exposed state.

- [x] **Step 2: Verify RED, implement, and verify GREEN**

Run RED then GREEN:

```sh
go test ./internal/ratelimit -race -count=1
```

Use a mutex-protected token bucket and backoff map. Never use `time.Sleep`; all decisions use the injected clock.

- [x] **Step 3: Write failing admission tests**

Cover total unauthenticated capacity, per-IP capacity, nil/unparseable IP rejection, release idempotence, concurrent acquire/release, and IPv4-mapped IPv6 canonicalization.

- [x] **Step 4: Verify RED, implement, and wire the server**

Run RED then GREEN:

```sh
go test ./internal/server -run 'TestAdmission|TestServerRejectsExcessUnauthenticated' -race -count=1
```

Acquire immediately after `Accept`; reject without starting a goroutine when capacity is unavailable. Release the unauthenticated lease once an authentication response is written successfully, including rollback pairing mode without an internal device ID, or when the connection closes.

- [x] **Step 5: Add failing config tests and wire limits**

Test defaults, zero, negative, malformed, overflow, and authenticated capacity smaller than one. Pass authenticated capacity to the device connection directory and the other two values to `Admission`.

Run: `go test ./cmd/gateway ./internal/deviceauth ./internal/ratelimit ./internal/server -race -count=1`

Expected: PASS after implementation.

- [x] **Step 6: Commit**

Commit: `feat(gateway): limit device authentication abuse`

### Task 6: Add safe registry configuration and lifecycle wiring

**Files:**
- Create: `internal/securefile/read.go`
- Create: `internal/securefile/read_test.go`
- Modify: `cmd/gateway/main.go`
- Modify: `cmd/gateway/main_test.go`
- Modify: `internal/devices/postgres/repository.go`
- Modify: `internal/devices/postgres/repository_test.go`
- Modify: `docs/deployment.md`

**Interfaces:**
- Adds `GATEWAY_AUTH_MODE=deny-all|pairing|device-registry`.
- Adds `GATEWAY_DEVICE_DATABASE_DSN_FILE` and `GATEWAY_DEVICE_PEPPER_FILE`; both must be absolute regular files, not symlinks, with no group/other permissions.
- `securefile.ReadExact(path string, expectedBytes int) ([]byte, error)` returns copied binary content for the 32-byte pepper.
- `securefile.ReadText(path string, maximumBytes int) (string, error)` accepts one nonempty line with no CR, LF, or NUL and is used for DSNs; both functions reject symlinks and unsafe modes and never include path or content in errors.
- Registry mode opens PostgreSQL, pings with a startup timeout, runs no automatic schema mutation, constructs the repository/authenticator/limiters, and closes the pool during shutdown.

- [x] **Step 1: Write failing secure-file tests**

Use temporary synthetic files. Cover relative paths, symlinks, directory/FIFO, mode `0644`, wrong exact length, empty text, NUL/CR/LF, oversize text, valid `0400`/`0600`, and returned-byte mutation.

- [x] **Step 2: Verify RED, implement, and verify GREEN**

Run RED then GREEN: `go test ./internal/securefile -count=1`

- [x] **Step 3: Write failing registry-config tests**

Cover default deny-all, explicit deny-all, complete registry config, missing one file, pairing/registry variables mixed, unknown mode, unsafe files, database ping failure, and startup logs containing only `auth=device-registry`.

- [x] **Step 4: Implement explicit mode selection**

Keep pairing available only when `GATEWAY_AUTH_MODE=pairing` for controlled rollback. Registry mode must not inspect pairing files or legacy database settings. DSN and pepper are read from files, not environment values or command-line arguments.

- [x] **Step 5: Add repository pool limits**

Set `MaxConns=10`, `MinConns=1`, `MaxConnLifetime=30m`, `MaxConnIdleTime=5m`, and a 5-second startup ping timeout. Tests inspect parsed pool configuration without printing the DSN.

- [x] **Step 6: Verify and commit**

Run:

```sh
gofmt -w cmd/gateway internal/securefile internal/devices/postgres
go test ./cmd/gateway ./internal/securefile ./internal/devices/postgres -race -count=1
git diff --check
```

Expected: PASS.

Commit: `feat(gateway): configure device registry auth`

### Task 7: Build local device administration and one-shot legacy import tools

**Files:**
- Create: `cmd/device-admin/main.go`
- Create: `cmd/device-admin/main_test.go`
- Create: `cmd/device-import/main.go`
- Create: `cmd/device-import/main_test.go`
- Create: `internal/deviceadmin/service.go`
- Create: `internal/deviceadmin/service_test.go`
- Create: `internal/legacyimport/import.go`
- Create: `internal/legacyimport/import_test.go`
- Modify: `internal/devices/postgres/repository.go`
- Modify: `internal/devices/postgres/repository_test.go`
- Modify: `go.mod`
- Modify: `go.sum`
- Modify: `.gitignore`
- Modify: `docs/deployment.md`

**Interfaces:**
- `device-admin` subcommands: `migrate`, `add`, `list`, `enable`, `disable`, and `set-expiry`; every created device uses `devices.DefaultTenantID` in the first release.
- Every command reads PostgreSQL DSN and pepper through `--database-dsn-file` and `--pepper-file`; defaults are empty, so paths must be explicit.
- `add` reads Credential only from stdin; interactive terminals use hidden input, redirected stdin accepts one newline-terminated value, and neither mode echoes it.
- `device-import` requires `--legacy-dsn-file`, `--database-dsn-file`, `--pepper-file`, `--query-file`, and optional `--dry-run`.
- The private query must return exactly aliases `credential`, `status`, and `auth_expires_at`; `status` must already be normalized to `active` or `disabled`.
- Produces `legacyimport.Target.Import(ctx context.Context, records []legacyimport.Record, now time.Time) (legacyimport.Summary, error)`; imported records use `devices.DefaultTenantID`, add audit action `created` with actor `migration` and reason `legacy_import`, insert only absent fingerprints, and report existing fingerprints as duplicates without updating them.

- [x] **Step 1: Add tool-only dependencies**

Run:

```sh
go get github.com/go-sql-driver/mysql@v1.9.3
go get golang.org/x/term@v0.33.0
```

Expected: dependencies are available to tool packages; the `cmd/gateway` binary import graph contains no MySQL driver.

- [x] **Step 2: Write failing device-admin service tests**

Test synthetic add/list/enable/disable/set-expiry operations against a fake repository. Assert fixed actor/reason codes, limit 1000 for list, RFC3339 expiry parsing, `never` mapping to null, and no Credential/fingerprint in returned values or errors.

- [x] **Step 3: Verify RED, implement service, and verify GREEN**

Run RED then GREEN: `go test ./internal/deviceadmin -count=1`

- [x] **Step 4: Write failing CLI tests and implement `device-admin`**

Inject stdin/stdout/stderr and repository construction into `run`. Tests cover every subcommand, missing flags, unsafe secret files, empty/multiple-line Credential input, exit codes, and sanitized output. `list` prints internal UUID, label, status, expiry, and last-authenticated time only.

Run RED then GREEN: `go test ./cmd/device-admin -count=1`

- [x] **Step 5: Write failing legacy importer tests**

Use `database/sql/driver` test doubles with synthetic rows. Cover dry-run counts, normal import, duplicate import idempotence, disabled-record preservation, new-database disabled state never re-enabled, invalid status/time/empty Credential causing an all-or-nothing rollback and nonzero completion, context cancellation, and output containing aggregate counts only.

- [x] **Step 6: Implement importer security boundaries**

Require all four input files to be regular non-symlink files with mode `0400` or `0600`. Limit query file size to 64 KiB. Open MySQL with `readTimeout=10s`, `writeTimeout=10s`, `timeout=5s`, `parseTime=true`, and a one-connection pool. Begin a read-only transaction, execute the private query, HMAC each Credential immediately, clear its byte slice after use, and validate all records before opening the PostgreSQL import transaction. If any row is rejected, write nothing. The PostgreSQL target inserts missing fingerprints and treats every conflict as a no-op duplicate; import never modifies an existing device's status, expiry, or label.

The importer never prints a row number, source primary key, Credential, fingerprint, label, query, table, DSN, or rejected value.

- [x] **Step 7: Verify RED/GREEN and binary dependency isolation**

Run:

```sh
go test ./internal/legacyimport ./cmd/device-import -count=1
go list -deps ./cmd/gateway | rg 'go-sql-driver/mysql|internal/legacyimport' && exit 1 || true
go list -deps ./cmd/device-import | rg -q 'go-sql-driver/mysql'
go list -deps ./cmd/device-import | rg -q 'internal/legacyimport/postgrestarget'
```

Expected: tests PASS; MySQL and the legacy import package are absent from gateway dependencies, while MySQL and the PostgreSQL import adapter are present in importer dependencies.

- [x] **Step 8: Commit**

Commit: `feat(devices): add admin and legacy import tools`

### Task 8: Update containers, local integration, and remote staging

**Files:**
- Modify: `Dockerfile`
- Create: `Dockerfile.tools`
- Modify: `deploy/compose.yaml`
- Modify: `deploy/smoke.sh`
- Modify: `.dockerignore`
- Modify: `docs/deployment.md`
- Modify: `docs/tasks/TASK-0006.md`
- Modify: `PROJECT_STATUS.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Gateway image contains only `/gateway`; it does not contain `device-admin`, `device-import`, MySQL code, migration SQL entrypoints, or secret values.
- Tools image is separately built and never runs as a persistent service.
- Compose mounts registry DSN and pepper as read-only files under `/run/secrets`, removes the writable pairing-state mount in registry mode, and keeps gateway non-root/read-only/capability-free.
- Local smoke provisions a disposable PostgreSQL volume and synthetic registry row without writing its Credential, fingerprint, DSN, or pepper to repository files.

- [ ] **Step 1: Write failing container assertions**

Extend `deploy/smoke.sh` to require:

- registry mode startup fails with either secret missing;
- migration completes before gateway starts;
- gateway image has no `/device-admin` or `/device-import`;
- gateway root filesystem is read-only, user is `65532:65532`, capabilities are dropped, and limits remain applied;
- two synthetic devices authenticate concurrently;
- same-device reconnect replaces the first connection;
- disabled/expired/unknown devices are rejected identically;
- the container remains healthy with restart count zero after malformed frames and rate-limit tests.

- [ ] **Step 2: Verify smoke RED**

Run: `./deploy/smoke.sh`

Expected: FAIL because registry containers and binaries are not wired.

- [ ] **Step 3: Implement hardened images and Compose**

Build gateway and tools in separate multi-stage targets. Use PostgreSQL 16 with an internal-only network, persistent named volume for non-test local use, healthcheck, memory limit, and no published database port. Checked-in Compose uses placeholder secret file paths only; real files remain ignored and outside Git.

- [ ] **Step 4: Run full local verification**

Run:

```sh
gofmt -w cmd internal proto
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
./scripts/test-postgres.sh go test ./internal/devices/postgres -count=1
./deploy/smoke.sh
git diff --check
```

Expected: every command exits 0.

- [ ] **Step 5: Perform public-repository safety review**

Inspect working and staged diffs, ignored files, Docker build contexts, generated binaries, database volumes, secret mounts, migration query files, logs, and known credential patterns. Stop if any real value, database artifact, dump, or payload is tracked.

- [ ] **Step 6: Commit implementation documentation**

Record exact command results and only aggregate synthetic counts in `TASK-0006`. Update project status and changelog without server paths, device counts from production, identifiers, or secrets.

Commit: `feat(deploy): stage multi-device authentication`

- [ ] **Step 7: Deploy a deny-public candidate**

Build from the reviewed commit, verify local and server SHA-256, and start an isolated candidate with PostgreSQL and registry authentication while the existing gateway remains untouched. Verify health, resource limits, database isolation, secret-file modes, and synthetic auth. Do not query the legacy database yet.

- [ ] **Step 8: Inspect legacy schema read-only and run dry-run**

On the server only, identify the authoritative legacy device rows and create a mode-`0600` private SELECT query that returns the required aliases. Use a read-only legacy account. Run importer `--dry-run`; review aggregate totals and rejected count without displaying rows. If rejected count is nonzero, stop and resolve mapping semantics before import.

- [ ] **Step 9: Import, cut over under source restriction, and validate one APK**

Run the idempotent import once, rerun dry-run to confirm no unsafe state change, then replace the staging gateway while retaining the existing single-source firewall restriction. Confirm one real APK authenticates, sustains at least three heartbeat intervals, reconnects, and produces no identifying logs. Do not expand the firewall to multiple public networks in this step.

- [ ] **Step 10: Validate revocation and rollback**

Disable the test device through `device-admin`, confirm PostgreSQL notification closes the connection, and confirm reconnect is rejected. Re-enable it and confirm reconnect. Exercise image rollback to deny-all without deleting PostgreSQL, pepper, legacy import evidence, or the previous pairing state.

- [ ] **Step 11: Final commit and handoff**

Update `TASK-0006`, `PROJECT_STATUS.md`, `CHANGELOG.md`, and `docs/deployment.md` with exact sanitized outcomes. Run the full verification suite again, inspect all diffs, commit, push, and update the Draft PR.

Commit: `docs: record multi-device authentication verification`
