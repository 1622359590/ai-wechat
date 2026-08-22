#!/bin/sh
set -eu

deploy_directory="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
repository_directory="$(dirname "$deploy_directory")"
compose_file="$deploy_directory/compose.yaml"
project_name="ai-wechat-smoke-$$"
temporary_directory="$(mktemp -d)"

cleanup() {
    docker compose -p "$project_name" -f "$compose_file" down -v --remove-orphans >/dev/null 2>&1 || true
    rm -r "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

if ! docker compose version >/dev/null 2>&1; then
    printf '%s\n' 'docker compose is required' >&2
    exit 1
fi

if ! command -v docker-credential-desktop >/dev/null 2>&1; then
    docker_executable="$(command -v docker)"
    docker_target="$(readlink "$docker_executable" 2>/dev/null || printf '%s' "$docker_executable")"
    docker_resource_bin="$(dirname "$docker_target")"
    if [ -x "$docker_resource_bin/docker-credential-desktop" ]; then
        PATH="$docker_resource_bin:$PATH"
        export PATH
    fi
fi

umask 077
postgres_password="$(openssl rand -hex 24)"
printf '%s\n' "$postgres_password" >"$temporary_directory/postgres-password"
printf 'host=postgres port=5432 dbname=ai_wechat user=ai_wechat password=%s sslmode=disable' "$postgres_password" >"$temporary_directory/device-database.dsn"
openssl rand 32 >"$temporary_directory/device-pepper"
chmod 0600 "$temporary_directory/postgres-password" "$temporary_directory/device-database.dsn" "$temporary_directory/device-pepper"
unset postgres_password

DEVICE_DATABASE_DSN_FILE="$temporary_directory/device-database.dsn"
DEVICE_PEPPER_FILE="$temporary_directory/device-pepper"
POSTGRES_PASSWORD_FILE="$temporary_directory/postgres-password"
GATEWAY_TCP_HOST_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
GATEWAY_HEALTH_HOST_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
ADMIN_HTTP_HOST_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
export DEVICE_DATABASE_DSN_FILE DEVICE_PEPPER_FILE POSTGRES_PASSWORD_FILE GATEWAY_TCP_HOST_PORT GATEWAY_HEALTH_HOST_PORT ADMIN_HTTP_HOST_PORT

compose() {
    docker compose -p "$project_name" -f "$compose_file" "$@"
}

assert_equal() {
    assertion_name="$1"
    actual_value="$2"
    expected_value="$3"
    if [ "$actual_value" != "$expected_value" ]; then
        printf 'assertion failed: %s\n' "$assertion_name" >&2
        exit 1
    fi
}

compose build gateway tools admin-web >/dev/null

if docker run --rm \
    -e GATEWAY_AUTH_MODE=device-registry \
    -e GATEWAY_DEVICE_DATABASE_DSN_FILE=/run/secrets/device_database_dsn \
    -v "$DEVICE_DATABASE_DSN_FILE:/run/secrets/device_database_dsn:ro" \
    ai-wechat-gateway:local >/dev/null 2>&1; then
    printf '%s\n' 'gateway started without pepper secret' >&2
    exit 1
fi
if docker run --rm \
    -e GATEWAY_AUTH_MODE=device-registry \
    -e GATEWAY_DEVICE_PEPPER_FILE=/run/secrets/device_pepper \
    -v "$DEVICE_PEPPER_FILE:/run/secrets/device_pepper:ro" \
    ai-wechat-gateway:local >/dev/null 2>&1; then
    printf '%s\n' 'gateway started without database secret' >&2
    exit 1
fi

filesystem_container="$(docker create ai-wechat-gateway:local)"
if docker export "$filesystem_container" | tar -tf - | grep -Eq '(^|/)(device-(admin|import)|admin-(user|web))$'; then
    docker rm "$filesystem_container" >/dev/null
    printf '%s\n' 'gateway image contains an administration tool' >&2
    exit 1
fi
docker rm "$filesystem_container" >/dev/null

admin_filesystem_container="$(docker create ai-wechat-admin:local)"
if docker export "$admin_filesystem_container" | tar -tf - | grep -Eq '(^|/)(gateway|device-(admin|import)|admin-user)$'; then
    docker rm "$admin_filesystem_container" >/dev/null
    printf '%s\n' 'admin image contains another service or tool' >&2
    exit 1
fi
docker rm "$admin_filesystem_container" >/dev/null

compose up -d --build

attempt=0
health=""
while [ "$attempt" -lt 60 ]; do
    gateway_container="$(compose ps -q gateway 2>/dev/null || true)"
    if [ -n "$gateway_container" ]; then
        health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$gateway_container" 2>/dev/null || true)"
    fi
    if [ "$health" = "healthy" ]; then
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done
test "$health" = "healthy"

attempt=0
admin_health=""
while [ "$attempt" -lt 60 ]; do
    admin_container="$(compose ps -q admin-web 2>/dev/null || true)"
    if [ -n "$admin_container" ]; then
        admin_health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$admin_container" 2>/dev/null || true)"
    fi
    if [ "$admin_health" = "healthy" ]; then
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done
test "$admin_health" = "healthy"

migration_container="$(compose ps -a -q migrate)"
test "$(docker inspect --format '{{.State.Status}}' "$migration_container")" = "exited"
test "$(docker inspect --format '{{.State.ExitCode}}' "$migration_container")" = "0"

active_one="smoke-active-one-$(openssl rand -hex 12)"
active_two="smoke-active-two-$(openssl rand -hex 12)"
disabled="smoke-disabled-$(openssl rand -hex 12)"
expired="smoke-expired-$(openssl rand -hex 12)"
unknown="smoke-unknown-$(openssl rand -hex 12)"
admin_username="smoke_admin_$(openssl rand -hex 6)"
admin_password="Smoke-initial-$(openssl rand -hex 12)"
admin_new_password="Smoke-replaced-$(openssl rand -hex 12)"
admin_device="smoke-admin-device-$(openssl rand -hex 12)"

printf '%s\n' "$active_one" | compose run --rm tools add --database-dsn-file /run/secrets/device_database_dsn --pepper-file /run/secrets/device_pepper --label smoke-active-one >/dev/null
printf '%s\n' "$active_two" | compose run --rm tools add --database-dsn-file /run/secrets/device_database_dsn --pepper-file /run/secrets/device_pepper --label smoke-active-two >/dev/null
printf '%s\n' "$disabled" | compose run --rm tools add --database-dsn-file /run/secrets/device_database_dsn --pepper-file /run/secrets/device_pepper --label smoke-disabled --status disabled >/dev/null
printf '%s\n' "$expired" | compose run --rm tools add --database-dsn-file /run/secrets/device_database_dsn --pepper-file /run/secrets/device_pepper --label smoke-expired --expiry 2020-01-01T00:00:00Z >/dev/null

SMOKE_GATEWAY_ADDRESS="127.0.0.1:$GATEWAY_TCP_HOST_PORT"
SMOKE_ACTIVE_ONE="$active_one"
SMOKE_ACTIVE_TWO="$active_two"
SMOKE_DISABLED="$disabled"
SMOKE_EXPIRED="$expired"
SMOKE_UNKNOWN="$unknown"
export SMOKE_GATEWAY_ADDRESS SMOKE_ACTIVE_ONE SMOKE_ACTIVE_TWO SMOKE_DISABLED SMOKE_EXPIRED SMOKE_UNKNOWN

(cd "$repository_directory" && go test ./deploy -run TestRegistryAuthenticationLifecycle -count=1)

if ! printf '%s\n%s\n' "$admin_password" "$admin_password" | python3 "$deploy_directory/pty_run.py" -- \
    docker compose -p "$project_name" -f "$compose_file" run --rm --entrypoint /admin-user tools \
    create --database-dsn-file /run/secrets/device_database_dsn --username "$admin_username" >/dev/null 2>&1; then
    printf '%s\n' 'synthetic administrator creation failed' >&2
    exit 1
fi

SMOKE_ADMIN_ADDRESS="http://127.0.0.1:$ADMIN_HTTP_HOST_PORT"
SMOKE_ADMIN_USERNAME="$admin_username"
SMOKE_ADMIN_PASSWORD="$admin_password"
SMOKE_ADMIN_NEW_PASSWORD="$admin_new_password"
SMOKE_ADMIN_DEVICE="$admin_device"
export SMOKE_ADMIN_ADDRESS SMOKE_ADMIN_USERNAME SMOKE_ADMIN_PASSWORD SMOKE_ADMIN_NEW_PASSWORD SMOKE_ADMIN_DEVICE
(cd "$repository_directory" && go test ./deploy -run TestAdminWebLifecycle -count=1)
unset admin_password SMOKE_ADMIN_PASSWORD

assert_equal gateway-user "$(docker inspect --format '{{.Config.User}}' "$gateway_container")" "65532:65532"
assert_equal readonly-root "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$gateway_container")" "true"
assert_equal dropped-capabilities "$(docker inspect --format '{{json .HostConfig.CapDrop}}' "$gateway_container")" '["ALL"]'
assert_equal pid-limit "$(docker inspect --format '{{.HostConfig.PidsLimit}}' "$gateway_container")" "100"
assert_equal memory-limit "$(docker inspect --format '{{.HostConfig.Memory}}' "$gateway_container")" "268435456"
assert_equal cpu-limit "$(docker inspect --format '{{.HostConfig.NanoCpus}}' "$gateway_container")" "1000000000"
assert_equal secrets-readonly "$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/run/secrets"}}{{.RW}}{{end}}{{end}}' "$gateway_container")" "false"
assert_equal no-pairing-state "$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/ai-wechat/pairing"}}{{.Destination}}{{end}}{{end}}' "$gateway_container")" ""

assert_equal admin-user "$(docker inspect --format '{{.Config.User}}' "$admin_container")" "65532:65532"
assert_equal admin-readonly-root "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$admin_container")" "true"
assert_equal admin-dropped-capabilities "$(docker inspect --format '{{json .HostConfig.CapDrop}}' "$admin_container")" '["ALL"]'
assert_equal admin-pid-limit "$(docker inspect --format '{{.HostConfig.PidsLimit}}' "$admin_container")" "50"
assert_equal admin-memory-limit "$(docker inspect --format '{{.HostConfig.Memory}}' "$admin_container")" "268435456"
assert_equal admin-cpu-limit "$(docker inspect --format '{{.HostConfig.NanoCpus}}' "$admin_container")" "500000000"
assert_equal admin-secrets-readonly "$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/run/secrets"}}{{.RW}}{{end}}{{end}}' "$admin_container")" "false"
assert_equal admin-loopback-publish "$(docker inspect --format '{{(index (index .HostConfig.PortBindings "18181/tcp") 0).HostIp}}' "$admin_container")" "127.0.0.1"

postgres_container="$(compose ps -q postgres)"
assert_equal postgres-not-published "$(docker inspect --format '{{json .HostConfig.PortBindings}}' "$postgres_container")" "{}"
assert_equal restart-count "$(docker inspect --format '{{.RestartCount}}' "$gateway_container")" "0"
assert_equal persistent-services "$(compose ps --services --status running | sort | tr '\n' ' ')" "admin-web gateway postgres "

docker exec "$gateway_container" /gateway healthcheck
docker exec -e GATEWAY_HEALTHCHECK_URL=http://127.0.0.1:18080/livez "$gateway_container" /gateway healthcheck

compose restart gateway >/dev/null
attempt=0
while [ "$attempt" -lt 30 ]; do
    health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$gateway_container" 2>/dev/null || true)"
    [ "$health" = "healthy" ] && break
    attempt=$((attempt + 1))
    sleep 1
done
test "$health" = "healthy"
(cd "$repository_directory" && go test ./deploy -run TestRegistryAuthenticationLifecycle -count=1)
test "$(docker inspect --format '{{.RestartCount}}' "$gateway_container")" = "0"

compose restart admin-web >/dev/null
attempt=0
while [ "$attempt" -lt 30 ]; do
    admin_health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$admin_container" 2>/dev/null || true)"
    [ "$admin_health" = "healthy" ] && break
    attempt=$((attempt + 1))
    sleep 1
done
test "$admin_health" = "healthy"
(cd "$repository_directory" && go test ./deploy -run TestAdminWebPersistsAfterRestart -count=1)

unset SMOKE_ACTIVE_ONE SMOKE_ACTIVE_TWO SMOKE_DISABLED SMOKE_EXPIRED SMOKE_UNKNOWN
unset SMOKE_ADMIN_ADDRESS SMOKE_ADMIN_USERNAME SMOKE_ADMIN_NEW_PASSWORD SMOKE_ADMIN_DEVICE admin_new_password admin_device admin_username
printf 'registry-smoke=pass health=%s admin_health=%s user=%s readonly=%s synthetic_devices=6\n' \
    "$health" \
    "$admin_health" \
    "$(docker inspect --format '{{.Config.User}}' "$gateway_container")" \
    "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$gateway_container")"
