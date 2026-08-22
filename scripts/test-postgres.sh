#!/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
    echo "usage: $0 command [args...]" >&2
    exit 2
fi

temporary_directory="$(mktemp -d)"
project_suffix="$(basename "$temporary_directory" | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]')"
project_name="ai-wechat-test-${project_suffix}"
compose_file="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/deploy/compose.test.yaml"

postgres_user="test_runner"
postgres_password="$(openssl rand -hex 24)"
postgres_database="device_registry_test"

compose() {
    POSTGRES_USER="$postgres_user" POSTGRES_PASSWORD="$postgres_password" POSTGRES_DB="$postgres_database" \
        docker compose -p "$project_name" -f "$compose_file" "$@"
}

cleanup() {
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    rmdir "$temporary_directory" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

compose up -d postgres

attempt=0
until compose exec -T postgres pg_isready -U "$postgres_user" -d "$postgres_database" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ]; then
        echo "PostgreSQL test service did not become ready" >&2
        exit 1
    fi
    sleep 1
done

published_address="$(compose port postgres 5432)"
published_port="${published_address##*:}"
TEST_POSTGRES_DSN="postgres://${postgres_user}:${postgres_password}@127.0.0.1:${published_port}/${postgres_database}?sslmode=disable" \
    "$@"
