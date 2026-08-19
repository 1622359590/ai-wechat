#!/bin/sh
set -eu

compose_file="$(dirname "$0")/compose.yaml"
project_name="ai-wechat-staging"
container_name="${project_name}-gateway-1"
temporary_docker_config=""

cleanup() {
    if [ -n "$temporary_docker_config" ]; then
        rm -r "$temporary_docker_config"
    fi
}
trap cleanup EXIT HUP INT TERM

# Some Docker Desktop installations retain credsStore=desktop after removing the
# matching helper. This image uses only a public base, so an empty temporary
# client config is a safe local fallback and is deleted when the smoke run exits.
if docker info --format '{{.OperatingSystem}}' 2>/dev/null | grep -q 'Docker Desktop' \
    && ! command -v docker-credential-desktop >/dev/null 2>&1; then
    temporary_docker_config="$(mktemp -d)"
    printf '{"auths":{}}\n' >"$temporary_docker_config/config.json"
    DOCKER_CONFIG="$temporary_docker_config"
    export DOCKER_CONFIG
fi

if docker compose version >/dev/null 2>&1; then
    docker compose -p "$project_name" -f "$compose_file" up -d --build
else
    docker build -t ai-wechat-gateway:local -f "$(dirname "$0")/../Dockerfile" "$(dirname "$0")/.."
    if docker container inspect "$container_name" >/dev/null 2>&1; then
        docker container rm -f "$container_name" >/dev/null
    fi
    docker run -d \
        --name "$container_name" \
        --restart unless-stopped \
        --read-only \
        --user 65532:65532 \
        --cap-drop ALL \
        --security-opt no-new-privileges:true \
        --pids-limit 100 \
        --memory 256m \
        --cpus 1.0 \
        --tmpfs /tmp:rw,noexec,nosuid,size=16m \
        -e GATEWAY_TCP_ADDRESS=:19090 \
        -e GATEWAY_HEALTH_ADDRESS=:18080 \
        -e GATEWAY_MAX_BODY_BYTES=1048576 \
        -p 127.0.0.1:19090:19090 \
        -p 127.0.0.1:18080:18080 \
        ai-wechat-gateway:local >/dev/null
fi

attempt=0
while [ "$attempt" -lt 30 ]; do
    health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container_name" 2>/dev/null || true)"
    if [ "$health" = "healthy" ]; then
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done

test "${health:-}" = "healthy"
test "$(docker inspect --format '{{.Config.User}}' "$container_name")" = "65532:65532"
test "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container_name")" = "true"
docker exec "$container_name" /gateway healthcheck
docker exec \
    -e GATEWAY_HEALTHCHECK_URL=http://127.0.0.1:18080/livez \
    "$container_name" /gateway healthcheck

printf 'staging-smoke=pass container=%s health=%s user=%s readonly=%s\n' \
    "$container_name" \
    "$health" \
    "$(docker inspect --format '{{.Config.User}}' "$container_name")" \
    "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container_name")"
