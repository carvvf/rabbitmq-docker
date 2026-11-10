#!/usr/bin/env bash
set -euo pipefail

image="${1:?Usage: test-image.sh IMAGE INPUTS_JSON}"
inputs="${2:?Usage: test-image.sh IMAGE INPUTS_JSON}"
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
suffix="$(date +%s)-$$"
container="rabbitmq-image-test-${suffix}"
network="rabbitmq-image-test-${suffix}"
volume="rabbitmq-image-test-${suffix}"
client="rabbitmq-image-client:${suffix}"

cleanup() {
  result=$?
  trap - EXIT
  if docker container inspect "$container" >/dev/null 2>&1; then
    docker logs "$container" > "$repo_root/build/runtime-${suffix}.log" 2>&1 || result=1
    docker rm -f "$container" >/dev/null || result=1
  fi
  docker volume rm "$volume" >/dev/null || result=1
  docker network rm "$network" >/dev/null || result=1
  docker image rm "$client" >/dev/null || result=1
  rm -rf "$work"
  exit "$result"
}
mkdir -p "$repo_root/build"
docker build --tag "$client" "$repo_root/tests/client"
docker network create --internal "$network" >/dev/null
docker volume create "$volume" >/dev/null
trap cleanup EXIT

mkdir -p "$work/tls" "$work/plugins" "$work/config"
chmod 755 "$work" "$work/tls" "$work/plugins" "$work/config"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/tls/ca.key" -out "$work/tls/ca.crt" \
  -subj /CN=ImageTestCA -days 1 \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign \
  -addext subjectKeyIdentifier=hash >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$work/tls/server.key" -out "$work/tls/server.csr" \
  -subj /CN=broker >/dev/null 2>&1
cat > "$work/tls/extensions" <<'EOF'
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:broker
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF
openssl x509 -req -in "$work/tls/server.csr" -CA "$work/tls/ca.crt" -CAkey "$work/tls/ca.key" \
  -CAcreateserial -out "$work/tls/server.crt" -days 1 -extfile "$work/tls/extensions" >/dev/null 2>&1
openssl verify -x509_strict -purpose sslserver -verify_hostname broker \
  -CAfile "$work/tls/ca.crt" "$work/tls/server.crt"
# The key is disposable fixture material; uid 999 must be able to read it.
chmod 644 "$work/tls/server.key" "$work/tls/server.crt" "$work/tls/ca.crt"
printf '[rabbitmq_management].\n' > "$work/plugins/enabled_plugins"
cat > "$work/config/90-image-test.conf" <<'EOF'
listeners.tcp.default = 5672
listeners.ssl.default = 5671
ssl_options.cacertfile = /tls/ca.crt
ssl_options.certfile = /tls/server.crt
ssl_options.keyfile = /tls/server.key
ssl_options.verify = verify_peer
ssl_options.fail_if_no_peer_cert = false
management.ssl.port = 15671
management.ssl.cacertfile = /tls/ca.crt
management.ssl.certfile = /tls/server.crt
management.ssl.keyfile = /tls/server.key
EOF

start_broker() {
  docker run -d --name "$container" --hostname broker --network "$network" --network-alias broker \
    --memory 512m --cpus 1 --pids-limit 256 --security-opt no-new-privileges \
    -e RABBITMQ_SERVER_ADDITIONAL_ERL_ARGS='+S 1:1' -e RABBITMQ_CTL_ERL_ARGS='+S 1:1' \
    -e RABBITMQ_DEFAULT_USER=image-test -e RABBITMQ_DEFAULT_PASS=image-test-password \
    -v "$volume:/var/lib/rabbitmq" -v "$work/tls:/tls:ro" \
    -v "$work/config/90-image-test.conf:/etc/rabbitmq/conf.d/90-image-test.conf:ro" \
    "$@" "$image" >/dev/null
}

wait_ready() {
  deadline=$((SECONDS + 180))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if timeout 15s docker exec --user 999:999 "$container" rabbitmq-diagnostics -q -t 10 check_running >/dev/null 2>&1 \
      && timeout 15s docker exec --user 999:999 "$container" rabbitmq-diagnostics -q -t 10 check_port_listener 15671 >/dev/null 2>&1 \
      && timeout 15s docker exec --user 999:999 "$container" rabbitmq-diagnostics -q -t 10 check_port_listener 5671 >/dev/null 2>&1; then
      return
    fi
    if [ "$(docker inspect --format '{{.State.Running}}' "$container")" != true ]; then
      docker logs "$container"
      return 1
    fi
    sleep 2
  done
  echo 'Broker readiness deadline exceeded.' >&2
  return 1
}

probe() {
  docker run --rm --network "$network" -v "$work/tls:/tls:ro" "$client" "$1"
}

start_broker
wait_ready
expected_rabbit="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["rabbitmq"]["version"])' "$inputs")"
expected_otp="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["otp"]["version"])' "$inputs")"
expected_ssl="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["openssl"]["version"])' "$inputs")"
actual_rabbit="$(docker exec --user 999:999 "$container" rabbitmq-diagnostics -q server_version)"
[ "$actual_rabbit" = "$expected_rabbit" ]
actual_otp="$(docker exec "$container" erl +S 1:1 -noshell -eval \
  '{ok,V}=file:read_file(filename:join([code:root_dir(),"releases",erlang:system_info(otp_release),"OTP_VERSION"])), io:format("~s",[V]), halt().')"
[ "$actual_otp" = "$expected_otp" ]
docker exec "$container" openssl version | awk -v expected="$expected_ssl" '$1 != "OpenSSL" || $2 != expected { exit 1 }'
docker exec "$container" sh -ec \
  'find /opt/erlang -name crypto.so -exec ldd {} \;' > "$work/linkage"
grep -E 'libcrypto\.so.*=> /opt/openssl/' "$work/linkage" >/dev/null
if grep -E 'libcrypto\.so.*=> /usr/' "$work/linkage"; then exit 1; fi
docker exec --user 999:999 "$container" rabbitmq-diagnostics -q ping
docker exec --user 999:999 "$container" rabbitmq-plugins list -e -m | grep -Fx rabbitmq_management
docker exec --user 999:999 "$container" rabbitmq-plugins list -e -m | grep -Fx rabbitmq_prometheus
probe publish
docker restart --time 30 "$container" >/dev/null
wait_ready
probe consume
docker logs "$container" > "$repo_root/build/runtime-root-${suffix}.log" 2>&1
docker rm -f "$container" >/dev/null

# Preserve the existing volume and identity while testing the consumer's non-root restrictions.
start_broker --user 999:999 --cap-drop ALL \
  -e RABBITMQ_ENABLED_PLUGINS_FILE=/etc/rabbitmq/ragtime-plugins/enabled_plugins \
  -v "$work/plugins:/etc/rabbitmq/ragtime-plugins:ro"
wait_ready
probe publish
docker restart --time 30 "$container" >/dev/null
wait_ready
probe consume
if docker exec --user 999:999 "$container" rabbitmq-plugins list -e -m | grep -Fx rabbitmq_prometheus; then
  echo 'Read-only management-only plugin configuration was not respected.' >&2
  exit 1
fi
printf 'Root and non-root RabbitMQ runtime qualification passed.\n'
