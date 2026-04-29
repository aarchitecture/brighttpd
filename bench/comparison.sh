#!/bin/sh

set -eu

cd "$(dirname "$0")"

command -v nginx >/dev/null 2>&1 || { echo "missing nginx" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "missing curl" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "missing openssl" >&2; exit 1; }

BIN=${1:-../brighttpd}

cleanup() {
    kill -INT "$BRIGHT_PID" 2>/dev/null || true
    wait "$BRIGHT_PID" 2>/dev/null || true
    nginx -p "$(pwd)" -c nginx.conf -s quit 2>/dev/null || true
    nginx -p "$(pwd)" -c nginx_tls.conf -s quit 2>/dev/null || true
    rm -f tmp/tls-bench.crt tmp/tls-bench.key tmp/tls-bench.p12
    rm -rf logs tmp/client_body tmp/proxy tmp/fastcgi tmp/uwsgi tmp/scgi
}

trap cleanup EXIT INT TERM

gen_tls() {
    mkdir -p tmp
    openssl req -x509 -newkey rsa:2048 -keyout tmp/tls-bench.key \
        -out tmp/tls-bench.crt -days 1 -nodes -subj /CN=localhost 2>/dev/null
    openssl pkcs12 -export -out tmp/tls-bench.p12 \
        -inkey tmp/tls-bench.key -in tmp/tls-bench.crt \
        -passout pass:brighttpd-bench 2>/dev/null
}

wait_ready() {
    url=$1; pid=${2:-}
    for i in $(seq 1 50); do
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "server exited" >&2; exit 1
        fi
        if curl -sk -o /dev/null "$url"; then
            return 0
        fi
        sleep 0.1
    done
    echo "timeout waiting for $url" >&2; exit 1
}

start_bright() {
    conf=$1; port=$2
    chmod 600 "$conf"
    "$BIN" -c "$conf" &
    BRIGHT_PID=$!
    scheme=$(echo "$port" | grep -q 8443 && echo https || echo http)
    wait_ready "$scheme://127.0.0.1:$port/" "$BRIGHT_PID"
}

stop_bright() {
    kill -INT "$BRIGHT_PID" 2>/dev/null || true
    wait "$BRIGHT_PID" 2>/dev/null || true
}

start_nginx() {
    conf=$1; port=$2
    mkdir -p logs tmp/client_body tmp/proxy tmp/fastcgi tmp/uwsgi tmp/scgi
    nginx -p "$(pwd)" -c "$conf"
    scheme=$(echo "$port" | grep -q 8443 && echo https || echo http)
    wait_ready "$scheme://127.0.0.1:$port/"
}

stop_nginx() {
    conf=$1
    nginx -p "$(pwd)" -c "$conf" -s quit 2>/dev/null || true
}

echo "=== HTTP: brighttpd ==="
start_bright brighttpd.conf 8000
./benchmark.sh 8000
stop_bright

echo "=== HTTP: nginx ==="
start_nginx nginx.conf 8001
./benchmark.sh 8001
stop_nginx nginx.conf

gen_tls

echo "=== TLS: brighttpd ==="
start_bright brighttpd_tls.conf 8443
./benchmark_tls.sh 8443
stop_bright

echo "=== TLS: nginx ==="
start_nginx nginx_tls.conf 8444
./benchmark_tls.sh 8444
stop_nginx nginx_tls.conf
