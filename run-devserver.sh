#!/usr/bin/env bash
# Runs the DBSC demo ON a Meta devserver behind Secure Web Apps (HTTPS on a 442xx port using
# the box's own host cert). This script is meant to be executed on the devserver — deploy.sh
# rsyncs the repo up and then runs it here. See README §10.
set -euo pipefail
cd "$(dirname "$0")"

# Devserver internet egress goes through fwdproxy — the box can't resolve external hosts
# directly, so point curl/rustup/cargo at it (fixes "Could not resolve host sh.rustup.rs").
export http_proxy="${http_proxy:-http://fwdproxy:8080}"
export https_proxy="${https_proxy:-http://fwdproxy:8080}"
export HTTP_PROXY="$http_proxy" HTTPS_PROXY="$https_proxy"
export no_proxy="${no_proxy:-.facebook.com,.fbinfra.net,localhost,127.0.0.1,::1}"

# Ensure a Rust toolchain (downloads via the proxy above if missing).
if ! command -v cargo >/dev/null 2>&1 && [ ! -x "$HOME/.cargo/bin/cargo" ]; then
  echo ">> Installing Rust (rustup) via fwdproxy…"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
source "$HOME/.cargo/env" 2>/dev/null || true

# Make cargo fetch crates through the proxy too.
mkdir -p "$HOME/.cargo"
grep -q fwdproxy "$HOME/.cargo/config.toml" 2>/dev/null \
  || printf '[http]\nproxy = "http://fwdproxy:8080"\n' >> "$HOME/.cargo/config.toml"

# Point the app at the host cert + a 442xx HTTPS port, bound on IPv6 (see README §10 gotchas).
# The browser-facing hostname is the FULL host with .facebook.com -> .fbinfra.net (KEEP the
# region, e.g. devvm59361.lla0.facebook.com -> devvm59361.lla0.fbinfra.net).
H="$(hostname)"
FBINFRA="${H/.facebook.com/.fbinfra.net}"
export DBSC_BIND="[::]:44200"
export DBSC_TLS_CERT="/etc/pki/tls/certs/${H}.crt"
export DBSC_TLS_KEY="/etc/pki/tls/certs/${H}.key"
export DBSC_ORIGIN="https://${FBINFRA}:44200"
export DBSC_HOST="${FBINFRA}"
export DBSC_COOKIE_NAME="__Host-auth_cookie"   # production-correct (Secure+Path=/+no Domain all satisfied); change to test other names

echo ">> DBSC_ORIGIN = $DBSC_ORIGIN"
echo ">> Open that URL in Chrome (macOS first, then Windows). Ctrl-C to stop."
echo ">> If it can't read $DBSC_TLS_KEY (permission denied), the host key may be root-only —"
echo ">>   copy it to a readable path (with sudo) and set DBSC_TLS_KEY/CERT accordingly."
exec cargo run
