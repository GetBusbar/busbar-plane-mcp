#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors

# Source-only helpers. A harness run creates its own short-lived CA and localhost leaf;
# no private key is checked in, and the peer pin is derived from that leaf's actual SPKI.
mcp_fixture_prepare_tls() {
  local dir="$1"
  command -v openssl >/dev/null 2>&1 || { echo 'MCP fixture TLS requires openssl' >&2; return 1; }
  mkdir -p "$dir" || return 1
  dir="$(cd "$dir" && pwd)" || return 1
  (
    umask 077
    cat >"$dir/ca.cnf" <<'TLS_CA'
[req]
distinguished_name = dn
x509_extensions = ca
prompt = no
[dn]
CN = MCP conformance ephemeral CA
[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
TLS_CA
    cat >"$dir/leaf.cnf" <<'TLS_LEAF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = localhost
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
TLS_LEAF
    openssl req -new -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
      -config "$dir/ca.cnf" -keyout "$dir/ca.key" -out "$dir/ca.pem" \
      >"$dir/generate.log" 2>&1 || exit 1
    openssl req -new -newkey rsa:2048 -nodes -sha256 -config "$dir/leaf.cnf" \
      -keyout "$dir/leaf.key" -out "$dir/leaf.csr" >>"$dir/generate.log" 2>&1 || exit 1
    openssl x509 -req -in "$dir/leaf.csr" -CA "$dir/ca.pem" -CAkey "$dir/ca.key" \
      -CAcreateserial -days 2 -sha256 -extfile "$dir/leaf.cnf" -extensions leaf \
      -out "$dir/leaf.pem" >>"$dir/generate.log" 2>&1 || exit 1
    openssl verify -CAfile "$dir/ca.pem" -verify_hostname localhost "$dir/leaf.pem" \
      >>"$dir/generate.log" 2>&1 || exit 1
    openssl x509 -in "$dir/leaf.pem" -pubkey -noout >"$dir/spki.pem" || exit 1
    openssl pkey -pubin -in "$dir/spki.pem" -outform DER -out "$dir/spki.der" || exit 1
    openssl dgst -sha256 -binary "$dir/spki.der" >"$dir/spki.sha256" || exit 1
    openssl base64 -A -in "$dir/spki.sha256" -out "$dir/spki.base64" || exit 1
  ) || { echo "MCP fixture TLS generation failed; see $dir/generate.log" >&2; return 1; }
  MCP_FIXTURE_CA_FILE="$dir/ca.pem"
  MCP_FIXTURE_TLS_CERT="$dir/leaf.pem"
  MCP_FIXTURE_TLS_KEY="$dir/leaf.key"
  MCP_FIXTURE_KEY_PIN="sha256/$(cat "$dir/spki.base64")"
  [[ "$MCP_FIXTURE_KEY_PIN" =~ ^sha256/[A-Za-z0-9+/]{43}=$ ]] \
    || { echo 'MCP fixture SPKI digest is malformed' >&2; return 1; }
  export MCP_FIXTURE_CA_FILE MCP_FIXTURE_TLS_CERT MCP_FIXTURE_TLS_KEY MCP_FIXTURE_KEY_PIN
  # Node reads extra roots at process startup. This affects fixture digest clients only;
  # busbar's own root must be supplied separately through its supported operator-CA config.
  export NODE_EXTRA_CA_CERTS="$MCP_FIXTURE_CA_FILE"
}

mcp_fixture_require_tls() {
  [ -r "${MCP_FIXTURE_CA_FILE:-}" ] && [ -r "${MCP_FIXTURE_TLS_CERT:-}" ] \
    && [ -r "${MCP_FIXTURE_TLS_KEY:-}" ] && [ -n "${MCP_FIXTURE_KEY_PIN:-}" ] \
    || { echo 'MCP fixture TLS material is missing' >&2; return 1; }
}
