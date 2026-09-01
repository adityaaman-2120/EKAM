#!/usr/bin/env bash
#
# Generate a THROWAWAY self-signed CA plus a CA-signed server certificate (and a
# client certificate for mutual-TLS testing) for local RFC 5425 syslog-over-TLS.
#
#   ./deploy/certs/generate_dev_certs.sh
#
# These are for local development and tests ONLY. They are never committed
# (see .gitignore) and must never be used in any real deployment.
#
# Env overrides: DAYS (default 825), CN (default localhost).

set -euo pipefail
cd "$(dirname "$0")"

# Stop Git-Bash/MSYS from rewriting the leading "/" of -subj into a Windows path.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

DAYS="${DAYS:-825}"
CN="${CN:-localhost}"

echo "==> Certificate authority"
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" \
  -subj "/O=ULPF Dev/CN=ULPF Dev Local CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out ca.crt

echo "==> Server key + CSR"
openssl genrsa -out server.key 4096
openssl req -new -key server.key \
  -subj "/O=ULPF Dev/CN=${CN}" \
  -out server.csr

cat > server.ext <<'EOF'
subjectAltName = DNS:localhost, IP:127.0.0.1, IP:::1
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
EOF

echo "==> Sign server certificate"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -sha256 -days "$DAYS" -extfile server.ext \
  -out server.crt

echo "==> Client certificate (for mutual TLS)"
openssl genrsa -out client.key 4096
openssl req -new -key client.key \
  -subj "/O=ULPF Dev/CN=ulpf-client" \
  -out client.csr

cat > client.ext <<'EOF'
extendedKeyUsage = clientAuth
basicConstraints = critical, CA:FALSE
EOF

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -sha256 -days "$DAYS" -extfile client.ext \
  -out client.crt

rm -f server.csr client.csr server.ext client.ext ca.srl

echo
echo "Wrote to $(pwd):"
echo "  ca.crt      - dev CA (trust this on clients)"
echo "  server.crt  - server certificate  -> ULPF_TLS__CERT_PATH"
echo "  server.key  - server private key   -> ULPF_TLS__KEY_PATH"
echo "  client.crt  - client certificate (mutual TLS)"
echo "  client.key  - client private key   (mutual TLS)"
