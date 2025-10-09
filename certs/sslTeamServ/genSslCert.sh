#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pushd "${SCRIPT_DIR}" >/dev/null

# Ensure a clean slate so repeated executions do not reuse stale material.
rm -f ca.pem ca-key.pem ca.srl \
      server-key.pem server.csr server.pem server.ext server.cnf \
      client-key.pem client.csr client.pem client.ext client.cnf

# ---------------------------------------------------------------------------
# Root CA
# ---------------------------------------------------------------------------
openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
    -keyout ca-key.pem -out ca.pem \
    -subj "/C=US/ST=California/L=San Francisco/O=C2TeamServer/OU=Certificate Services/CN=C2TeamServer Root CA"

# ---------------------------------------------------------------------------
# Server certificate (used by the TeamServer itself)
# ---------------------------------------------------------------------------
cat <<'EOF' > server.cnf
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[ dn ]
C  = US
ST = California
L  = San Francisco
O  = C2TeamServer
OU = TeamServer
CN = localhost

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1  = 127.0.0.1
EOF

openssl genrsa -out server-key.pem 2048
openssl req -new -key server-key.pem -out server.csr -config server.cnf

cat <<'EOF' > server.ext
authorityKeyIdentifier = keyid,issuer
basicConstraints       = CA:FALSE
extendedKeyUsage       = serverAuth
keyUsage               = digitalSignature,keyEncipherment
subjectAltName         = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1  = 127.0.0.1
EOF

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -out server.pem -days 825 -sha256 -extfile server.ext

# ---------------------------------------------------------------------------
# Client certificate (used by gRPC clients)
# ---------------------------------------------------------------------------
cat <<'EOF' > client.cnf
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[ dn ]
C  = US
ST = California
L  = San Francisco
O  = C2TeamServer
OU = TeamServer Client
CN = client

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = client
EOF

openssl genrsa -out client-key.pem 2048
openssl req -new -key client-key.pem -out client.csr -config client.cnf

cat <<'EOF' > client.ext
authorityKeyIdentifier = keyid,issuer
basicConstraints       = CA:FALSE
extendedKeyUsage       = clientAuth
keyUsage               = digitalSignature,keyEncipherment
subjectAltName         = @alt_names

[ alt_names ]
DNS.1 = client
EOF

openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem \
    -CAcreateserial -out client.pem -days 825 -sha256 -extfile client.ext

# Remove transient files that are not required by the build system.
rm -f server.csr server.ext server.cnf client.csr client.ext client.cnf ca.srl

popd >/dev/null
