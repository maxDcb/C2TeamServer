#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <domain>" >&2
    exit 1
fi

DOMAIN="$1"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pushd "${SCRIPT_DIR}" >/dev/null

rm -f rootCA.key rootCA.crt rootCA.srl \
      "${DOMAIN}.key" "${DOMAIN}.csr" "${DOMAIN}.crt" \
      csr.conf cert.ext

# ---------------------------------------------------------------------------
# Root CA used to sign the beacon HTTPS certificate.
# ---------------------------------------------------------------------------
openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
    -keyout rootCA.key -out rootCA.crt \
    -subj "/C=US/ST=California/L=San Francisco/O=C2TeamServer/OU=Beacon/CN=${DOMAIN} Root CA"

# ---------------------------------------------------------------------------
# Private key and CSR for the provided domain.
# ---------------------------------------------------------------------------
openssl genrsa -out "${DOMAIN}.key" 2048

cat <<EOF > csr.conf
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
OU = Beacon
CN = ${DOMAIN}

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${DOMAIN}
DNS.2 = www.${DOMAIN}
IP.1  = 192.168.1.2
IP.2  = 192.168.1.3
EOF

openssl req -new -key "${DOMAIN}.key" -out "${DOMAIN}.csr" -config csr.conf

cat <<EOF > cert.ext
authorityKeyIdentifier = keyid,issuer
basicConstraints       = CA:FALSE
extendedKeyUsage       = serverAuth
keyUsage               = digitalSignature,keyEncipherment
subjectAltName         = @alt_names

[ alt_names ]
DNS.1 = ${DOMAIN}
DNS.2 = www.${DOMAIN}
IP.1  = 192.168.1.2
IP.2  = 192.168.1.3
EOF

openssl x509 -req -in "${DOMAIN}.csr" -CA rootCA.crt -CAkey rootCA.key \
    -CAcreateserial -out "${DOMAIN}.crt" -days 365 -sha256 -extfile cert.ext

rm -f csr.conf cert.ext "${DOMAIN}.csr" rootCA.srl

popd >/dev/null
