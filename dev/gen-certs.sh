#!/usr/bin/env bash
# Generates a throwaway dev CA, a server cert for the three *.localhost
# hostnames, and client certs for mTLS login. Output goes to dev/certs/.
#
#   ./gen-certs.sh            # create anything missing
#   ./gen-certs.sh alice bob  # also create client certs for these names
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p certs
cd certs

P12_PASSWORD="changeit"
SERVER_NAMES="ctfd.localhost mtls.ctfd.localhost dex.localhost"
CLIENTS=("alice" "bob" "$@")

# macOS Keychain can't import PKCS#12 files using OpenSSL 3's default AES
# encryption, so use the legacy algorithms there.
LEGACY=""
if openssl version | grep -q '^OpenSSL 3'; then
    LEGACY="-legacy"
fi

if [ ! -f ca.key ]; then
    echo "Creating dev CA"
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
        -keyout ca.key -out ca.crt -subj "/O=CTFd Dev/CN=CTFd Dev CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
fi

if [ ! -f server.key ]; then
    echo "Creating server cert for: $SERVER_NAMES"
    san=$(printf 'DNS:%s,' $SERVER_NAMES); san=${san%,}
    openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
        -subj "/O=CTFd Dev/CN=ctfd.localhost" 2>/dev/null
    printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nbasicConstraints=CA:FALSE\n' "$san" > server.ext
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
        -days 397 -out server.crt -extfile server.ext 2>/dev/null
    rm -f server.csr server.ext
fi

for name in "${CLIENTS[@]}"; do
    [ -f "$name.crt" ] && continue
    echo "Creating client cert: $name (p12 password: $P12_PASSWORD)"
    openssl req -newkey rsa:2048 -nodes -keyout "$name.key" -out "$name.csr" \
        -subj "/O=CTFd Dev/OU=Players/CN=$name" 2>/dev/null
    printf 'subjectAltName=email:%s@example.com\nextendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\nbasicConstraints=CA:FALSE\n' "$name" > "$name.ext"
    openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
        -days 397 -out "$name.crt" -extfile "$name.ext" 2>/dev/null
    openssl pkcs12 -export $LEGACY -in "$name.crt" -inkey "$name.key" -certfile ca.crt \
        -name "CTFd dev: $name" -out "$name.p12" -passout "pass:$P12_PASSWORD"
    rm -f "$name.csr" "$name.ext"
done

# Caddy and CTFd run as non-root/other users; certs only need to be readable.
chmod 644 ./*.crt ./*.key
echo "Certs are in $(pwd)"
