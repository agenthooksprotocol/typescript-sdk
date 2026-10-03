#!/bin/sh
# TEST ONLY: all generated private keys are deliberately public repository fixtures.
set -eu
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
cat > "$work/ca.cnf" <<'CONFIG'
[req]
distinguished_name=dn
x509_extensions=ca
prompt=no
[dn]
CN=AHP Synthetic Interop TEST ONLY CA
[ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
CONFIG
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 36500 -config "$work/ca.cnf" -keyout ca-key.pem -out ca.pem 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 36500 -config "$work/ca.cnf" -subj '/CN=AHP Untrusted TEST ONLY CA' -keyout "$work/untrusted-ca-key.pem" -out untrusted-ca.pem 2>/dev/null
for name in server client untrusted-client; do
  openssl req -new -newkey rsa:2048 -nodes -sha256 -subj "/CN=AHP Synthetic TEST ONLY $name" -keyout "$name-key.pem" -out "$work/$name.csr" 2>/dev/null
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n' > "$work/leaf.cnf"
  if [ "$name" = server ]; then
    printf 'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' >> "$work/leaf.cnf"
  else
    printf 'extendedKeyUsage=clientAuth\n' >> "$work/leaf.cnf"
  fi
  ca=ca.pem; key=ca-key.pem
  if [ "$name" = untrusted-client ]; then ca=untrusted-ca.pem; key="$work/untrusted-ca-key.pem"; fi
  openssl x509 -req -in "$work/$name.csr" -CA "$ca" -CAkey "$key" -set_serial "0x$(openssl rand -hex 16)" -days 36500 -sha256 -extfile "$work/leaf.cnf" -out "$name.pem" 2>/dev/null
 done
chmod 644 ./*-key.pem
openssl verify -CAfile ca.pem server.pem client.pem
openssl verify -CAfile untrusted-ca.pem untrusted-client.pem
