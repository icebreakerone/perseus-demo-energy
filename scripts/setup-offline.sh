#!/usr/bin/env bash
#
# Offline fallback: generate a complete self-signed PKI for local development.
#
# Prefer ./scripts/refresh-certs.sh, which issues client and signing
# certificates from the real sandbox directory service. Use this script only
# when you have no directory account or no network.
#
# The certificates it produces chain to a client CA that exists nowhere but
# this machine, so a client holding a real directory certificate cannot connect
# to nginx afterwards, and vice versa. scripts/generated/MANIFEST.txt records
# which of the two scripts ran last.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v ib1-directory >/dev/null; then
  echo "ib1-directory is not installed. Install it with:" >&2
  echo "  pipx install ../../ib1-directory/" >&2
  exit 1
fi



# Create jwt signing key
openssl genpkey -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 \
    -out jwt-signing-key.pem

# Create all three CAs
ib1-directory create-ca -u server -f Core
ib1-directory create-ca -u client -f Core
ib1-directory create-ca -u signing -f Core

# Create the server certificate
# Creates localhost-cert.pem and localhost-key.pem
ib1-directory create-server-certificates \
    --issuer-key-file server-issuer-key.pem \
    --issuer-cert-file server-issuer-cert.pem \
    --domain localhost \
    --trust-framework Core \
    --country UK \
    --state London

# Create the client certificate
# Creates cap-demo-client-cert.pem and cap-demo-client-key.pem
ib1-directory create-application-certificates --issuer-key-file client-issuer-key.pem   \
  --issuer-cert-file client-issuer-cert.pem \
  --member-uri  https://directory.core.development.trust.ib1.org/member/rydua98c \
  --organization-name "CAP Demo"  \
  --country UK \
  --state London \
  --role https://registry.core.sandbox.trust.ib1.org/scheme/perseus/role/carbon-accounting-provider \
  --application-uri https://registry.core.pilot.trust.ib1.org/application/cap-demo

# Create sigining certificates
# Creates edp-demo-signing-cert.pem and edp-demo-signing-key.pem
ib1-directory create-application-certificates --issuer-key-file signing-issuer-key.pem   \
  --issuer-cert-file signing-issuer-cert.pem \
  --member-uri  https://directory.core.development.trust.ib1.org/member/tezdi16s \
  --organization-name "EDP Demo"  \
  --country UK \
  --state London \
  --role https://registry.core.pilot.trust.ib1.org/scheme/perseus/role/energy-data-provider \
  --application-uri https://registry.core.pilot.trust.ib1.org/application/edp-demo \
  --certificate-type signing


# Create various chains and bundles required
# server-complete-bundle
cat localhost-cert.pem server-issuer-cert.pem server-ca-cert.pem > server-complete-bundle.pem

# signing-issued-intermediate-bundle
cat edp-demo-signing-cert.pem signing-issuer-cert.pem > signing-issued-intermediate-bundle.pem

# server bundle (for a  connection to validate the server certificate)
cat server-issuer-cert.pem server-ca-cert.pem > server-bundle.pem

# client bundle (for a client MTLS connection, leaf + intermediate)
cat cap-demo-client-cert.pem client-issuer-cert.pem  > cap-demo-client-bundle.pem

# client bundle to verify (intermediate + root)
cat client-issuer-cert.pem client-ca-cert.pem > client-verify-bundle.pem
# Move them to a nested folder. Named explicitly rather than *.pem, so a stray
# PEM left in this directory is not swept into the generated set.
mkdir -p generated
mv jwt-signing-key.pem \
  server-ca-cert.pem server-ca-key.pem server-issuer-cert.pem server-issuer-key.pem \
  client-ca-cert.pem client-ca-key.pem client-issuer-cert.pem client-issuer-key.pem \
  signing-ca-cert.pem signing-ca-key.pem signing-issuer-cert.pem signing-issuer-key.pem \
  localhost-cert.pem localhost-key.pem localhost-bundle.pem \
  cap-demo-client-cert.pem cap-demo-client-key.pem cap-demo-client-bundle.pem \
  edp-demo-signing-cert.pem edp-demo-signing-key.pem edp-demo-signing-bundle.pem \
  server-complete-bundle.pem signing-issued-intermediate-bundle.pem \
  server-bundle.pem client-verify-bundle.pem \
  generated
# nginx requires server-complete-bundle and server-key, as well as client-verify-bundle for mtls 
#mv those keys to ../certs
mkdir -p ../certs
mv generated/server-complete-bundle.pem \
  generated/localhost-key.pem \
  generated/client-ca-cert.pem \
  generated/client-verify-bundle.pem \
  ../certs
# authentication api requires jwt-signing-key.pem
mkdir -p ../authentication/certs
mv generated/jwt-signing-key.pem  ../authentication/certs

# resource api requires server-ca-cert.pem, provence key and cert bundle, provenance CA root 
mkdir -p ../resource/certs
mv generated/server-ca-cert.pem \
    generated/signing-issued-intermediate-bundle.pem \
    generated/edp-demo-signing-key.pem \
    generated/edp-demo-signing-cert.pem \
    generated/signing-ca-cert.pem \
    ../resource/certs

# Put the certs required for client certificates in the right place
mkdir -p generated/client
mv generated/server-bundle.pem \
    generated/cap-demo-client-bundle.pem \
    generated/cap-demo-client-key.pem \
    generated/client

# Record which script produced the current certificates, so it is always clear
# whether nginx is trusting the real directory client CA or this local one.
cat > generated/MANIFEST.txt <<EOF
source=offline
refreshed=$(date -u +%Y-%m-%dT%H:%MZ)
note=Self-signed CAs. Real directory certificates will not work against this stack.
EOF
