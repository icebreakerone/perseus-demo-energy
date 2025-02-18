

# Create jwt signing key
openssl genpkey -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 \
    -out jwt-signing-key.pem

# Create all three CAs
pipx install --force ib1-directory
ib1-directory create-ca -u server -f Core
ib1-directory create-ca -u client -f Core
ib1-directory create-ca -u signing -f Core

# Create the server certificate
# Creates localhost-cert.pem and localhost-key.pem
ib1-directory create-server-certificates \
    --issuer-key-file server-issuer-key.pem \
    --issuer-cert-file server-issuer-cert.pem \
    --domain localhost \
    --trust_framework Core \
    --country UK \
    --state London

# Create the client certificate
# Creates edp-demo-client-cert.pem and edp-demo-client-key.pem
ib1-directory create-application-certificates --issuer-key-file client-issuer-key.pem   \
  --issuer-cert-file client-issuer-cert.pem \
  --member_uri  https://directory.core.development.trust.ib1.org/member/tezdi16s \
  --organization_name "EDP Demo"  \
  --country UK \
  --state London \
  --role https://registry.core.ib1.org/scheme/perseus/role/carbon-accounting \
  --application_uri https://registry.core.pilot.trust.ib1.org/application/edp-demo

# Create sigining certificates
# Creates edp-demo-signing-cert.pem and edp-demo-signing-key.pem
ib1-directory create-application-certificates --issuer-key-file signing-issuer-key.pem   \
  --issuer-cert-file signing-issuer-cert.pem \
  --member_uri  https://directory.core.development.trust.ib1.org/member/tezdi16s \
  --organization_name "EDP Demo"  \
  --country UK \
  --state London \
  --role https://registry.core.pilot.trust.ib1.org/scheme/perseus/role/energy-data-provider \
  --application_uri https://registry.core.pilot.trust.ib1.org/application/edp-demo \
  --cert_type signing

# Create various chains and bundles required
# server-complete-bundle
cat localhost-cert.pem server-issuer-cert.pem server-ca-cert.pem > server-complete-bundle.pem

# signing-issued-intermediate-bundle
cat edp-demo-signing-cert.pem signing-issuer-cert.pem > signing-issued-intermediate-bundle.pem

# Move them to a nested folder
mkdir -p generated
mv *.pem generated
# nginx requires server-complete-bundle and server-key, as well as client-verify-bundle for mtls 
#mv those keys to ../certs
mkdir -p ../certs
mv generated/server-complete-bundle.pem generated/localhost-key.pem generated/client-ca-cert.pem ../certs
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
