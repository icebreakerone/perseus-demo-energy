# Certificate trees generated:
#
# 1. Core Trust Framework Server CA
#     2. Core Trust Framework Server Issuer
#         3. <This computer>
#
# 4. Core Trust Framework Client CA
#     5. Core Trust Framework Client Issuer
#          6. Application One (roles: supply-voltage-reader, reporter)
#          7. Application Two (roles: consumption-reader, reporter)

set -e

if ! which openssl
then
    echo "openssl must be in your PATH" >&2
    exit 1
fi

# Core Trust Framework Server CA 
openssl genpkey -algorithm RSA -out server-ca-key.pem
openssl req -new -x509 -key server-ca-key.pem -out server-ca-cert.pem -days 3560 \
    -subj "/C=GB/O=Core Trust Framework/CN=Core Trust Framework Server CA"

# Core Trust Framework Issuer
openssl genpkey -algorithm RSA -out server-issuer-key.pem
openssl req -new -key server-issuer-key.pem -out server-issuer-csr.pem \
    -subj "/C=GB/ST=London/O=Core Trust Framework/CN=Core Trust Framework Server Issuer"
openssl x509 -req -in server-issuer-csr.pem -out server-issuer-ca.pem -extfile ../scripts/extensions.cnf \
    -extensions v3_ca -CA server-ca-cert.pem -CAkey server-ca-key.pem -days 365

# Server
openssl genpkey -algorithm RSA -out server-key.pem
openssl req -new -key server-key.pem -out server-csr.pem \
    -subj "/C=GB/ST=London/O=Core Trust Framework/CN=`hostname`"
openssl x509 -req -in server-csr.pem -out server-cert.pem -CA server-issuer-ca.pem \
    -CAkey server-issuer-key.pem -days 365
cat server-cert.pem server-issuer-ca.pem > server-cert-bundle.pem

# Core Trust Framework  Client CA
openssl genpkey -algorithm RSA -out client-ca-key.pem
openssl req -new -x509 -key client-ca-key.pem -out client-ca-cert.pem -days 3560 \
    -subj "/C=GB/O=Core Trust Framework/CN=Core Trust Framework Client CA"

# Core Trust Framework  Client Issuer
openssl genpkey -algorithm RSA -out client-issuer-key.pem
openssl req -new -key client-issuer-key.pem -out client-issuer-csr.pem \
    -subj "/C=GB/ST=London/O=Core Trust Framework/CN=Core Trust Framework Client Issuer"
openssl x509 -req -in client-issuer-csr.pem -out client-issuer-ca.pem -extfile ../scripts/extensions.cnf \
    -extensions v3_ca -CA client-ca-cert.pem -CAkey client-ca-key.pem -days 365

# Carbon Accounting Application
openssl genpkey -algorithm RSA -out application-key.pem
openssl req -new -key application-key.pem -out application-csr.pem \
    -subj "/C=GB/ST=London/O=Application One/CN=https:\/\/directory.estf.ib1.org\/member\/2876152"
openssl x509 -req -in application-csr.pem -out application-cert.pem -extfile ../scripts/roles.cnf -extensions roles1 \
    -CA client-issuer-ca.pem -CAkey client-issuer-key.pem -days 365
cat application-cert.pem client-issuer-ca.pem > application-bundle.pem

# openssl x509 -in application-cert.pem -noout -text
