# Perseus Trust Framework CA 
openssl genpkey -algorithm RSA -out server-ca-key.pem
openssl req -new -x509 -key server-ca-key.pem -out server-ca-cert.pem -days 3560 \
    -subj "/C=GB/O=Perseus Trust Framework/CN=Perseus Trust Framework Server CA"

# Generate server private key
openssl genpkey -algorithm RSA -out server-key.pem

# Generate server CSR
openssl req -new -key server-key.pem -out server-csr.pem \
    -subj "/C=GB/ST=London/O=Perseus Trust Framework/CN=${SERVER_HOSTNAME:-`hostname`}"

# Sign the server CSR with CA key and certificate
openssl x509 -req -in server-csr.pem -out server-cert.pem -CA server-ca-cert.pem \
    -CAkey server-ca-key.pem -days 365

# Bundle server and CA certificates
cat server-cert.pem  server-ca-cert.pem > server-cert-bundle.pem


# Perseus Trust Framework Client CA
openssl genpkey -algorithm RSA -out client-ca-key.pem
openssl req -new -x509 -key client-ca-key.pem -out client-ca-cert.pem -days 3560 \
    -subj "/C=GB/O=Perseus Trust Framework/CN=Perseus Trust Framework Client CA"

# Client Key
openssl genpkey -algorithm RSA -out client-key.pem

# Client CSR
openssl req -new -key client-key.pem -out client-csr.pem \
    -subj "/C=GB/ST=London/O=Application One/OU=carbon-accounting@perseus/CN=https:\/\/directory.perseus.ib1.org\/member\/2876152"
openssl x509 -req -in client-csr.pem -out client-cert.pem \
    -CA client-ca-cert.pem -CAkey client-ca-key.pem -days 365
cat client-cert.pem client-ca-cert.pem > client-bundle.pem

