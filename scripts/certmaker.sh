# Generate CA private key
openssl genpkey -algorithm RSA -out ca-key.pem

# Generate CA self-signed certificate
openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -subj "/C=GB/ST=London/O=Perseus CA/CN=perseus-demo-fapi.ib1.org"

# Generate server private key
openssl genpkey -algorithm RSA -out server-key.pem

# Generate server CSR
openssl req -new -key server-key.pem -out server-csr.pem -subj "/C=GB/ST=London/O=Perseus Demo Authentication/CN=perseus-demo-authentication.ib1.org"

# Sign the server CSR with CA key and certificate
openssl x509 -req -in server-csr.pem -out server-cert.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -days 365

# Generate client private key
openssl genpkey -algorithm RSA -out client-key.pem

# Generate client CSR
openssl req -new -key client-key.pem -out client-csr.pem -subj "/C=GB/ST=London/O=Perseus Demo Accountancy/CN=perseus-demo-accountancy.ib1.org"

# Sign the client CSR with CA key and certificate
openssl x509 -req -in client-csr.pem -out client-cert.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -days 365


# # Generate private key for the server
# openssl genpkey -algorithm RSA -out server-key.pem

# # Generate CSR for the server with subject information
# openssl req -new -key server-key.pem -out server-csr.pem -subj "/C=GB/ST=London/O=Perseus Demo Authentication/CN=perseus-demo-authentication.ib1.org"

# # Create PEM
# openssl x509 -req -days 365 -in server-csr.pem -signkey server-key.pem -out server-cert.pem

# # Generate private key for the client
# openssl genpkey -algorithm RSA -out client-key.pem

# # Generate CSR for the client with subject information
# openssl req -new -key client-key.pem -out client-csr.pem -subj "/C=GB/ST=London/O=Perseus Demo Accountancy/CN=perseus-demo-accountancy.ib1.org"

# # Create PEM
# openssl x509 -req -days 365 -in client-csr.pem -signkey client-key.pem -out client-cert.pem