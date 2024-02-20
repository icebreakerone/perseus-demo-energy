# Create a key and pem. The pem file is suitable for the test suite.
# Create a cert.pem and a fail.pem. The test jwt will need to be updated with the cert's thumbprint.

openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/C=GB/O=IB1 Trust Framework/OU=test/CN=client-id"