# Create a key pair suitable for signing jwts and creating a jwks endpoint

openssl ecparam -name prime256v1 -genkey -noout -out server-signing-private-key.pem 
openssl ec -in server-signing-private-key.pem -pubout -out server-signing-public-key.pem

