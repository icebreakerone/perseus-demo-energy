openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out jwt-signing-key.pem
openssl ec -in ec-key.pem -pubout -out jwt-signing-pub.pem