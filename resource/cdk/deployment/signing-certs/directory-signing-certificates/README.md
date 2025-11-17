# Signing Certificates

Contains:

- root-ca.pem: The root certificate authority (CA) certificate.
- intermediate.pem: The intermediate certificate.
- bundle.pem: The leaf and intermediate certificates combined (leaf first, then intermediate).

## Verifying Certificate Chain and Bundle Order

### Check that bundle is in the correct order

The bundle should contain certificates in this order:

1. Leaf certificate (first)
2. Intermediate certificate (second)

Verify the order:

```bash
# Check how many certificates are in the bundle (should be 2)
grep -c "BEGIN CERTIFICATE" bundle.pem

# Verify the first certificate's issuer matches the second certificate's subject
ISSUER=$(openssl x509 -in bundle.pem -noout -issuer | sed 's/issuer=//')
SUBJECT=$(openssl x509 -in bundle.pem -noout -subject -skip 1 | sed 's/subject=//')

if [ "$ISSUER" = "$SUBJECT" ]; then
  echo "✓ Bundle order is correct: leaf certificate is first, intermediate is second"
else
  echo "✗ Bundle order is incorrect: issuer/subject mismatch"
fi
```

### Verify the complete certificate chain

Verify that your leaf certificate matches the CA certificate chain:

```bash
# Replace LEAF_CERT.pem with your actual leaf certificate filename
openssl verify -CAfile root-ca.pem -untrusted intermediate.pem LEAF_CERT.pem
```

Expected output: `LEAF_CERT.pem: OK`

### Verify bundle against CA chain

If you have a bundle file (leaf + intermediate), verify it:

```bash
# Verify bundle using the intermediate explicitly
openssl verify -CAfile root-ca.pem -untrusted intermediate.pem bundle.pem
```

Expected output: `bundle.pem: OK`

### Quick verification commands

```bash
# 1. Verify intermediate is signed by root CA
openssl verify -CAfile root-ca.pem intermediate.pem

# 2. Check certificate expiration dates
openssl x509 -in bundle.pem -noout -enddate
openssl x509 -in intermediate.pem -noout -enddate
openssl x509 -in root-ca.pem -noout -enddate

# 3. View certificate details
openssl x509 -in bundle.pem -text -noout | head -20
```
