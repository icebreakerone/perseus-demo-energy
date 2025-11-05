#!/bin/bash

set -e

BUNDLE=${1:-./deployment/signing-certs/directory-signing-certificates/bundle.pem}
ROOT_CA=${2:-./deployment/signing-certs/directory-signing-certificates/root-ca.pem}
INTERMEDIATE=${3:-./deployment/signing-certs/directory-signing-certificates/intermediate.pem}
LEAF_CERT=${4:-./deployment/signing-certs/Perseus-Demo-Energy-Resource.pem}

# Check how many certificates are in the bundle (should be 2)
grep -c "BEGIN CERTIFICATE" $BUNDLE

# Verify the first certificate's issuer matches the second certificate's subject
# This ensures the bundle is in the correct order: leaf first, intermediate second
ISSUER=$(openssl x509 -in $BUNDLE -noout -issuer | sed 's/issuer=//')
# Extract second certificate from bundle (intermediate) and get its subject

TMP_CERT=$(mktemp)
awk '/BEGIN CERTIFICATE/ {i++; if (i==2) p=1} p; /END CERTIFICATE/ && p==1 {print; exit}' $BUNDLE > $TMP_CERT
SUBJECT=$(openssl x509 -in $TMP_CERT -noout -subject | sed 's/subject=//')
rm -f $TMP_CERT
echo "ISSUER: $ISSUER"
echo "SUBJECT: $SUBJECT"
if [ "$ISSUER" = "$SUBJECT" ]; then
  echo "✓ Bundle order is correct: leaf certificate is first, intermediate is second"
else
  echo "✗ Bundle order is incorrect: issuer/subject mismatch"
fi


echo "Verifying leaf certificate using the intermediate explicitly"
openssl verify -CAfile $ROOT_CA -untrusted $INTERMEDIATE $LEAF_CERT

# Verify bundle using the intermediate explicitly
echo "Verifying bundle using the intermediate explicitly"
openssl verify -CAfile $ROOT_CA -untrusted $INTERMEDIATE $BUNDLE

