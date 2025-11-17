#!/bin/bash

set -e

# Usage: ./upload-certificates.sh [ROOT_CA] [BUNDLE] [SIGNING_KEY] [DEPLOYMENT_CONTEXT]
#
# Uploads signing certificates and key to AWS S3 and SSM Parameter Store.
#
# Arguments (all optional, defaults shown):
#   ROOT_CA: Path to root CA certificate (default: ./deployment/signing-certs/directory-signing-certificates-3/root-ca.pem)
#   BUNDLE: Path to certificate bundle (default: ./deployment/signing-certs/directory-signing-certificates-3/bundle.pem)
#   SIGNING_KEY: Path to signing key (default: ./deployment/signing-certs/directory-signing-certificates-3/signing-key.pem)
#   DEPLOYMENT_CONTEXT: Deployment context for SSM path (default: dev, or CDK_DEPLOYMENT_CONTEXT env var)
#
# Examples:
#   ./upload-certificates.sh
#   ./upload-certificates.sh ./certs/root-ca.pem ./certs/bundle.pem ./certs/key.pem prod
#   DEPLOYMENT_CONTEXT=prod ./upload-certificates.sh

# Default file paths (based on checkcerts.sh defaults)
# Allow overrides via command line arguments
ROOT_CA=${1:-./deployment/signing-certs/directory-signing-certificates-3/root-ca.pem}
BUNDLE=${2:-./deployment/signing-certs/directory-signing-certificates-3/bundle.pem}
SIGNING_KEY=${3:-./deployment/signing-certs/directory-signing-certificates-3/signing-key.pem}
DEPLOYMENT_CONTEXT=${4:-${CDK_DEPLOYMENT_CONTEXT:-dev}}

# S3 bucket for certificates
S3_BUCKET="perseus-demo-energy-certificate-store"

# SSM parameter path for signing key
SSM_PARAMETER_PATH="/copilot/perseus-demo-energy/${DEPLOYMENT_CONTEXT}/secrets/signing-key"

echo "Uploading certificates and signing key..."
echo "Deployment context: ${DEPLOYMENT_CONTEXT}"
echo ""

# Verify files exist
if [ ! -f "$ROOT_CA" ]; then
    echo "Error: Root CA file not found: $ROOT_CA"
    exit 1
fi

if [ ! -f "$BUNDLE" ]; then
    echo "Error: Bundle file not found: $BUNDLE"
    exit 1
fi

if [ ! -f "$SIGNING_KEY" ]; then
    echo "Error: Signing key file not found: $SIGNING_KEY"
    exit 1
fi

# Upload root CA to S3
echo "Uploading root CA to S3..."
aws s3 cp "$ROOT_CA" "s3://${S3_BUCKET}/signing-root-ca.pem"
echo "✓ Root CA uploaded to s3://${S3_BUCKET}/signing-root-ca.pem"
echo ""

# Upload bundle to S3
echo "Uploading bundle to S3..."
aws s3 cp "$BUNDLE" "s3://${S3_BUCKET}/signing-issued-bundle.pem"
echo "✓ Bundle uploaded to s3://${S3_BUCKET}/signing-issued-bundle.pem"
echo ""

# Upload signing key to SSM Parameter Store
echo "Uploading signing key to SSM Parameter Store..."
# Check if parameter already exists
if aws ssm get-parameter --name "$SSM_PARAMETER_PATH" &>/dev/null; then
    echo "Parameter already exists. Updating..."
    aws ssm put-parameter \
        --name "$SSM_PARAMETER_PATH" \
        --value "$(cat "${SIGNING_KEY}")" \
        --type "SecureString" \
        --overwrite
else
    echo "Creating new parameter..."
    aws ssm put-parameter \
        --name "$SSM_PARAMETER_PATH" \
        --value "$(cat "${SIGNING_KEY}")" \
        --type "SecureString"
fi
echo "✓ Signing key uploaded to ${SSM_PARAMETER_PATH}"
echo ""

echo "All files uploaded successfully!"
echo ""
echo "Summary:"
echo "  - Root CA: s3://${S3_BUCKET}/signing-root-ca.pem"
echo "  - Bundle: s3://${S3_BUCKET}/signing-issued-bundle.pem"
echo "  - Signing Key: ${SSM_PARAMETER_PATH}"

