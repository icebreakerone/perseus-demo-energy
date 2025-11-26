#!/bin/bash

set -e

# Usage: ./upload-certificates.sh [OPTIONS]
#
# Uploads signing certificates and key to AWS S3 and SSM Parameter Store.
#
# Options:
#   --root-ca PATH          Path to root CA certificate
#                           (default: ./deployment/signing-certs/directory-signing-certificates/root-ca.pem)
#   --bundle PATH           Path to certificate bundle
#                           (default: ./deployment/signing-certs/directory-signing-certificates/bundle.pem)
#   --signing-key PATH      Path to signing key
#                           (default: ./deployment/signing-certs/v60qlnnh-key.pem)
#   --deployment-context CTX Deployment context for SSM path
#                           (default: prod, or CDK_DEPLOYMENT_CONTEXT env var)
#   -h, --help              Show this help message
#
# Examples:
#   ./upload-certificates.sh
#   ./upload-certificates.sh --root-ca ./certs/root-ca.pem --bundle ./certs/bundle.pem
#   ./upload-certificates.sh --deployment-context dev --signing-key ./certs/key.pem
#   DEPLOYMENT_CONTEXT=prod ./upload-certificates.sh

# Default file paths (based on checkcerts.sh defaults)
ROOT_CA="./deployment/signing-certs/directory-signing-certificates/root-ca.pem"
BUNDLE="./deployment/signing-certs/signing-issued-intermediate-bundle.pem"
SIGNING_KEY="./deployment/signing-certs/signing-key.pem"
DEPLOYMENT_CONTEXT="${CDK_DEPLOYMENT_CONTEXT:-prod}"

# Parse named arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --root-ca)
            if [[ -z "$2" ]]; then
                echo "Error: --root-ca requires a value"
                exit 1
            fi
            ROOT_CA="$2"
            shift 2
            ;;
        --bundle)
            if [[ -z "$2" ]]; then
                echo "Error: --bundle requires a value"
                exit 1
            fi
            BUNDLE="$2"
            shift 2
            ;;
        --signing-key)
            if [[ -z "$2" ]]; then
                echo "Error: --signing-key requires a value"
                exit 1
            fi
            SIGNING_KEY="$2"
            shift 2
            ;;
        --deployment-context)
            if [[ -z "$2" ]]; then
                echo "Error: --deployment-context requires a value"
                exit 1
            fi
            DEPLOYMENT_CONTEXT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --root-ca PATH          Path to root CA certificate"
            echo "  --bundle PATH           Path to certificate bundle"
            echo "  --signing-key PATH      Path to signing key"
            echo "  --deployment-context CTX Deployment context for SSM path"
            echo "  -h, --help              Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0"
            echo "  $0 --root-ca ./certs/root-ca.pem --bundle ./certs/bundle.pem"
            echo "  $0 --deployment-context dev --signing-key ./certs/key.pem"
            exit 0
            ;;
        *)
            echo "Error: Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done
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

