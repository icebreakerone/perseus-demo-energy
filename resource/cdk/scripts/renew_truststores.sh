#!/bin/bash

set -euo pipefail

function usage() {
  cat <<'EOF'
Usage: renew_truststores [environment ...]

Without arguments the script updates both dev and prod trust stores. Specify one
or more environment names to limit the update (e.g. "renew_truststores dev").
The AWS region defaults to eu-west-2 unless AWS_REGION or AWS_DEFAULT_REGION is
set.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-eu-west-2}}"
if [[ -z "$REGION" ]]; then
  echo "AWS region must be specified via AWS_REGION or AWS_DEFAULT_REGION" >&2
  exit 1
fi

if [[ $# -gt 0 ]]; then
  envs=("$@")
else
  envs=(dev prod)
fi

for env in "${envs[@]}"; do
  bucket="perseus-resource-truststore-${env}"
  key="bundle.pem"
  trust_store_name="PerseusAuthenticationTrust-${env}"

  echo "\n=== Updating trust store for environment: ${env} ==="
  echo "Region: ${REGION}"
  echo "Source bucket: ${bucket}/${key}"

  version_id=$(aws s3api list-object-versions \
    --bucket "${bucket}" \
    --prefix "${key}" \
    --region "${REGION}" \
    --query 'Versions[?IsLatest==`true` && Size>`0`].VersionId | [0]' \
    --output text || true)

  if [[ -z "${version_id}" || "${version_id}" == "None" ]]; then
    echo "!! Could not determine the latest version for ${bucket}/${key}. Skipping." >&2
    continue
  fi

  trust_store_arn=$(aws elbv2 describe-trust-stores \
    --region "${REGION}" \
    --query "TrustStores[?Name=='${trust_store_name}'].TrustStoreArn | [0]" \
    --output text || true)

  if [[ -z "${trust_store_arn}" || "${trust_store_arn}" == "None" ]]; then
    echo "!! Trust store ${trust_store_name} not found in region ${REGION}. Skipping." >&2
    continue
  fi

  echo "Found trust store ARN: ${trust_store_arn}"
  echo "Using object version: ${version_id}"

  aws elbv2 modify-trust-store \
    --region "${REGION}" \
    --trust-store-arn "${trust_store_arn}" \
    --ca-certificates-bundle-s3-bucket "${bucket}" \
    --ca-certificates-bundle-s3-key "${key}" \
    --ca-certificates-bundle-s3-object-version "${version_id}"

  echo "Trust store ${trust_store_name} updated successfully."

done
