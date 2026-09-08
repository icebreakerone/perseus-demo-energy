# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## Project Overview

This repository demonstrates securing a mockup smart meter data endpoint using the FAPI (Financial-grade API) standard, compliant with the Perseus Scheme (https://ib1.org/perseus/). It contains two FastAPI applications that work together:

- **Authentication API** (`authentication/`): Handles OAuth2 authorization flows with FAPI extensions (PAR, mTLS, certificate-bound tokens). Uses Ory Hydra as the upstream OAuth2 provider and Redis for PAR request storage.
- **Resource API** (`resource/`): Demonstrates protected API endpoints using certificate-bound access tokens. Returns mock meter data with provenance records.

## Specifications

The implementation adheres to the following IB1 Trust Framework specifications:

- **Certificates** — [Member Identity Digital Certificates 1.0](https://specification.trust.ib1.org/member-identity-digital-certificates/1.0/)
- **OAuth** — [OAuth with Member Identity Certificates 1.0](https://specification.trust.ib1.org/oauth-with-member-identity-certificates/1.0/#oauth-profile)
- **Provenance** — [Provenance Records 1.0](https://specification.trust.ib1.org/provenance-records/1.0/)

## Development Environment Setup

```bash
# Refresh certificates for local development. Client and signing certificates
# are issued by the real sandbox directory; only the localhost server
# certificate is generated locally. Needs `directory login` first.
./scripts/refresh-certs.sh --restart
# Offline fallback, fully self-signed:
./scripts/setup-offline.sh

# Run with Docker Compose (recommended)
docker compose up

# Run individual app without Docker
cd authentication  # or resource
pipenv install --dev
pipenv run uvicorn api.main:app --reload
```

## Linting

```bash
# Lint with ruff (used in CI)
cd authentication  # or resource
pipenv run ruff check .
```

## Deployment (CDK)

```bash
# Deploy resource API first (creates shared truststore)
cd resource/cdk
cdk deploy --context deployment_context=dev

# Then deploy authentication API
cd authentication/cdk
cdk deploy --context deployment_context=dev
```

## Architecture

### Certificate Types

The IB1 directory issues three certificate types:

- **Client certificates**: For mTLS authentication
- **Server certificates**: For TLS
- **Signing certificates**: For signing provenance records

Locally, client and signing certificates come from the real sandbox directory
via the `directory` CLI, so roles and identity extensions match production. The
localhost server certificate is generated with openssl, because no directory
issues certificates for localhost.

Each component is a different scheme participant. The resource API is an energy
data provider and signs provenance records with an EDP signing certificate.
cap-demo is a carbon accounting provider and holds the client certificate used
for mTLS. `SCHEME_BASE_URL` defaults to sandbox in both conf.py files, so the
roles in a sandbox certificate match without further configuration.

nginx reads its certificates once at startup, so restart the web containers
after refreshing them.

### External Dependencies

- **ib1-directory**: The Python library (`from ib1 import directory`) used for certificate parsing, role validation and application ID extraction. The same package also provides an `ib1-directory` command, used only by `scripts/setup-offline.sh` to generate a self-signed PKI. That command is expected to be deprecated; `scripts/refresh-certs.sh` does not use it.
- **ib1-provenance**: Provenance record creation and signing
- **Ory Hydra**: Upstream OAuth2 provider (external service)

## Docker Services

The compose file runs:

- `authentication_web`: nginx proxy for authentication backend (port 8000)
- `resource_web`: nginx proxy for resource backend (port 8010)
- `redis`: PAR request storage
- `dynamodb-local`: Permission storage for local dev

Nginx passes client certificates via `x-amzn-mtls-clientcert-leaf` header, matching AWS ALB behavior.
