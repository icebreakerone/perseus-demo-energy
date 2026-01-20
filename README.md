# Perseus demo energy provider

This repository contains two apps that demonstrate securing a mockup smart meter data endpoint using the FAPI standard, in a way that is compliant with the [Perseus Scheme](https://ib1.org/perseus/)

It contains a docker compose based development environment that is helpful for developing client applications.

It may also be a useful reference for developers who are creating secure data endpoints that are compliant with the Perseus Scheme, but is not intended to be a production ready implementation.

## Contents

- [Overview](#overview)
  - [Authentication API](#authentication-api)
  - [Resource API](#resource-api)
- [Development](#development)
  - [Environment variables](#environment-variables)
  - [Running a dev server](#running-a-dev-server)
  - [Creating self signed certificates for development](#creating-self-signed-certificates-for-development)
  - [Running the local docker environment](#running-the-local-docker-environment)
- [Pushed Authorization Request (PAR)](#pushed-authorization-request-par)
- [Ory Hydra](#ory-hydra)
  - [Authentication and consent](#authentication-and-consent)
    - [Flow steps for Ory Hydra with external user management and consent services](#flow-steps-for-ory-hydra-with-external-user-management-and-consent-services)
- [FAPI Flow](#fapi-flow)
- [Deployment](#deployment)
  - [Preparing certificates](#preparing-certificates)
  - [System Context Diagram](#system-context-diagram)
  - [Container Diagram](#container-diagram)

## Overview

### Authentication API

The authentication app is in the [authentication](authentication) directory. It provides endpoints for authenticating and identifying users, and for handling and passing on requests from the client API to the FAPI API. It uses the Ory Hydra service to handle most of the OAuth2 flow, with additional endpoints added to handle the FAPI specific requirements.

Authentication API documentation is available at https://perseus-demo-authentication.ib1.org/api-docs.

#### API Endpoints

The Authentication API provides the following endpoints:

- **`POST /api/v1/par`** - Pushed Authorization Request (PAR) endpoint. Stores authorization request parameters in Redis and returns a `request_uri` token. Requires mTLS client certificate authentication. The client certificate is used to extract the client ID from the certificate extensions.

- **`GET /api/v1/authorize`** - Authorization endpoint that retrieves the PAR request from Redis and redirects the user to Ory Hydra's authorization endpoint for authentication and consent. Accepts a `request_uri` parameter containing the token from the PAR response.

- **`POST /api/v1/authorize/token`** - Token endpoint that issues access and refresh tokens. Supports both authorization code and refresh token grant types. Requires mTLS client certificate authentication. Enhances tokens from Ory Hydra by adding client certificate thumbprint information and stores permissions in Redis.

- **`POST /api/v1/permissions`** - Permissions endpoint that retrieves stored permission data for a given token. Requires mTLS client certificate authentication.

- **`POST /api/v1/authorize/revoke`** - Token revocation endpoint that revokes access or refresh tokens. Requires mTLS client certificate authentication. Delegates to Ory Hydra's revocation endpoint.

- **`GET /.well-known/oauth-authorization-server`** - OAuth 2.0 authorization server metadata endpoint. Returns server configuration including supported endpoints, grant types, response types, and FAPI-specific features like PAR support and mTLS endpoint aliases.

- **`GET /evidence/{evidence_id}`** - Evidence endpoint that displays user-readable permission records. Used to show users what permissions have been granted and when they expire.

### Resource API

The resource api is in the [resource](resource) directory. It demonstrates how to protect an API endpoint using a certificate bound token obtained from the authentication API's interaction with the FAPI provider.

Resource API documentation is available at https://perseus-demo-energy.ib1.org/api-docs.

#### API Endpoints

The Resource API provides the following endpoints:

- **`GET /datasources`** - Lists available data sources. Returns a collection of data sources with their IDs, types, locations, and available measures. Requires both mTLS client certificate authentication and a bearer token (certificate-bound access token). Validates the client certificate has the correct provider role, verifies the token signature and certificate binding.

- **`GET /datasources/{id}/{measure}`** - Retrieves meter data for a specific data source and measure. Requires both mTLS client certificate authentication and a bearer token (certificate-bound access token). Validates the client certificate has the correct provider role, verifies the token signature and certificate binding, and returns meter consumption data along with a provenance record. Accepts query parameters `from` and `to` to specify the date range for the data.


## Development

### Environment variables

Both apps have example `.env.template` files in their root directories. These should be copied to `.env` and edited as required. The following environment variables are used in the authentication app:

- `REDIS_HOST`: a local redis instance is used to store PAR requests
- `OAUTH_CLIENT_ID`: Client ID for the Ory Hydra client
- `OAUTH_URL`: URL for the Ory Hydra client
- `OAUTH_CLIENT_SECRET`: Client secret for the Ory Hydra client
- `REDIRECT_URI`: The page to return to after authentication and authorisation eg. for local development http://127.0.0.1:3000/callback
- `ISSUER_URL`: URL of the Oauth issuer eg. for docker compose https://authentication_web

The following environment variables are used in the resource app:

- `OAUTH_CLIENT_ID`: Client ID for the Ory Hydra client (same as for authentication)
- `OAUTH_CLIENT_SECRET`: Client secret for the Ory Hydra client (same as for authentication)
- `ISSUER_URL`: URL of the Oauth issuer eg. for docker compose https://authentication_web

For more information on generating the client ID and secret, see the [Ory Hydra](#ory-hydra) section.

### Running a dev server

The fastapi servers for each app can be run using:

```bash
cd authentication|resource
pipenv install --dev
pipenv run uvicorn api.main:app --reload
```

**nb** the recommended way to run the apps is using the docker compose environment, as the apps require a redis instance and the resource app requires the authentication app to be running.

### Creating self signed certificates for development

The ib1 directory issues three kinds of certificates, client, server and signing. The client and server certificates are used for mTLS and the signing certificates are used to sign provenance records.

To generate a complete set of self-signed certificates for testing, run the following command:

```bash
cd scripts
./setup.sh
```

The script will generate the required certificates, keys and bundles and move them to the correct file locations for the docker compose dev environment.

#### Outline of certificates used

**nginx**

- certs/client-verify-bundle.pem: The client CA root certificate and intermediate to verify incoming mtls requests
- certs/localhost-key.pem: Key for the localhost tls certificate
- certs/server-complete-bundle.pem: A chain of localhost certificate, intermediate and CA for tls

**Authentication**

- authentication/certs/jwt-signing-key.pem: Key for signing jwt tokens. This is not a directory certificate.

**Resource**

- resource/signing-issued-intermediate-bundle.pem: A chain of issued certificate and intermediate used in creating provenance records
- resource/edp-demo-signing-key.pem: Provenance record signing key
- resource/edp-demo-signing-cert.pem: Provenance record signing certificate
- resource/signing-ca-cert.pem: Root CA certificate for the signing CA used in provenance

**Others**

The remaining files in scripts/generated directory will be the key and certificate for each of the three CAs with matching intermediates. Files in cerscriptsts/generated/client can be used by a client application (such as the demo cap) to make mtls secured connections and verify the server certificate.

- certs/client/edp-demo-client-bundle.pem: Client mtls certificate
- ccerts/client/edp-demo-client-key.pem: Client private key
- certs/client/server-bundle.pem: Root CA and intermediate certificate to validate the server certificate

### Running the local docker environment

The included docker compose file will bring up both APIs. It uses nginx to proxy requests to uvicorn, with nginx configuration to pass through client certificates to the backend, using the same header as used by AWS ALB (`x-amzn-mtls-clientcert`).

```bash
docker-compose up
```

## Pushed Authorization Request (PAR)

As PAR is not available on the Ory Hydra service that this demo is based on, a PAR endpoint has been implemented in this example service. It is expected that production ipmlementations may use the PAR endpoint of their Fapi provider.

In this simple implementation, the request is stored in a redis instance, using a token that matches Fapi requirements as the key.

## Ory Hydra

Please contact [tf-ops@icebreakerone.org](mailto:tf-ops@icebreakerone.org) for the Client ID and secret if you would like to test against our demo Ory account. Alternatively you can set up a free developer account and create an OAuth2 client with your own details. The client should have:

- Authentication method set to None
- Grant types authorization Code and Refresh Token
- Response types Code and ID Token
- Access Token Type jwt
- Scopes profile and offline_access
- Redirect urls to match your production and/or development and local redirect URLs

![Authentication Method None](docs/authentication-method-none.png)

![Grant Types and Response Types](docs/supported-flows.png)

![Scopes and redirecs](docs/scope-redirects.png)

### Authentication and consent

For this demo, we have used Ory hydra user management platform to provide authentication and consent as part of the authorization code flow. In production, data providers will be using existing user management systems. Some user management platforms may provide OAuth2 endpoints as Ory Hydra does, in other cases the implementation may need to integrate separate OAuth and user management and consent services. Whilst it is outside of the scope of this demo to anticipate all configurations, the following steps explain how a separate user management and consent service might be integrated, using Ory OAuth2 as an example.

#### Flow steps for Ory Hydra with external user management and consent services

1. The OAuth 2.0 Client initiates an Authorize Code flow, and the user is redirected to Ory OAuth2

2. Ory OAuth2, if unable to authenticate the user (no session cookie exists), redirects the user's user agent to the Login Provider's login page. The URL the user is redirected to looks like https://data-provider.com/oauth2-screens/login?login_challenge=1234....

3. The Login Provider, once the user has logged in, tells Ory OAuth2 some information about who the user is (for example the user's ID) and also that the login attempt was successful. This is done using a REST request which returns another redirect URL like https://{project-slug}.projects.oryapis.com/oauth2/auth?client_id=...&...&login_verifier=4321.

4. The user's user agent follows the redirect and lands back at Ory OAuth2. Next, Ory OAuth2 redirects the user's user agent to the Consent Provider, hosted at - for example - https://example.org/oauth2-screens/consent?consent_challenge=4567...

5. The Consent Provider shows a user interface which asks the user if they would like to grant the OAuth 2.0 Client the requested permissions ("OAuth 2.0 Scope").

6. The Consent Provider makes another REST request to Ory OAuth2 to let it know which permissions the user authorized, and if the user declined consent. In the response to that REST request, a redirect URL is included like https://{project-slug}.projects.oryapis.com/oauth2/auth?client_id=...&...&consent_verifier=7654....

7. The user's user agent follows that redirect.

8. Now, the user has authenticated and authorized the application. Ory OAuth2 will run checks and if all is well issue access, refresh, and ID tokens.

A full example is available at [https://www.ory.sh/docs/hydra/guides/custom-ui-oauth2](https://www.ory.sh/docs/hydra/guides/custom-ui-oauth2).

## FAPI Flow

![FAPI Flow diagram](docs/fapi-authlete-flow.png)

## Deployment

Both APIs are deployed using cdk. With a fresh install, the resource api should be deployed first as the trust store for client mtls connections is shared with both deployments.

```bash
cd /resource/cdk
cdk deploy --context deployment_context=dev
cd /authentication/cdk
cdk deploy --context deployment_context=dev
```

### Preparing certificates

The certificates required for the mtls truststores are available at https://member.core.sandbox.trust.ib1.org/ca. The cdk deployments will upload these certificates into the truststores if they are available, using the locations:

- resource/cdk/truststores/directory-dev-client-certificates
- resource/cdk/truststores/directory-prod-client-certificates

Both the resource and authentication apps use these CA certificates. If the CA certificates need to be updated, the truststore used by the authentication app will need to be renewed by running resource/cdk/scripts/renew_truststores.sh

A set of signing certificates are also required for signing provenance records. The CA files can be download as above, and a key and certificate can be created from https://member.core.sandbox.trust.ib1.org/applications/ by clicking "New Signing Certificate" and following instructions.

A script is available ([resource/cdk/scripts/upload-certificates.sh](resource/cdk/scripts/upload-certificates.sh)) which will upload files into the correct locations. You will need to create a certificate chain with the leaf certificate and the intermediate CA. Check the upload script for further details.

Another script is available [resource/cdk/scripts/checkcerts.sh](resource/cdk/scripts/checkcerts.sh) which can be used to check you a valid set of signing certificates before uploading.

### System Context Diagram

![System Context Diagram](docs/System%20Context%20Diagram.png)

### Container Diagram

![Container Diagram](docs/Container%20Diagram.png)
