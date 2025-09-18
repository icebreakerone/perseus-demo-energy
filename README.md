# Perseus demo energy provider

This repository contains two apps that demonstrate securing a mockup smart meter data endpoint using the FAPI standard, in a way that is compliant with the [Perseus Scheme](https://ib1.org/perseus/)

It contains a docker compose based development environment that is helpful for developing client applications.

It may also be a useful reference for developers who are creating secure data endpoints that are compliant with the Perseus Scheme, but is not intended to be a production ready implementation.

## Contents

- [Authentication API](#authentication-api)
- [Resource API](#resource-api)
- [Environment variables](#environment-variables)
- [Running a dev server](#running-a-dev-server)
- [Creating self-signed certificates](#creating-self-signed-certificates)
  - [Using client certificates](#using-client-certificates)
- [Creating signing certificates](#creating-signing-certificates)
- [Running the local docker environment](#running-the-local-docker-environment)
- [Pushed Authorization Request (PAR)](#pushed-authorization-request-par)
- [Testing the API with client.py](#testing-the-api-with-clientpy)
  - [Auth](#auth)
  - [Client demo app](#client-demo-app)
  - [Introspection](#introspection)
  - [Client side id_token decoding](#client-side-id_token-decoding)
  - [Retrieve data from protected endpoint](#retrieve-data-from-protected-endpoint)
- [Ory Hydra](#ory-hydra)
  - [Authentication and consent](#authentication-and-consent)
    - [Flow steps for Ory Hydra with external user management and consent services](#flow-steps-for-ory-hydra-with-external-user-management-and-consent-services)
- [FAPI Flow](#fapi-flow)

## Authentication API

The authentication app is in the [authentication](authentication) directory. It provides endpoints for authenticating and identifying users, and for handling and passing on requests from the client API to the FAPI API. It uses the Ory Hydra service to handle most of the OAuth2 flow, with additional endpoints added to handle the FAPI specific requirements.

Authentication API documentation is available at https://perseus-demo-authentication.ib1.org/api-docs.

## Resource API

The resource api is in the [resource](resource) directory. It demonstrates how to protect an API endpoint using a certificate bound token obtained from the authentication API's interaction with the FAPI provider.

Resource API documentation is available at https://perseus-demo-energy.ib1.org/api-docs.

## Environment variables

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

## Running a dev server

The fastapi servers for each app can be run using:

```bash
cd authentication|resource
pipenv install --dev
pipenv run uvicorn api.main:app --reload
```

**nb** the recommended way to run the apps is using the docker compose environment, as the apps require a redis instance and the resource app requires the authentication app to be running.

## Creating self signed certificates for development

The ib1 directory issues three kinds of certificates, client, server and signing. The client and server certificates are used for mTLS and the signing certificates are used to sign provenance records.

To generate a complete set of self-signed certificates for testing, run the following command:

```bash
cd scripts
./setup.sh
```

The script will generate the required certificates, keys and bundles and move them to the correct file locations for the docker compose dev environment.

### Outline of certificates used

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

## Running the local docker environment

The included docker compose file will bring up both APIs. It uses nginx to proxy requests to uvicorn, with nginx configuration to pass through client certificates to the backend, using the same header as used by AWS ALB (`x-amzn-mtls-clientcert`).

```bash
docker-compose up
```

## Pushed Authorization Request (PAR)

As PAR is not available on the Ory Hydra service that this demo is based on, a PAR endpoint has been implemented in this example service. It is expected that production ipmlementations may use the PAR endpoint of their Fapi provider.

In this simple implementation, the request is stored in a redis instance, using a token that matches Fapi requirements as the key.

## Testing the API with client.py

client.py can be used to test authorization code flow, introspection, id_token decoding and retrieving data from the resource URL.

Four commands are available, and are run using:

```bash
python -W ignore  client.py [auth|introspect|id-token|resource]
```

nb. The optional `-W ignore` switch suppresses multiple warnings about the self-signed certificates.

### Auth

Running `client.py auth` will perform the initial steps in the authorization code flow, outputting the URL of a UI to log in and confirm consent. The PKCE code verifier will also be in the output, which will be needed after the redirect

```bash
python -W ignore  client.py auth
```

Example output:

```bash
Code verifier: c6P-FfD0ayLslzCUESCsay8QHEg71O0SnKLeHPkOSyOZ6KubKPRaclM4u5veKcqI7MNqZX_xAUt4CUwIwm4JD99EacbtjAABbyY1i972umU9Ong9HFjtJq84y5mljGFy
https://vigorous-heyrovsky-1trvv0ikx9.projects.oryapis.com/oauth2/auth?client_id=f67916ce-de33-4e2f-a8e3-cbd5f6459c30&response_type=code&redirect_uri=http://127.0.0.1:3000/callback&scope=profile+offline_access&state=9mpb2gDwhp2fLTa_MwJGM21R7FjOQCJq&code_challenge=cksXMlSWrcflDTJoyrpiWX0u2VRV6C--pzetmBIo6LQ&code_challenge_method=S256
```

By default the client will use the local docker environment and expects instances to be running on ports 8000 (authentication) and 8010 (resource). Testing against other endpoints can be achieved by setting the `AUTHENTICATION_API` and `RESOURCE_API` environment variables, eg. to test against the deployed demo:

```bash
AUTHENTICATION_API="https://perseus-demo-authentication.ib1.org" RESOURCE_API=https://perseus-demo-energy.ib1.org python -W ignore  client.py auth
```

Opening the redirect url will present you with the default Ory Hydra log in/ sign up screen, followed by a consent screen:

![Consent screen](docs/consent.png)

Granting consent will redirect to our demo client application, with the authorization code appended to the url. The authorization code can be exchanged for an access token by adding the code_verifier value to the form and submitting:

![Redirect](docs/exchange.png)

### Client demo app

As an alternative to the command line client, the authorization flow can be completed in a browser at https://perseus-demo-accounting.ib1.org/start. Technical information such as the code verifier, token, and the contents of the introspected token are displayed
at each step.

### Retrieve data from protected endpoints

```bash
python -W ignore  client.py resource --token <token>
```

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

```

```
