# Perseus demo energy provider

Emulates authentication and resource api endpoints for the Perseus demo. Authentication is built on top of [Ory Hydra](https://www.ory.sh).

## Authentication API

The authentication app is in the [authentication](authentication) directory. It provides endpoints for authenticating and identifying users, and for handling and passing on requests from the client API to the FAPI API. It uses a

Authentication API documentation is available at https://perseus-demo-authentication.ib1.org/api-docs.

## Resource API

The resource api is in the [resource](resource) directory. It demonstrates how to protect an API endpoint using a certificate bound token obtained from the authentication API's interaction with the FAPI provider.

Resource API documentation is available at https://perseus-demo-energy.ib1.org/api-docs.

## Running a dev server

```bash
cd authentication|resource
pipenv install --dev
pipenv run uvicorn api.main:app --reload
```

## Creating self-signed certificates

The docker compose and client.py scripts require a set of self-signed certificates in a certs/ folder. These can be generated using the `certmaker.sh` script in the `scripts` directory.

```bash
cd scripts
./certmaker.sh
```

You will need to create a "certs" directory in the root of the project, and move the generated certificates into it.

### Using client certificates

Most of the endpoints require a client certificate to be presented. As the directory service is not yet available, the contents of the certificate will not be checked with an external, so any valid certificate will be acceptable. The certificate **is** used to confirm identity, so the same one must be presented in all requests.

## Creating signing certificates

A separate set of certificates are required for signing JWTs. These can be generated using the `signingcerts.sh` script in the `scripts` directory.

```bash
cd scripts
./signingcerts.sh
```

The default configuration will expect these certificate to be in authentication/api/certs. The location can be changed by setting the DIRECTORY_CERTIFICATE and DIRECTORY_PRIVATE_KEY environment variables.

## Running the local docker environment

The included docker compose file will bring up both APIs. It uses nginx to proxy requests to uvicorn, with nginx configuration to pass through client certificates to the backend, using the same header as used by AWS ALB (`x-amzn-mtls-clientcert`).

```bash
docker-compose up
```

The environment variables in the docker compose file point to the FAPI api running on localhost port 8020 (http://host.docker.internal:8020). As the FAPI api is not running in the docker environment, you may need to change these environment variables to match your local environment. It will also work with the live FAPI api by changing these values to "https://perseus-demo-authentication.ib1.org".

## Pushed Authorization Request (PAR)

As PAR is not available on the Ory Hydra service that this demo is based on, a PAR endpoint has been implemented in this example service. It is expected that production ipmlementations may use the PAR endpoint of their Fapi provider.

In this simple implementation, the request is stored in a redis instance, using a token that matches Fapi requirements as the key.

## Testing the API with client.py

client.py can be used to test authorisation code flow, introspection, id_token decoding and retrieving data from the resource URL.

Four commands are available, and are run using:

```bash
python -W ignore  client.py [auth|introspect|id-token|resource]
```

nb. The optional `-W ignore` switch suppresses multiple warnings about the self-signed certificates.

### Auth

Running `client.py auth` will perform the initial steps in the authorisation code flow, outputting a URL that will open the UI to log in and confirm consent. The PKCE code verifier will also be in the output, which will be needed after the redirect

```bash
python -W ignore  client.py auth
```

Example output:

```bash
Code verifier: c6P-FfD0ayLslzCUESCsay8QHEg71O0SnKLeHPkOSyOZ6KubKPRaclM4u5veKcqI7MNqZX_xAUt4CUwIwm4JD99EacbtjAABbyY1i972umU9Ong9HFjtJq84y5mljGFy
https://vigorous-heyrovsky-1trvv0ikx9.projects.oryapis.com/oauth2/auth?client_id=f67916ce-de33-4e2f-a8e3-cbd5f6459c30&response_type=code&redirect_uri=http://127.0.0.1:3000/callback&scope=profile+offline_access&state=9mpb2gDwhp2fLTa_MwJGM21R7FjOQCJq&code_challenge=cksXMlSWrcflDTJoyrpiWX0u2VRV6C--pzetmBIo6LQ&code_challenge_method=S256
```

By default the client will use the local docker environment and expects a local instance of the FAPI api to be running on localhost:8020. Testing against the deployed API can be achieved by setting the `AUTHENTICATION_API` and `RESOURCE_API` environment variables, and optionally the FAPI_API environment variable.

```bash
FAPI_API=https://perseus-demo-authentication.ib1.org AUTHENTICATION_API="https://perseus-demo-authentication.ib1.org" RESOURCE_API=https://perseus-demo-energy.ib1.org python -W ignore  client.py auth
```

Opening the redirect url will present you with the default Ory Hydra log in/ sign up screen, followed by a consent screen:

![Consent screen](docs/consent.png)

Granting consent will redirect to our demo client application, with the authorisation code appended to the url. The authorisation code can be exchanged for an access token by adding the code_verifier value to the form and submitting:

![Redirect](docs/exchange.png)

### Introspection

To show the response of the introspection endpoint, run:

```bash
python -W ignore  client.py introspect --token <token>
```

with token being the `token` value obtained from authorisation code flow

### Client side id_token decoding

To show the response of client side id_token decoding, run:

```bash
python -W ignore  client.py id-token --token <token>
```

with token being the `id_token` value obtained from authorisation code flow

### Retrieve data from protected endpoint

```bash
python -W ignore  client.py resource --token <token>
```

## Ory Hydra

Please contact IB1 for the Client ID and secret if you would like to test against our demo Ory account. Alternatively you can set up a free developer account and create an Oauth2 client with your own details. The client should have:

- Authentication method set to None
- Grant types Authorisation Code and Refresh Token
- Response types Code and ID Token
- Access Token Type jwt
- Scopes profile and offline_access
- Redirect urls to match your production and/or development and local redirect URLs

![Authentication Method None](docs/authentication-method-none.png)

![Grant Types and Response Types](docs/supported-flows.png)

![Scopes and redirecs](docs/scope-redirects.png)

## FAPI Flow

![FAPI Flow diagram](docs/fapi-authlete-flow.png)
