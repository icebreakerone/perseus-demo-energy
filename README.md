# Perseus demo energy provider

Emulates authentication and resource api endpoints for the Perseus demo.

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

## Running the local docker environment

The included docker compose file will bring up both APIs. It uses nginx to proxy requests to uvicorn, with nginx configuration to pass through client certificates to the backend, using the same header as used by AWS ALB (`x-amzn-mtls-clientcert`).

```bash
docker-compose up
```

The environment variables in the docker compose file point to the FAPI api running on localhost port 8020 (http://host.docker.internal:8020). As the FAPI api is not running in the docker environment, you may need to change these environment variables to match your local environment. It will also work with the live FAPI api by changing these values to "https://perseus-demo-fapi.ib1.org".

## Pushed Authorization Request (PAR)

As PAR is not available on the Ory Hydra service that this demo is based on, a PAR endpoint has been implemented in this example service. It is expected that production ipmlementations may use the PAR endpoint of their Fapi provider.

In this simple implementation, the request is stored in a redis instance, using a token that matches Fapi requirements as the key.

## Testing the API with client.py

Running client.py will perform the initial steps in the authorisation code flow, outputting a URL that will open the UI to log in and confirm consent. The PKCE code verifier will also be in the output, which will be needed after the redirect

```bash
python -W ignore  client.py
```

Example output:

```bash
Code verifier: c6P-FfD0ayLslzCUESCsay8QHEg71O0SnKLeHPkOSyOZ6KubKPRaclM4u5veKcqI7MNqZX_xAUt4CUwIwm4JD99EacbtjAABbyY1i972umU9Ong9HFjtJq84y5mljGFy
https://vigorous-heyrovsky-1trvv0ikx9.projects.oryapis.com/oauth2/auth?client_id=f67916ce-de33-4e2f-a8e3-cbd5f6459c30&response_type=code&redirect_uri=http://127.0.0.1:3000/callback&scope=profile+offline_access&state=9mpb2gDwhp2fLTa_MwJGM21R7FjOQCJq&code_challenge=cksXMlSWrcflDTJoyrpiWX0u2VRV6C--pzetmBIo6LQ&code_challenge_method=S256&request={"response_type": "code", "client_id": "f67916ce-de33-4e2f-a8e3-cbd5f6459c30", "code_challenge": "cksXMlSWrcflDTJoyrpiWX0u2VRV6C--pzetmBIo6LQ", "code_challenge_method": "S256", "redirect_uri": "http://127.0.0.1:3000/callback", "state": "9mpb2gDwhp2fLTa_MwJGM21R7FjOQCJq", "scope": "profile+offline_access"}
```

nb. The `-W ignore` switch suppresses multiple warnings about the self-signed certificates.

By default the client will use the local docker environment and expects a local instance of the FAPI api to be running on localhost:8020. Testing against the deployed API can be achieved by setting the `AUTHENTICATION_API` and `RESOURCE_API` environment variables, and optionally the FAPI_API environment variable.

```bash
FAPI_API=https://perseus-demo-fapi.ib1.org AUTHENTICATION_API="https://perseus-demo-authentication.ib1.org" RESOURCE_API=https://perseus-demo-energy.ib1.org python -W ignore  client.py
```

## FAPI Flow

![FAPI Flow diagram](docs/fapi-authlete-flow.png)
