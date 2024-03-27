# Perseus demo energy provider

Emulates authentication and resource api endpoints for the Perseus demo.

## Authentication API

The authentication app is in the [authentication](authentication) directory. It provides endpoints for authenticating and identifying users, and for handling and passing on requests from the client API to the FAPI API.

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

client.py will execute a series of requests to the API demonstrating the steps from initial PAR (pushed authorization request) to introspecting the token presented to the resource API. The steps are

- Create a push authorization request, and store the ticket value
- Authenticate the user
- Ask for user's consent
- With the users identity and the ticket, retrieve the authorization code
- Exchange the authorization code for an access token
- Introspect the access token
- Use the access token to access the resource API

```bash
python -W ignore  client.py
```

The `-W ignore` switch suppresses multiple warnings about the self-signed certificates.

By default the client will use the local docker environment and expects a local instance of the FAPI api to be running on localhost:8020. Testing against the deployed API can be achieved by setting the `AUTHENTICATION_API` and `RESOURCE_API` environment variables, and optionally the FAPI_API environment variable.

```bash
FAPI_API=https://perseus-demo-fapi.ib1.org AUTHENTICATION_API="https://perseus-demo-authentication.ib1.org" RESOURCE_API=https://perseus-demo-energy.ib1.org python -W ignore  client.py
```

A successful run will complete with outputting data from the resource API.

## FAPI Flow

![FAPI Flow diagram](docs/fapi-authlete-flow.png)
