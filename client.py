"""
A command line script to demonstrate the FAPI flow
"""

import os
import requests
import jwt
import pkce
import time
import secrets

import click

from authentication.api import conf


AUTHENTICATION_API = os.environ.get("AUTHENTICATION_API", "https://0.0.0.0:8000")
RESOURCE_API = os.environ.get("RESOURCE_API", "https://0.0.0.0:8010")

ROOT_PATH = os.path.dirname(os.path.abspath(__file__))
CLIENT_CERTIFICATE = f"{ROOT_PATH}/certs/client-bundle.pem"
CLIENT_PRIVATE_KEY = f"{ROOT_PATH}/certs/client-key.pem"


def generate_state(length=32):
    """
    Generate a cryptographically random state parameter for OAuth 2.0.

    Parameters:
        length (int): Length of the state parameter (default is 32 bytes).

    Returns:
        str: The generated state parameter.
    """
    # Generate a random string using a secure random source
    state = secrets.token_urlsafe(length)
    # Return the first 'length' characters of the generated string
    return state[:length]


def get_session():
    session = requests.Session()
    session.cert = (CLIENT_CERTIFICATE, CLIENT_PRIVATE_KEY)
    session.verify = False
    return session


def pushed_authorization_request() -> tuple[str, dict]:
    code_verifier, code_challenge = pkce.generate_pkce_pair()
    response = requests.post(
        f"{AUTHENTICATION_API}/api/v1/par",
        data={
            "response_type": "code",
            "client_id": f"{conf.OAUTH_CLIENT_ID}",
            "redirect_uri": f"{conf.REDIRECT_URI}",
            "state": generate_state(),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "scope": "profile+offline_access",
        },
        verify=False,
        cert=(CLIENT_CERTIFICATE, CLIENT_PRIVATE_KEY),
    )
    return code_verifier, response.json()


def introspect_token(fapi_token: str):
    session = get_session()
    # session = requests.Session()
    introspection_response = session.post(
        f"{AUTHENTICATION_API}/api/v1/authorize/introspect",
        json={"token": fapi_token},
        verify=False,
    )
    return introspection_response.json()


def client_side_decoding(token: str):
    """
    Use the jwks to decode the token
    """
    # Workaround for self-signed certificates, insecure
    # ssl._create_default_https_context = ssl._create_unverified_context

    jwks_url = conf.ISSUER_URL + "/.well-known/jwks.json"
    print(jwks_url)
    jwks_client = jwt.PyJWKClient(jwks_url)
    header = jwt.get_unverified_header(token)
    key = jwks_client.get_signing_key(header["kid"]).key
    decoded = jwt.decode(
        token, key, [header["alg"]], audience=f"{conf.OAUTH_CLIENT_ID}"
    )
    print(decoded, conf.ISSUER_URL)
    # Example of tests to apply
    if decoded["aud"] != conf.OAUTH_CLIENT_ID:
        raise ValueError("Invalid audience")
    if decoded["iss"] != conf.ISSUER_URL:
        raise ValueError("Invalid issuer")
    if decoded["exp"] < int(time.time()):
        raise ValueError("Token expired")
    if decoded["iat"] > int(time.time()):
        raise ValueError("Token issued in the future")

    return decoded


@click.group()
def cli():
    pass


@click.option("--token", help="introspect token returned from authorisation flow")
@cli.command()
def introspect(token):
    print(introspect_token(token))


@click.option("--token", help="Decode ID token returned from authorisation flow")
@cli.command()
def id_token(token):
    print(client_side_decoding(token))


@click.option("--token", help="Authorisation token")
@cli.command()
def resource(token):
    result = requests.get(
        f"{RESOURCE_API}/api/v1/consumption",
        verify=False,
        headers={"Authorization": f"Bearer {token}"},
        cert=(CLIENT_CERTIFICATE, CLIENT_PRIVATE_KEY),
    )
    return result.json()


@cli.command()
def auth():
    code_verifier, par_response = pushed_authorization_request()
    print("Code verifier: ", code_verifier)
    session = get_session()
    response = session.get(
        f"{AUTHENTICATION_API}/api/v1/authorize",
        params={
            "client_id": f"{conf.OAUTH_CLIENT_ID}",
            "request_uri": par_response["request_uri"],
        },
        verify=False,
        allow_redirects=False,
        cert=(CLIENT_CERTIFICATE, CLIENT_PRIVATE_KEY),
    )
    if response.status_code == 302:
        print(response.headers["location"])
    else:
        print("Error:", response.status_code, response.text)


if __name__ == "__main__":
    cli()
