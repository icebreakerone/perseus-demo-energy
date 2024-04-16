"""
A command line script to demonstrate the FAPI flow
"""

import os
import requests
import jwt
import pkce
import time
import secrets
from authentication.api import conf

AUTHENTICATION_API = os.environ.get("AUTHENTICATION_API", "https://0.0.0.0:8000")
RESOURCE_API = os.environ.get("RESOURCE_API", "https://0.0.0.0:8010")

ROOT_PATH = os.path.dirname(os.path.abspath(__file__))
CLIENT_CERTIFICATE = f"{ROOT_PATH}/certs/client-cert.pem"
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


def pushed_authorization_request():
    code_verifier, code_challenge = pkce.generate_pkce_pair()
    print(len(code_verifier), len(code_challenge))
    print(code_verifier, code_challenge)
    response = requests.post(
        f"{AUTHENTICATION_API}/api/v1/par",
        data={
            "response_type": "code",
            "client_id": f"{conf.CLIENT_ID}",
            "redirect_uri": "https://mobile.example.com/cb",
            "state": generate_state(),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "scope": "profile email offline_access",
        },
        verify=False,
        cert=(CLIENT_CERTIFICATE, CLIENT_PRIVATE_KEY),
    )
    return code_verifier, response.json()


def initiate_authorization(request_uri: str):
    """
    /as/authorise?request_uri=urn:ietf:params:oauth:request_uri:UymBrux4ZEMrBRKx9UyKyIm98zpX1cHmAPGAGNofmm4
    """
    response = requests.post(
        f"{AUTHENTICATION_API}/api/v1/authorize",
        json={
            "request_uri": request_uri,
            "client_id": f"{conf.CLIENT_ID}",
        },
        verify=False,
    )
    return response.json()


def get_user_token():
    response = requests.post(
        f"{AUTHENTICATION_API}/api/v1/authenticate/token",
        data={"username": "platform_user", "password": "perseus"},
        verify=False,
    )
    return response.json()


def authentication_issue_request(token: str, ticket: str):
    response = requests.post(
        f"{AUTHENTICATION_API}/api/v1/authorize/issue",
        json={"ticket": ticket},
        headers={"Authorization": "Bearer " + token},
        verify=False,
    )
    return response.json()


def give_consent(token: str):
    response = requests.post(
        f"{AUTHENTICATION_API}/api/v1/authenticate/consent",
        json={"scopes": ["account"]},
        headers={"Authorization": "Bearer " + token},
        verify=False,
    )
    return response.json()


def get_fapi_token(
    auth_code: str,
):
    session = get_session()
    response = session.post(
        f"{AUTHENTICATION_API}/api/v1/authorize/token",
        json={
            "client_id": f"{conf.CLIENT_ID}",
            "parameters": f"grant_type=authorization_code&redirect_uri=https://mobile.example.com/cb&code={auth_code}",
        },
        verify=False,
    )
    if not response.status_code == 200:
        raise Exception(response.text)
    return response.json()


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
    jwks_url = conf.FAPI_API + "/.well-known/jwks.json"
    jwks_client = jwt.PyJWKClient(jwks_url)
    header = jwt.get_unverified_header(token)
    key = jwks_client.get_signing_key(header["kid"]).key
    decoded = jwt.decode(token, key, [header["alg"]], audience=f"{conf.CLIENT_ID}")
    # Example of tests to apply
    if decoded["aud"] != conf.CLIENT_ID:
        raise ValueError("Invalid audience")
    if decoded["iss"] != conf.FAPI_API:
        raise ValueError("Invalid issuer")
    if decoded["exp"] < int(time.time()):
        raise ValueError("Token expired")
    if decoded["iat"] > int(time.time()):
        raise ValueError("Token issued in the future")

    return decoded


if __name__ == "__main__":
    # Initiate flow with PAR

    # Generate PKCE code verifier and challenge

    code_verifier, par_response = pushed_authorization_request()
    print("Code verifier:", code_verifier)
    # print(par_response)
    session = get_session()
    response = session.get(
        f"{AUTHENTICATION_API}/api/v1/authorize",
        params={
            "client_id": f"{conf.CLIENT_ID}",
            "request_uri": par_response["request_uri"],
        },
        verify=False,
        allow_redirects=False,
        cert=(CLIENT_CERTIFICATE, CLIENT_PRIVATE_KEY),
    )
    if response.status_code == 302:
        print(response.headers["location"])
    else:
        print(response.status_code, response.text)
    print(
        introspect_token(
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOltdLCJjbGllbnRfaWQiOiJmNjc5MTZjZS1kZTMzLTRlMmYtYThlMy1jYmQ1ZjY0NTljMzAiLCJleHAiOjE3MTI4NDY2NTYsImV4dCI6e30sImlhdCI6MTcxMjg0MzA1NSwiaXNzIjoiaHR0cHM6Ly92aWdvcm91cy1oZXlyb3Zza3ktMXRydnYwaWt4OS5wcm9qZWN0cy5vcnlhcGlzLmNvbSIsImp0aSI6IjkxYWMwZjRkLWJlZGEtNDE0Yy1hYjMxLTIzNDA1NmQ4YmRlNyIsIm5iZiI6MTcxMjg0MzA1NSwic2NwIjpbInByb2ZpbGUiLCJlbWFpbCIsIm9mZmxpbmVfYWNjZXNzIl0sInN1YiI6ImQ2ZmQ2ZTFjLWExMGUtNDBkOC1hYTJiLTk2MDZmM2QzNGQzYyIsImNuZiI6eyJ4NXQjUzI1NiI6Ims2Sm9jX1RiUkltX3ZJUXlyV2NNVElWel9RWm1SMEpSZUdBU1dSY0xkblEifX0.hOFJCiR0QVIIOJrfSU6cUevCy953Qg2vsRBwBKBvYbLiCCGkelIIFwObAUtdREaZktVoVAMFKC2X7yrER-PXSA"
        )
    )
