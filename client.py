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
import ssl


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


def pushed_authorization_request() -> tuple[str, dict]:
    code_verifier, code_challenge = pkce.generate_pkce_pair()
    response = requests.post(
        f"{AUTHENTICATION_API}/api/v1/par",
        data={
            "response_type": "code",
            "client_id": f"{conf.CLIENT_ID}",
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
    ssl._create_default_https_context = ssl._create_unverified_context

    jwks_url = conf.FAPI_API + "/.well-known/jwks.json"
    print(jwks_url)
    jwks_client = jwt.PyJWKClient(jwks_url)
    header = jwt.get_unverified_header(token)
    key = jwks_client.get_signing_key(header["kid"]).key
    decoded = jwt.decode(token, key, [header["alg"]], audience=f"{conf.CLIENT_ID}")
    print(decoded, conf.FAPI_API)
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
    # The following two tests will use the values returned after login and consent has been given
    print(
        introspect_token(
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOltdLCJjbGllbnRfaWQiOiJmNjc5MTZjZS1kZTMzLTRlMmYtYThlMy1jYmQ1ZjY0NTljMzAiLCJleHAiOjE3MTMyODU5MjUsImV4dCI6e30sImlhdCI6MTcxMzI4MjMyNSwiaXNzIjoiaHR0cHM6Ly92aWdvcm91cy1oZXlyb3Zza3ktMXRydnYwaWt4OS5wcm9qZWN0cy5vcnlhcGlzLmNvbSIsImp0aSI6ImNjYTQ5N2Y1LWYzYjAtNGM4MS1iODczLTdmOTdhNzRjZmNkYSIsIm5iZiI6MTcxMzI4MjMyNSwic2NwIjpbInByb2ZpbGUiLCJvZmZsaW5lX2FjY2VzcyJdLCJzdWIiOiJkNmZkNmUxYy1hMTBlLTQwZDgtYWEyYi05NjA2ZjNkMzRkM2MiLCJjbmYiOnsieDV0I1MyNTYiOiJrNkpvY19UYlJJbV92SVF5cldjTVRJVnpfUVptUjBKUmVHQVNXUmNMZG5RIn19.SxM9YvqE-vvXwemHNbLHNey7xbyLGsGu4T6bSmmhXNP2-nk8GMcmoHCLXhgYhQFJ3HcuLx7P9kQCqEUrY68xGQ"
        )
    )
    # print(
    #     client_side_decoding(
    #         "eyJhbGciOiJFUzI1NiIsImtpZCI6IjEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL3BlcnNldXMtZGVtby1lbmVyZ3kuaWIxLm9yZyIsInN1YiI6ImQ2ZmQ2ZTFjLWExMGUtNDBkOC1hYTJiLTk2MDZmM2QzNGQzYyIsImF1ZCI6ImY2NzkxNmNlLWRlMzMtNGUyZi1hOGUzLWNiZDVmNjQ1OWMzMCIsImV4cCI6MTcxMzI3OTgxMiwiaWF0IjoxNzEzMjc2MjEyLCJraWQiOjF9.SHpel4gQyrIS6RNM4VTZgsepgR-g-g5zQWeLwBVUzapeusDU2tsfT4yCczN6XMNYq9xCuL2WmIVEWKJBonp2Gw"
    #     )
    # )
