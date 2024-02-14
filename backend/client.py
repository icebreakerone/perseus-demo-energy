"""
A command line script to demonstrate the FAPI flow
"""

import os
import time
import requests
import jwt

from api import conf

AUTHENTICATION_API = os.environ.get("AUTHENTICATION_API", "https://0.0.0.0:443")
ROOT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_CERTIFICATE = f"{ROOT_PATH}/certs/client-cert.pem"
CLIENT_PRIVATE_KEY = f"{ROOT_PATH}/certs/client-key.pem"


def get_session():
    session = requests.Session()
    session.cert = (CLIENT_CERTIFICATE, CLIENT_PRIVATE_KEY)
    session.verify = False
    return session


def pushed_authorization_request():
    session = get_session()
    response = session.post(
        f"{AUTHENTICATION_API}/api/v1/par/",
        json={
            "response_type": "code",
            "client_id": f"{conf.CLIENT_ID}",
            "redirect_uri": "https://mobile.example.com/cb",
            "code_challenge": "W78hCS0q72DfIHa...kgZkEJuAFaT4",
            "code_challenge_method": "S256",
        },
        verify=False,
    )
    return response.json()


def initiate_authorization(request_uri: str):
    """
    /as/authorise?request_uri=urn:ietf:params:oauth:request_uri:UymBrux4ZEMrBRKx9UyKyIm98zpX1cHmAPGAGNofmm4
    """
    response = requests.post(
        f"{AUTHENTICATION_API}/api/v1/authorize/",
        json={
            "request_uri": request_uri,
            "client_id": f"{conf.CLIENT_ID}",
        },
        verify=False,
    )
    # print()
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


def client_side_decoding():
    """
    Use the jwks to decode the token
    """
    jwks_url = conf.FAPI_API + "/.well-known/jwks.json"
    jwks_client = jwt.PyJWKClient(jwks_url)
    header = jwt.get_unverified_header(fapi_token)
    key = jwks_client.get_signing_key(header["kid"]).key
    decoded = jwt.decode(fapi_token, key, [header["alg"]], audience=f"{conf.CLIENT_ID}")
    return decoded


if __name__ == "__main__":
    # Initiate flow with PAR
    data = pushed_authorization_request()
    # Take note of the ticket
    ticket = initiate_authorization(data["request_uri"])["ticket"]
    # authenticate the user
    token = get_user_token()["access_token"]
    # Ask for user's consent
    consent = give_consent(token)
    # Now we have identified the user, we can use the ticket to request an authorization code
    auth_code = authentication_issue_request(token, ticket)["authorization_code"]
    # Now we need to exchange the auth code for an access token
    result = get_fapi_token(auth_code)
    fapi_token = result["access_token"]
    # The token can be used to access protected APIs
    # The resource server can introspect the token
    print(introspect_token(fapi_token))
