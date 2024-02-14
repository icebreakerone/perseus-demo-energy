import os

import requests
import jwt

from api import conf

AUTHENTICATION_API = os.environ.get("AUTHENTICATION_API", "https://0.0.0.0:443")
ROOT_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_CERTIFICATE = f"{ROOT_PATH}/certs/client-cert.pem"
CLIENT_PRIVATE_KEY = f"{ROOT_PATH}/certs/client-key.pem"


def pushed_authorization_request():
    session = requests.Session()
    session.cert = (CLIENT_CERTIFICATE, CLIENT_PRIVATE_KEY)
    session.verify = False
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
    session = requests.Session()
    session.cert = (CLIENT_CERTIFICATE, CLIENT_PRIVATE_KEY)
    session.verify = False
    """
    """
    response = session.post(
        f"{AUTHENTICATION_API}/api/v1/authorize/token",
        json={
            "client_id": f"{conf.CLIENT_ID}",
            "parameters": f"grant_type=authorization_code&redirect_uri=https://mobile.example.com/cb&code={auth_code}",
        },
        verify=False,
    )
    return response.json()


if __name__ == "__main__":
    data = pushed_authorization_request()
    print(data)
    ticket = initiate_authorization(data["request_uri"])["ticket"]
    token = get_user_token()["access_token"]
    consent = give_consent(token)
    print(consent)
    auth_code = authentication_issue_request(token, ticket)["authorization_code"]
    print(auth_code)
    ## Now we need to exchange the auth code for an access token
    result = get_fapi_token(auth_code)
    # print(result)
    fapi_token = result["access_token"]
    print(fapi_token)
    # Test decoding the token using jwks
    # jwks_url = conf.FAPI_API + "/.well-known/jwks.json"
    # # print(jwks_url)
    # jwks_client = jwt.PyJWKClient(jwks_url)
    # header = jwt.get_unverified_header(fapi_token)
    # print(header)

    # key = jwks_client.get_signing_key(header["kid"]).key
    # decoded = jwt.decode(fapi_token, key, [header["alg"]], audience=f"{conf.CLIENT_ID}")

    # print(decoded)
    # And finally! When we acces the resource server, it can introspect the FAPI token
    # This request would come from the resource server
    session = requests.Session()
    session.cert = (CLIENT_CERTIFICATE, CLIENT_PRIVATE_KEY)
    session.verify = False
    introspection_response = session.post(
        f"{AUTHENTICATION_API}/api/v1/authorize/introspect",
        json={"token": fapi_token},
        verify=False,
    )
    print(introspection_response.json())
