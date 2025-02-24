from pydantic.config import JsonDict


ORY_CLIENT_ID = "abc123-addefg-4e2f-a8e3-cbd5f6459c30"

CLIENT_CERTIFICATE = "-----BEGIN%20CERTIFICATE-----%0AMIIDkzCCAnugAwIBAgIUerCGLrDY6aCYaB6nj9HivLJQtCAwDQYJKoZIhvcNAQEL%0ABQAwVzELMAkGA1UEBhMCR0IxDzANBgNVBAgMBkxvbmRvbjETMBEGA1UECgwKUGVy%0Ac2V1cyBDQTEiMCAGA1UEAwwZcGVyc2V1cy1kZW1vLWZhcGkuaWIxLm9yZzAeFw0y%0ANDAxMzAxNTA2NDRaFw0yNTAxMjkxNTA2NDRaMGwxCzAJBgNVBAYTAkdCMQ8wDQYD%0AVQQIDAZMb25kb24xITAfBgNVBAoMGFBlcnNldXMgRGVtbyBBY2NvdW50YW5jeTEp%0AMCcGA1UEAwwgcGVyc2V1cy1kZW1vLWFjY291bnRhbmN5LmliMS5vcmcwggEiMA0G%0ACSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC06LPNmROgBhDrfpUnfYaoqMENiqcy%0ArbqMGGWiRtRQO87ngL96iCMi30kPQjg4kD8PK49522ZZJ%2BVTqErtD6reS5y6mWkB%0AydsoWRKTi7UyHdyyK9D%2FHc%2FxK1JtFwlAZd4pMaN6KWJLEEfvmZxhOI5pfzKwi6Jj%0A%2BOfedpVJSAeXkI6CYY6qq33KRI4KQau5E7PbzbcNYICvLj1Vhs2bUz8a0tOJG5r8%0A06MCr%2FtteTYMjbb6x3yVlSL3b3LOtj4n8RCYyLlQ3S4ni1MSyHdnqngUGGyrnSVI%0AJF3lR9xJ6AK96RNgiRSzjCWOjOFZjnpuFlGa%2FXxn7buIrDehuKlmVDm3AgMBAAGj%0AQjBAMB0GA1UdDgQWBBRgUt%2BadzZuWnp9bEQLx6qhSm0T%2BTAfBgNVHSMEGDAWgBQP%0Ad2ICahMnEqfEp%2FLCaoBcGQufojANBgkqhkiG9w0BAQsFAAOCAQEArGVkNNfH9Zct%0Ak68YUrky3jPc3L714CjsW3l7yCWCqmkuB6VWIggNqltdKQDzdXDIwFLmN%2Fi7D57K%0AFqDaQboKUumeF3vsIi4LYlRqwGTuN7uGTghcqrpPozM7m%2BYTdPObY%2F8FtL6MqmqJ%0Adv61MYERRl3iLuR6UIbBaQr4YvgThe9WGotqknFOyxrD1yuunlYutOQpF2tXR8hk%0AES5XhvdLQfiuGStM4MPB0%2FWlMwc7mVge5aOVOixJeB0yGNmSSJWeEMQB0ETW3BbF%0AySdR2NroAWqouPWaJMZIpjxldeeTOBmc8k6%2BDLBvRIFcDUgpuLfaoAFTZKtkWbao%0A2NHw6nQAMQ%3D%3D%0A-----END%20CERTIFICATE-----%0A"
CLIENT_PUSHED_AUTHORIZATION_REQUEST: JsonDict = {
    "response_type": "code",
    "client_id": ORY_CLIENT_ID,
    "redirect_uri": "https://mobile.example.com/cb",
    "code_challenge": "W78hCS0q72DfIHa...kgZkEJuAFaT4",
    "code_challenge_method": "S256",
}

PUSHED_AUTHORIZATION_REQUEST: JsonDict = {
    "parameters": f"response_type=code&client_id={ORY_CLIENT_ID}&redirect_uri=https%3A%2F%2Fmobile.example.com%2Fcb&code_challenge=W78hCS0q72DfIHa...kgZkEJuAFaT4&code_challenge_method=S256",
    "client_id": ORY_CLIENT_ID,
    "client_certificate": CLIENT_CERTIFICATE,
}


PUSHED_AUTHORIZATION_RESPONSE: JsonDict = {
    "expires_in": 600,
    "request_uri": "urn:ietf:params:oauth:request_uri:UymBrux4ZEMrBRKx9UyKyIm98zpX1cHmAPGAGNofmm4",
}

AUTHORIZATION_REQUEST: JsonDict = {
    "client_id": ORY_CLIENT_ID,
    "request_uri": "urn:ietf:params:oauth:request_uri:UymBrux4ZEMrBRKx9UyKyIm98zpX1cHmAPGAGNofmm4",
}

AUTHORIZATION_RESPONSE: JsonDict = {
    "message": "Authorisation code request issued",
    "ticket": "b0JGD-ZkT8ElBGw2ck-T-t87Z033jXvhqC2omPT1bQ4",
}


TOKEN_REQUEST: JsonDict = {
    "client_id": ORY_CLIENT_ID,
    "parameters": "grant_type=authorization_code&redirect_uri=https://client.example.org/cb/example.com&code=DxiKC0cOc_46nzVjgr41RWBQtMDrAvc0BUbMJ_v7I70",
    "client_certificate": CLIENT_CERTIFICATE,
    "redirect_uri": "https://client.example.org/cb/",
    "code_verifier": "random_string",
    "code": "DxiKC0cOc_46nzVjgr41RWBQtMDrAvc0BUbMJ_v7I70",
}

TOKEN_RESPONSE: JsonDict = {
    "access_token": "SUtEVc3Tj3D3xOdysQtssQxe9egAhI4fimexNVMjRyU",
    "id_token": (
        "eyJraWQiOiIxIiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJ0ZXN0dXNlcjAxIiwiYXVkIjpbIjU5MTIwN"
        "Tk4NzgxNjQ5MCJdLCJpc3MiOiJodHRwczovL2FzLmV4YW1wbGUuY29tIiwiZXhwIjoxNTcyNDEyNzY5L"
        "CJpYXQiOjE1NzIzMjYzNjksIm5vbmNlIjoibi0wUzZfV3pBMk1qIn0.9EQojck-Cf2hnKAZWR164kr21"
        "o5lPKehvIHyViZgRg4CY_ZGmnyFooG4FCwlZxu-QOTtaDCffCsuCdz4GqknTA"
    ),
    "refresh_token": "tXZjYfoK35I-djg9V3n6s58zsrVqRIzTNMXKIS_wkj8",
}

INTROSPECTION_REQUEST: JsonDict = {
    "token": "SUtEVc3Tj3D3xOdysQtssQxe9egAhI4fimexNVMjRyU",
    "client_certificate": CLIENT_CERTIFICATE,
}
INTROSPECTION_FAILED_RESPONSE: JsonDict = {"active": False}
INTROSPECTION_RESPONSE = {
    "aud": [],
    "client_id": ORY_CLIENT_ID,
    "exp": 1713285925,
    "ext": {},
    "iat": 1713282325,
    "iss": "https://vigorous-heyrovsky-1trvv0ikx9.projects.oryapis.com",
    "jti": "cca497f5-f3b0-4c81-b873-7f97a74cfcda",
    "nbf": 1713282325,
    "scp": ["profile", "offline_access"],
    "sub": "d6fd6e1c-a10e-40d8-aa2b-9606f3d34d3c",
    "cnf": {"x5t#S256": "k6Joc_TbRIm_vIQyrWcMTIVz_QZmR0JReGASWRcLdnQ"},
    "active": True,
}
