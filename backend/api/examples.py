from pydantic.config import JsonDict
from . import conf


CLIENT_ID = "21653835348762"
CLIENT_SECRET = "uE4NgqeIpuSV_XejQ7Ds3jsgA1yXhjR1MXJ1LbPuyls"

CLIENT_CERTIFICATE = "-----BEGIN%20CERTIFICATE-----%0AMIIDkzCCAnugAwIBAgIUerCGLrDY6aCYaB6nj9HivLJQtCAwDQYJKoZIhvcNAQEL%0ABQAwVzELMAkGA1UEBhMCR0IxDzANBgNVBAgMBkxvbmRvbjETMBEGA1UECgwKUGVy%0Ac2V1cyBDQTEiMCAGA1UEAwwZcGVyc2V1cy1kZW1vLWZhcGkuaWIxLm9yZzAeFw0y%0ANDAxMzAxNTA2NDRaFw0yNTAxMjkxNTA2NDRaMGwxCzAJBgNVBAYTAkdCMQ8wDQYD%0AVQQIDAZMb25kb24xITAfBgNVBAoMGFBlcnNldXMgRGVtbyBBY2NvdW50YW5jeTEp%0AMCcGA1UEAwwgcGVyc2V1cy1kZW1vLWFjY291bnRhbmN5LmliMS5vcmcwggEiMA0G%0ACSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC06LPNmROgBhDrfpUnfYaoqMENiqcy%0ArbqMGGWiRtRQO87ngL96iCMi30kPQjg4kD8PK49522ZZJ%2BVTqErtD6reS5y6mWkB%0AydsoWRKTi7UyHdyyK9D%2FHc%2FxK1JtFwlAZd4pMaN6KWJLEEfvmZxhOI5pfzKwi6Jj%0A%2BOfedpVJSAeXkI6CYY6qq33KRI4KQau5E7PbzbcNYICvLj1Vhs2bUz8a0tOJG5r8%0A06MCr%2FtteTYMjbb6x3yVlSL3b3LOtj4n8RCYyLlQ3S4ni1MSyHdnqngUGGyrnSVI%0AJF3lR9xJ6AK96RNgiRSzjCWOjOFZjnpuFlGa%2FXxn7buIrDehuKlmVDm3AgMBAAGj%0AQjBAMB0GA1UdDgQWBBRgUt%2BadzZuWnp9bEQLx6qhSm0T%2BTAfBgNVHSMEGDAWgBQP%0Ad2ICahMnEqfEp%2FLCaoBcGQufojANBgkqhkiG9w0BAQsFAAOCAQEArGVkNNfH9Zct%0Ak68YUrky3jPc3L714CjsW3l7yCWCqmkuB6VWIggNqltdKQDzdXDIwFLmN%2Fi7D57K%0AFqDaQboKUumeF3vsIi4LYlRqwGTuN7uGTghcqrpPozM7m%2BYTdPObY%2F8FtL6MqmqJ%0Adv61MYERRl3iLuR6UIbBaQr4YvgThe9WGotqknFOyxrD1yuunlYutOQpF2tXR8hk%0AES5XhvdLQfiuGStM4MPB0%2FWlMwc7mVge5aOVOixJeB0yGNmSSJWeEMQB0ETW3BbF%0AySdR2NroAWqouPWaJMZIpjxldeeTOBmc8k6%2BDLBvRIFcDUgpuLfaoAFTZKtkWbao%0A2NHw6nQAMQ%3D%3D%0A-----END%20CERTIFICATE-----%0A"
CLIENT_PUSHED_AUTHORIZATION_REQUEST: JsonDict = {
    "response_type": "code",
    "client_id": f"{conf.CLIENT_ID}",
    "redirect_uri": "https://mobile.example.com/cb",
    "code_challenge": "W78hCS0q72DfIHa...kgZkEJuAFaT4",
    "code_challenge_method": "S256",
}

PUSHED_AUTHORIZATION_REQUEST: JsonDict = {
    "parameters": f"response_type=code&client_id={conf.CLIENT_ID}&redirect_uri=https%3A%2F%2Fmobile.example.com%2Fcb&code_challenge=W78hCS0q72DfIHa...kgZkEJuAFaT4&code_challenge_method=S256",
    "client_id": CLIENT_ID,
    "client_certificate": CLIENT_CERTIFICATE,
}


PUSHED_AUTHORIZATION_RESPONSE: JsonDict = {
    "expires_in": 600,
    "request_uri": "urn:ietf:params:oauth:request_uri:UymBrux4ZEMrBRKx9UyKyIm98zpX1cHmAPGAGNofmm4",
}

AUTHORIZATION_REQUEST: JsonDict = {
    "client_id": conf.CLIENT_ID,
    "request_uri": "urn:ietf:params:oauth:request_uri:UymBrux4ZEMrBRKx9UyKyIm98zpX1cHmAPGAGNofmm4",
}

AUTHORIZATION_RESPONSE: JsonDict = {
    "message": "Authorisation code request issued",
    "ticket": "b0JGD-ZkT8ElBGw2ck-T-t87Z033jXvhqC2omPT1bQ4",
}

ISSUE_RESPONSE: JsonDict = {
    "type": "authorizationIssueResponse",
    "result_code": "A040001",
    "result_message": "[A040001] The authorization request was processed successfully.",
    "access_token_duration": 0,
    "access_token_expires_at": 0,
    "action": "LOCATION",
    "authorization_code": "DxiKC0cOc_46nzVjgr41RWBQtMDrAvc0BUbMJ_v7I70",
    "id_token": "eyJraWQiOiIxIiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJ0ZXN0dXNlcjAxIiwiYXVkIjpbIjU5MTIwNTk4NzgxNjQ5MCJdLCJjX2hhc2giOiJqR2kyOElvYm5HcjNNQ3Y0UUVQRTNnIiwiaXNzIjoiaHR0cHM6Ly9hcy5leGFtcGxlLmNvbSIsImV4cCI6MTU3MjQxMjY4MiwiaWF0IjoxNTcyMzI2MjgyLCJub25jZSI6Im4tMFM2X1d6QTJNaiJ9.1PFmc0gAsBWtLBriq3z9a4Tsi_ioEYlOqOYbicGEXWIS1WGX5ffGOyZNSzVBMamZbltZmSys0jlYmmYYLqgGsg",
    "response_content": (
        "https://client.example.org/cb/example.com#"
        "code=DxiKC0cOc_46nzVjgr41RWBQtMDrAvc0BUbMJ_v7I70&"
        "id_token=eyJraWQiOiIxIiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJ0ZXN0dXNlcjAxIiwiYXVkIjpbIjU5MTIwN"
        "Tk4NzgxNjQ5MCJdLCJjX2hhc2giOiJqR2kyOElvYm5HcjNNQ3Y0UUVQRTNnIiwiaXNzIjoiaHR0cHM6L"
        "y9hcy5leGFtcGxlLmNvbSIsImV4cCI6MTU3MjQxMjY4MiwiaWF0IjoxNTcyMzI2MjgyLCJub25jZSI6I"
        "m4tMFM2X1d6QTJNaiJ9.1PFmc0gAsBWtLBriq3z9a4Tsi_ioEYlOqOYbicGEXWIS1WGX5ffGOyZNSzVB"
        "MamZbltZmSys0jlYmmYYLqgGsg"
    ),
}


TOKEN_REQUEST: JsonDict = {
    "client_id": f"{CLIENT_ID}",
    "parameters": "grant_type=authorization_code&redirect_uri=https://client.example.org/cb/example.com&code=DxiKC0cOc_46nzVjgr41RWBQtMDrAvc0BUbMJ_v7I70",
    "client_certificate": CLIENT_CERTIFICATE,
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
