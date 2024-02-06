from pydantic.config import JsonDict

CLIENT_ID = "21653835348762"
CLIENT_SECRET = "uE4NgqeIpuSV_XejQ7Ds3jsgA1yXhjR1MXJ1LbPuyls"

CLIENT_CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMIIDPDCCAiQCCQDWNMOIuzwDfzANBgkqhkiG9w0BAQUFADBgMQswCQYDVQQGEwJK\nUDEOMAwGA1UECAwFVG9reW8xEzARBgNVBAcMCkNoaXlvZGEta3UxDzANBgNVBAoM\nBkNsaWVudDEbMBkGA1UEAwwSY2xpZW50LmV4YW1wbGUub3JnMB4XDTE5MTAyODA3\nMjczMFoXDTIwMTAyNzA3MjczMFowYDELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBVRv\na3lvMRMwEQYDVQQHDApDaGl5b2RhLWt1MQ8wDQYDVQQKDAZDbGllbnQxGzAZBgNV\nBAMMEmNsaWVudC5leGFtcGxlLm9yZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\nAQoCggEBAK2Oyc+BV4N5pYcp47opUwsb2NaJq4X+d5Itq8whpFlZ9uCCHzF5TWSF\nXrpYscOp95veGPF42eT1grfxYyvjFotE76caHhBLCkIbBh6Vf222IGMwwBbSZfO9\nJ3eURtEADBvsZ117HkPVdjYqvt3Pr4RxdR12zG1TcBAoTLGchyr8nBqRADFhUTCL\nmsYaz1ADiQ/xbJN7VUNQpKhzRWHCdYS03HpbGjYCtAbl9dJnH2EepNF0emGiSPFq\ndf6taToyCr7oZjM7ufmKPjiiEDbeSYTf6kbPNmmjtoPNNLeejHjP9p0IYx7l0Gkj\nmx4kSMLp4vSDftrFgGfcxzaMmKBsosMCAwEAATANBgkqhkiG9w0BAQUFAAOCAQEA\nqzdDYbntFLPBlbwAQlpwIjvmvwzvkQt6qgZ9Y0oMAf7pxq3i9q7W1bDol0UF4pIM\nz3urEJCHO8w18JRlfOnOENkcLLLntrjOUXuNkaCDLrnv8pnp0yeTQHkSpsyMtJi9\nR6r6JT9V57EJ/pWQBgKlN6qMiBkIvX7U2hEMmhZ00h/E5xMmiKbySBiJV9fBzDRf\nmAy1p9YEgLsEMLnGjKHTok+hd0BLvcmXVejdUsKCg84F0zqtXEDXLCiKcpXCeeWv\nlmmXxC5PH/GEMkSPiGSR7+b1i0sSotsq+M3hbdwabpJ6nQLLbKkFSGcsQ87yL+gr\nSo6zun26vAUJTu1o9CIjxw==\n-----END CERTIFICATE-----\n"
CLIENT_PUSHED_AUTHORIZATION_REQUEST: JsonDict = {
    "response_type": "code",
    "client_id": "3280859750204",
    "redirect_uri": "https://mobile.example.com/cb",
    "code_challenge": "W78hCS0q72DfIHa...kgZkEJuAFaT4",
    "code_challenge_method": "S256",
}

PUSHED_AUTHORIZATION_REQUEST: JsonDict = {
    "parameters": "response_type=code&client_id=3280859750204&redirect_uri=https%3A%2F%2Fmobile.example.com%2Fcb&code_challenge=W78hCS0q72DfIHa...kgZkEJuAFaT4&code_challenge_method=S256",
    "clientId": CLIENT_ID,
    "clientCertificate": CLIENT_CERTIFICATE,
}


PUSHED_AUTHORIZATION_RESPONSE: JsonDict = {
    "expires_in": 600,
    "request_uri": "urn:ietf:params:oauth:request_uri:UymBrux4ZEMrBRKx9UyKyIm98zpX1cHmAPGAGNofmm4",
}

AUTHORIZATION_REQUEST: JsonDict = {
    "client_id": 3280859750204,
    "request_uri": "urn:ietf:params:oauth:request_uri:UymBrux4ZEMrBRKx9UyKyIm98zpX1cHmAPGAGNofmm4",
}

AUTHORIZATION_RESPONSE: JsonDict = {
    "message": "Authorisation code request issued",
    "ticket": "b0JGD-ZkT8ElBGw2ck-T-t87Z033jXvhqC2omPT1bQ4",
}

ISSUE_RESPONSE: JsonDict = {
    "type": "authorizationIssueResponse",
    "resultCode": "A040001",
    "resultMessage": "[A040001] The authorization request was processed successfully.",
    "accessTokenDuration": 0,
    "accessTokenExpiresAt": 0,
    "action": "LOCATION",
    "authorizationCode": "DxiKC0cOc_46nzVjgr41RWBQtMDrAvc0BUbMJ_v7I70",
    "idToken": "eyJraWQiOiIxIiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJ0ZXN0dXNlcjAxIiwiYXVkIjpbIjU5MTIwNTk4NzgxNjQ5MCJdLCJjX2hhc2giOiJqR2kyOElvYm5HcjNNQ3Y0UUVQRTNnIiwiaXNzIjoiaHR0cHM6Ly9hcy5leGFtcGxlLmNvbSIsImV4cCI6MTU3MjQxMjY4MiwiaWF0IjoxNTcyMzI2MjgyLCJub25jZSI6Im4tMFM2X1d6QTJNaiJ9.1PFmc0gAsBWtLBriq3z9a4Tsi_ioEYlOqOYbicGEXWIS1WGX5ffGOyZNSzVBMamZbltZmSys0jlYmmYYLqgGsg",
    "responseContent": (
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
