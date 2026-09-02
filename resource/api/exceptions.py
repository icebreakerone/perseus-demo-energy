class ApiError(Exception):
    """
    An error to return to the caller, with an RFC 6750 error code.

    The IB1 ops guidelines say a Data Provider should answer a failed check
    with an RFC 6750 section 6.2 error, which is a WWW-Authenticate header.
    `header` renders that; the same fields are also returned as JSON so the
    body is usable without parsing the header.
    """

    def __init__(
        self,
        status_code: int,
        error: str,
        error_description: str | None = None,
        include_code_in_header: bool = True,
    ) -> None:
        self.status_code = status_code
        self.error = error
        self.error_description = error_description
        self.include_code_in_header = include_code_in_header
        super().__init__(f"{error}: {error_description or ''}".strip())

    def body(self) -> dict:
        payload = {"error": self.error}
        if self.error_description:
            payload["error_description"] = self.error_description
        return payload

    def header(self) -> str | None:
        """
        The WWW-Authenticate value, for authentication failures only.

        RFC 6750 section 3 says not to include an error code when the request
        carried no credentials at all, so that case sends a bare challenge.
        """
        if self.status_code != 401:
            return None
        if not self.include_code_in_header:
            return "Bearer"
        parts = [f'error="{self.error}"']
        if self.error_description:
            quoted = self.error_description.replace("\\", "").replace('"', "")
            parts.append(f'error_description="{quoted}"')
        return "Bearer " + ", ".join(parts)


class ConfigurationError(Exception):
    """
    Base class for configuration errors
    """


class KeyNotFoundError(ConfigurationError):
    pass


class CertificateNotFoundError(ConfigurationError):
    pass


class LicenseScopeError(Exception):
    """
    A token carried no single Registry License URL in its granted scopes.

    Per the IB1 OAuth profile the scope is a Registry License URL. A token
    without one means the authorization server is misconfigured.
    """


class FrameworkAuthError(Exception):
    """Base class for access token exceptions"""


class AccessTokenValidatorError(FrameworkAuthError):
    """
    Base class for errors related to the presented token
    """


class AccessTokenInactiveError(AccessTokenValidatorError):
    pass


class AccessTokenTimeError(AccessTokenValidatorError):
    pass


class AccessTokenAudienceError(AccessTokenValidatorError):
    pass


class AccessTokenDecodingError(AccessTokenValidatorError):
    pass
