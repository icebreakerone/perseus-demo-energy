class OAuthError(Exception):
    """
    An error to return to the caller in the RFC 6749 section 5.2 shape.

    `error` is a registered OAuth2 error code, `error_description` is safe to
    show the caller. Anything that is not safe to show belongs in the logs.
    """

    def __init__(
        self,
        status_code: int,
        error: str,
        error_description: str | None = None,
        error_hint: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.error = error
        self.error_description = error_description
        self.error_hint = error_hint
        super().__init__(f"{error}: {error_description or ''}".strip())

    def body(self) -> dict:
        payload = {"error": self.error}
        if self.error_description:
            payload["error_description"] = self.error_description
        if self.error_hint:
            payload["error_hint"] = self.error_hint
        return payload


class FrameworkAuthError(Exception):
    """Base class for auth exceptions in this module."""


class KeyNotFoundError(FrameworkAuthError):
    pass


class AccessTokenDecodingError(FrameworkAuthError):
    """
    Base class for errors related to the issuing of the token
    """


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


class PermissionStorageError(Exception):
    pass


class PermissionRevocationError(Exception):
    pass
