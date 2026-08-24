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
