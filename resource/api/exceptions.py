class ConfigurationError(Exception):
    """
    Base class for configuration errors
    """


class KeyNotFoundError(ConfigurationError):
    pass


class CertificateNotFoundError(ConfigurationError):
    pass


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
