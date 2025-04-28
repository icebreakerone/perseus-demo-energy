class FrameworkAuthError(Exception):
    """Base class for auth exceptions in this module."""


class KeyNotFoundError(FrameworkAuthError):
    pass


class CertificateError(FrameworkAuthError):
    """
    Base class for errors related to the client certificate
    """


class CertificateMissingError(CertificateError):
    pass


class CertificateRoleError(CertificateError):
    pass


class CertificateRoleMissingError(CertificateRoleError):
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


class AccessTokenCertificateError(AccessTokenValidatorError):
    pass


class PermissionStorageError(Exception):
    pass
