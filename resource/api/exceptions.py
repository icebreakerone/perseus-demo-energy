class FrameworkAuthError(Exception):
    """Base class for exceptions in this module."""


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
