class TaxaException(Exception):
    pass

class MissingKey(TaxaException):
    pass

class InvalidKey(TaxaException):
    pass

class InvalidRequest(TaxaException):
    pass

class TaxaClientException(TaxaException):
    pass

class AttestationException(TaxaException):
    pass

class InvalidAttestationStatus(AttestationException):
    pass

class UnknownAttestationException(AttestationException):
    pass

class TserviceError(TaxaException):
    pass

class SessionLimitsExceeded(TserviceError):
    pass

class WebUIError(TaxaException):
    pass
