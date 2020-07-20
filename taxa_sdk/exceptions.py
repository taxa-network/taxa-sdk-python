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
