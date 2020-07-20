import base64
import base58
import hashlib
import binascii

def sha256_multihash(payload, encoding="base58"):
    if not isinstance(payload, bytes):
        payload = bytes(payload, 'UTF-8')
    hash = b'\x12 ' + hashlib.sha256(payload).digest()
    encoder = get_encoder(encoding)
    return encoder(hash).decode()

def get_encoder(encoding):
    if encoding == "base64":
        return base64.b64encode
    elif encoding == "base58":
        return base58.b58encode
    elif encoding == 'hex':
        return binascii.hexlify
    else:
        raise Exception("Unknown encoding")
