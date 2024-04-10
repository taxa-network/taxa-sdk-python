import binascii, json

def hex_to_b64(h):
    """
    From hex to base64 string
    """
    return binascii.b2a_base64(binascii.a2b_hex(h))[:-1].decode()
    
def swap8(b):
    """
    From bytes to hex swapped every 8 bits
    """
    val = binascii.b2a_hex(b).decode()
    if len(val) % 2:
        raise Exception("Can't swap odd length")
    
    swapped = []
    for i in range(len(val), 0, -2):
        swapped.append(val[i - 2] + val[i - 1])

    return ''.join(swapped)

class KeyPairGenerator(object):
    implementations = ['cryptography', 'ecdsa', 'cryptodome']
    
    def __init__(self, lib):
        if lib not in self.implementations:
            raise Exception(
                "Unknown crypto library. Must be one of:" + ''.join(self.implementations)
            )
        self.lib = lib
    
    def make_ecdsa_keypair(self):
        """
        Fully working. Both pubkey and privkey are in correct format and
        it has been tested using the taxa server.
        `pip install ecdsa`
        """
        from ecdsa import SigningKey, NIST256p
        sk = SigningKey.generate(curve=NIST256p)
        return sk.to_string(), sk.verifying_key.to_string()
        
    def make_cryptography_keypair(self):
        """
        Not Working. Pubkey export format is correct, but priv key is not.
        `pip install cryptography`
        """
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        
        private_key = ec.generate_private_key(ec.SECP256R1())
        priv = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        return priv, pub
        
    def make_cryptodome_keypair(self):
        """
        Not Working. Pubkey export format is correct, but priv key is not.
        `pip install cryptodome`
        """
        from Crypto.PublicKey import ECC
        key = ECC.generate(curve='P-256')
        return key.export_key(format='OpenSSH'), key.public_key().export_key(format='SEC1')
        
    def make_keypair(self):
        return getattr(self, "make_%s_keypair" % self.lib)()
    
def make_taxa_identity(priv, cert):
    cert = hex_to_b64(swap8(cert[:32]) + swap8(cert[32:]))
    priv = hex_to_b64(swap8(priv))
    return {
        "client_key": priv, "client_cert": cert, "master_key": {}, "version": 1
    }
    
def make_keypair(lib="ecdsa"):
    priv, cert = KeyPairGenerator(lib).make_keypair()
    return make_taxa_identity(priv, cert)
    
    
def _cert_from_priv(b64_priv):
    """
    Generate pubkey from private key. Used in testing.
    """
    swapped_priv = binascii.a2b_hex(swap8(binascii.a2b_base64(b64_priv)))
    sk = SigningKey.from_string(swapped_priv, curve=NIST256p)
    pub = sk.verifying_key.to_string()
    return hex_to_b64(swap8(pub[:32]) + swap8(pub[32:]))
    
    
if __name__ == '__main__':
    print(make_keypair())
