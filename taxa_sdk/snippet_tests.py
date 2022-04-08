from __future__ import print_function

import argparse
import sys
import unittest

from .taxa_request import TaxaRequest
from .tests import BaseServerTest

try:
    from dev_nodes import nodes
except ImportError:
    nodes = None

bin = b'R\x9d\x94r\x12\xa4\x1a\xec\xb4\x11\x90\xdcY\x9a\x96\xccReWimBsDWONrzoeO'
b64 = b"Up2UchKkGuy0EZDcWZqWzFJlV2ltQnNEV09OcnpvZU8="
hex = b'529d947212a41aecb41190dc599a96cc526557696d427344574f4e727a6f654f'

def make_snippets(module, snippet, pre_snippet=''):
    import_module = 'None'
    if module:
        import_module = "import %s" % module

    return ("""%s
@taxa.route("/test")
def test():
    %s # pre-snippet
    result = %s
    response.add(str(result))
""" % (import_module, pre_snippet, snippet),
    "%s; %s; local_value = %s" % (import_module, pre_snippet, snippet)
)

class BaseSnippetTest(object):
    def compare(self, value):
        return str(value)

    def test_snippets(self):
        request = TaxaRequest("snippet_test.json", verbose=False)
        if FORCEIP: request.ip = FORCEIP

        g = {'local_value': None}

        for snippet in self.snippets:
            pre_snippet = None
            if type(snippet) in (tuple, list):
                pre_snippet = snippet[0]
                snippet = snippet[1]

            remote, local = make_snippets(self.module, snippet, pre_snippet)

            response = request.send(function="test", code=remote)
            exec(local, g)

            print(snippet, ":", "remote->", response['decrypted_data'], "local->", self.compare(g['local_value']))
            self.assertEqual(
                self.compare(response['decrypted_data']),
                self.compare(g['local_value']),
                snippet
            )

class UnicodeTest(BaseSnippetTest, BaseServerTest):
    module = None
    snippets = [
        'str(u"u")'
    ]

class BytestoStrTest(BaseSnippetTest, BaseServerTest):
    module = None
    snippets = [
        'str(b"b")'
    ]

class AddUnicode(BaseSnippetTest, BaseServerTest):
    module = None
    snippets = [
        'u"u" + u"u"'
    ]

class MathTest(BaseSnippetTest, BaseServerTest):
    module = 'math'
    snippets = [
        "math.ceil(4.5)", "math.ceil(-5.01)", "math.fabs(-3.768)",
        "math.floor(4.5)", "math.floor(-5.01)", "math.exp(3)",
        "math.log(20.085536923187668)", "math.sqrt(81)", "math.pow(3, 3)",
        "math.cos(math.pi)"
    ]
    def compare(self, value):
        return "%.5f" % float(value)

class CMathTest(BaseSnippetTest, BaseServerTest):
    module = 'cmath'
    snippets = ['cmath.cosh(0)']


class MD5Test(BaseSnippetTest, BaseServerTest):
    module = 'md5'
    snippets = [
        ('m = md5.new(); m.update("Nobody inspects")', 'm.hexdigest()')
    ]

class PickleTest(BaseSnippetTest, BaseServerTest):
    module = "pickle"
    snippets = ["pickle.dumps({'test': 1})"]

class Sha256Test(BaseSnippetTest, BaseServerTest):
    module = "hashlib"
    snippets = [
        ('s = hashlib.sha256(); s.update(b"Nobody inspects")', 's.hexdigest() # sha256 of b"Nobody inspects"')
    ]

class HmacTest(BaseSnippetTest, BaseServerTest):
    module = 'hmac, hashlib'
    snippets = [
        ('h = hmac.new(b"ffff", digestmod=hashlib.sha1); h.update(b"hello")', 'h.hexdigest() # sha1'),
        ('h = hmac.new(b"ffff", digestmod=hashlib.sha256); h.update(b"hello")', 'h.hexdigest() # sha256')
    ]

class KeccakTest(BaseSnippetTest, BaseServerTest):
    module = "keccak"
    snippets = [
        ('k = keccak.keccak_512(); k.update(b"data")', 'k.hexdigest() # sha3 512')
    ]

class ECDSATest(BaseSnippetTest, BaseServerTest):
    module = "ecdsa"
    snippets = [
        (
            'sk = ecdsa.SigningKey.generate();'
            'vk = sk.verifying_key;'
            'signature = sk.sign(b"message")',
            'vk.verify(signature, b"message") # NIST192p;'
        ),
        # (
        #     'sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST384p);'
        #     'vk = sk.verifying_key;'
        #     'signature = sk.sign(b"message")',
        #     'vk.verify(signature, b"message") #NIST384p'
        # ),
        (
            'sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST384p);'
            'sk2 = ecdsa.SigningKey.from_string(sk.to_string(), curve=ecdsa.NIST384p)',
            'sk == sk2'
        )


        # vk = sk.verifying_key
        # vk_string = vk.to_string()
        # vk2 = VerifyingKey.from_string(vk_string, curve=NIST384p)
        # # vk and vk2 are the same key
        #
        # sk = SigningKey.generate(curve=NIST384p)
        # vk = sk.verifying_key
        # vk_pem = vk.to_pem()
        # vk2 = VerifyingKey.from_pem(vk_pem)
        #
        # rng1 = PRNG(b"seed")
        # sk1 = SigningKey.generate(entropy=rng1)
        # rng2 = PRNG(b"seed")
        # sk2 = SigningKey.generate(entropy=rng2)
        # # sk1 and sk2 are the same key
        #
        # ecdh = ECDH(curve=NIST256p)
        # ecdh.generate_private_key()
        # local_public_key = ecdh.get_public_key()
        #
        # sk = SigningKey.generate(curve=NIST521p)
        # vk = sk.verifying_key
    ]


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--forceip', default=None)
    parser.add_argument('--nopackagedcore', action='store_true', default=False)
    parser.add_argument('--keepkeys', action='store_true', default=False)
    parser.add_argument('--nop2p', action='store_true', default=False)
    parser.add_argument('unittest_args', nargs='*')

    args = parser.parse_args()
    if args.forceip:
        FORCEIP = args.forceip

    USE_PACKAGED = not args.nopackagedcore
    KEEP_KEYS = args.keepkeys
    NO_P2P = args.nop2p

    sys.argv[1:] = args.unittest_args
    unittest.main()
