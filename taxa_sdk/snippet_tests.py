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

    return (
#remote snippet
"""%s
@taxa.route("/test")
def test():
    %s # pre-snippet
    result = %s
    response.add(str(result))
""" % (import_module, pre_snippet, snippet),

    #local snippet
    "%s\n%s\nlocal_value = %s" % (import_module, pre_snippet, snippet)
)

class BaseSnippetTest(object):
    def compare(self, value):
        return str(value)

    def test_snippets(self):
        request = TaxaRequest("snippet_test.json", verbose=VERBOSE)
        if FORCEIP: request.ip = FORCEIP

        g = {'local_value': None}

        for snippet in self.snippets:
            pre_snippet = None
            if type(snippet) in (tuple, list):
                pre_snippet = snippet[0]
                snippet = snippet[1]

            remote, local = make_snippets(self.module, snippet, pre_snippet)

            if DO_ONLY != 'local':
                response = request.send(function="test", code=remote)
                remote_val = self.compare(response['decrypted_data'])
                print(snippet, ":", "remote->", remote_val, end="  ")
            else:
                print(snippet, ":", "remote->","(skipped)", end="  ")

            if DO_ONLY != 'remote':
                exec(local, g)
                local_val = self.compare(g['local_value'])
                print("local->", local_val)
            else:
                print("local-> (skipped)")

            if not DO_ONLY:
                self.assertEqual(remote_val, local_val, snippet)

class JsonTest(BaseSnippetTest, BaseServerTest):
    module = 'json'
    snippets = [
        #"""json.loads('{"a": 1, "b": [1, 2, 3], "c": 5.4}')""",
        """json.dumps({"a": 1, "b": [1, 2, 3], "c": 5.4})""",
    ]

class UnicodetoStrTest(BaseSnippetTest, BaseServerTest):
    module = None
    snippets = [
        'u"A" == "A"',
        'str(u"u")'
    ]

class BytestoStrTest(BaseSnippetTest, BaseServerTest):
    module = None
    snippets = [
        'str(b"b")'
    ]

class AddToItselfTest(BaseSnippetTest, BaseServerTest):
    module = None
    snippets = [
        '"s" + "s"',
        'b"b" + b"b"',
        'u"u" + u"u"',
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
            'sk = ecdsa.SigningKey.generate(); '
            'vk = sk.verifying_key; '
            'signature = sk.sign(b"message")',
            'vk.verify(signature, b"message") # SECP256K1'
        ),
        (
            'sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST384p); '
            'vk = sk.verifying_key; '
            'signature = sk.sign(b"message")',
            'vk.verify(signature, b"message") # NIST384p'
        ),
        (
            'sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST384p); '
            'sk2 = ecdsa.SigningKey.from_string(sk.to_string(), curve=ecdsa.NIST384p)',
            'sk == sk2'
        ),
        (
            "msg = b'Hello World!';"
            "private_key = b'0x2574c4b3ba6ecc8714740cedf1554ec3332d30589ff535f38de5d028a51f0165';"
            "msg_hash = ecdsa.SigningKey.eth_hash(msg)",
            "msg_hash == '0xec3608877ecbf8084c29896b7eab2a368b2b3c8d003288584d145613dfa4706c'"
        ),
        (
            "msg = b'Hello World!';"
            "public_key = b'0xbb5e2f23623af907307e918ec16599a4bdb7de0af6a114a073dcb82a4b17920d506e75406d2b4f4c53356d344fb9d64b4d5bb33f2ce341201e4bafea6666b651';"
            "private_key = b'0x2574c4b3ba6ecc8714740cedf1554ec3332d30589ff535f38de5d028a51f0165';"
            "signature, v, r, s, message_hash = ecdsa.SigningKey.eth_sign(msg, private_key)",
            "ecdsa.SigningKey.eth_verify(msg, r, s, public_key)"
        ),
        (
            'from ecdsa import PRNG; '
            'rng1 = PRNG(b"seed")',
            "ecdsa.SigningKey.generate(entropy=rng1).to_pem()"
        ),
    ]


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--forceip', default=None)
    parser.add_argument('--verbose', action='store_true', default=False)
    parser.add_argument('--keepkeys', action='store_true', default=False)
    parser.add_argument('--nop2p', action='store_true', default=False)
    parser.add_argument('--local-only', action='store_true', default=False)
    parser.add_argument('--remote-only', action='store_true', default=False)
    parser.add_argument('unittest_args', nargs='*')

    args = parser.parse_args()
    if args.forceip:
        FORCEIP = args.forceip

    KEEP_KEYS = args.keepkeys
    NO_P2P = args.nop2p
    VERBOSE = args.verbose

    if args.local_only:
        DO_ONLY = 'local'
    elif args.remote_only:
        DO_ONLY = 'remote'
    else:
        DO_ONLY = None

    sys.argv[1:] = args.unittest_args
    unittest.main()
