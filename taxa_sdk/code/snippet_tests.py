import json
import binascii
import itertools
import collections
import math
import cmath
import hashlib
import array
import md5

global random
import random

import hmac
import pyaes
import sha3

global ecdsa
import ecdsa

broke_modules = [
    'hmac', 'ecdsa', 'random'
]

@taxa.route("/test")
def test_snippets():
    bin = b'R\x9d\x94r\x12\xa4\x1a\xec\xb4\x11\x90\xdcY\x9a\x96\xccReWimBsDWONrzoeO'
    b64 = b"Up2UchKkGuy0EZDcWZqWzFJlV2ltQnNEV09OcnpvZU8="
    hex = b'529d947212a41aecb41190dc599a96cc526557696d427344574f4e727a6f654f'

    def do_assert(got, expected):
        assert got == expected, "got: %s, expected: %s" % (got, expected)

    def test_hashlib():
        m = hashlib.md5()
        m.update("Nobody inspects")
        m.update(" the spammish repetition")
        result = m.digest()
        do_assert(result, b"\xbbd\x9c\x83\xdd\x1e\xa5\xc9\xd9\xde\xc9\xa1\x8d\xf0\xff\xe9")

        #result = hashlib.sha224("Nobody inspects the spammish repetition").hexdigest()
        #do_assert(result, "a4337bc45a8fc544c03f52dc550cd6e1e87021bc896588bd79e901e2")

    def test_math():
        #math snippets
        do_assert(math.ceil(4.5), 5)
        do_assert(math.ceil(-5.01), -5)
        do_assert(math.fabs(-3.768), 3.768)
        do_assert(math.floor(4.5), 4)
        do_assert(math.floor(-5.01), -6)
        do_assert(math.exp(3), 20.085536923187668)
        do_assert(math.log(20.085536923187668), 3.0)
        do_assert(math.sqrt(81), 9.0)
        do_assert(math.pow(3, 3), 27.0)
        do_assert(math.cos(math.pi), -1.0)

        #cmath snippets
        do_assert(cmath.cosh(0), (1+0j))

    def test_collections():
        # collections snippets (not working)
        # cnt = collections.Counter()
        # for word in ['red', 'blue', 'red', 'green', 'blue', 'blue']:
        #     cnt[word] += 1
        # do_assert(cnt, collections.Counter({'blue': 3, 'red': 2, 'green': 1}))

        # Point = collections.namedtuple('Point', ['x', 'y'])
        # p = Point(3,5)
        # do_assert(p[0] + p[1], 8)

        # d = {'banana': 3, 'apple': 4, 'pear': 1, 'orange': 2}
        # od = collections.OrderedDict(sorted(d.items(), key=lambda t: t[0]))
        # do_assert(od, collections.OrderedDict([('apple', 4), ('banana', 3), ('orange', 2), ('pear', 1)]))

        # collections snippets working
        d = collections.deque('abc')
        d.appendleft("x")
        do_assert(d, collections.deque(['x', 'a', 'b', 'c']))
        do_assert(d.popleft(), 'x')
        do_assert(d, collections.deque(['a', 'b', 'c']))

        dd = collections.defaultdict(list)
        dd['my_key'].append("x")
        do_assert(dd, collections.defaultdict(list, {'my_key': ['x']}))

    def test_itertools():
        result = []
        for x in itertools.chain([1,2,3], [4,5,6]):
            result.append(x)
        do_assert(result, [1,2,3, 4,5,6])

        result = itertools.compress([1,1,2,2,3,3,4,4], [0,1,0,1])
        do_assert(list(result), [1,2])

        result = []
        for x in itertools.cycle([1,2]):
            result.append(x)
            if len(result) > 5:
                break
        do_assert(result, [1,2,1,2,1,2])

        r = itertools.dropwhile(lambda x: x < 5, [1,2,3,4,5,6,7,8,9,10])
        do_assert(list(r), [5, 6,7,8,9,10])

        r = itertools.permutations('ABCD', 2)
        do_assert(set(r), set([
            ('A', 'B'), ('A', 'C'), ('A', 'D'), ('B', 'A'), ('B', 'C'), ('B', 'D'),
            ('C', 'A'), ('C', 'B'), ('C', 'D'), ('D', 'A'), ('D', 'B'), ('D', 'C')
        ]))

        r = itertools.product('ABCD', 'xy')
        do_assert(list(r), [
            ('A', 'x'), ('A', 'y'), ('B', 'x'), ('B', 'y'),
            ('C', 'x'), ('C', 'y'), ('D', 'x'), ('D', 'y')
        ])

        r = itertools.repeat(10, 3)
        do_assert(list(r), [10, 10, 10])

        r = itertools.starmap(pow, [(2,5), (3,2), (10,3)])
        do_assert(list(r), [32, 9, 1000])

        r = itertools.takewhile(lambda x: x<5, [1,4,6,4,1])
        do_assert(list(r), [1, 4])

        r = itertools.tee([1,2,3], 3)
        do_assert(list(list(x) for x in r), [[1,2,3], [1,2,3], [1,2,3]])

    def test_array():
        a = array.array('c', 'abcdefg')
        a.append('h')
        do_assert(a.tostring(), 'abcdefgh')
        do_assert(a.tolist(), ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'])
        a.reverse()
        do_assert(a, array.array('c', 'hgfedcba'))

        do_assert(array.array('i', [1,2,3,3,3,4,5,6]).count(3), 3)

        a = array.array('i', [1,2,3])
        a.extend([4,5,6])
        do_assert(a, array.array('i', [1,2,3,4,5,6]))

        do_assert(array.array('f', [3.4, 5.0, 8.3, 5.6]).pop(1), 5.0)

    def test_binascii():
        do_assert(binascii.a2b_base64(b64), bin)
        do_assert(binascii.b2a_base64(bin), b64 + "\n")
        do_assert(binascii.hexlify(bin), hex)
        do_assert(binascii.unhexlify(hex), bin)

    def test_json():
        do_assert(json.loads('{"x": 4}'), {"x": 4})
        #do_assert(json.dumps({"x": 4}), '{"x": 4}') #not working

    def test_md5():
        m = md5.new()
        m.update("Nobody inspects")
        m.update(" the spammish repetition")
        do_assert(m.digest(), '\xbbd\x9c\x83\xdd\x1e\xa5\xc9\xd9\xde\xc9\xa1\x8d\xf0\xff\xe9')
        do_assert(m.hexdigest(), 'bb649c83dd1ea5c9d9dec9a18df0ffe9')

    def test_sha1():
        sha1 = hashlib.sha1()
        sha1.update("Nobody inspects")
        sha1.update(" the spammish repetition")
        do_assert(sha1.hexdigest(), '531b07a0f5b66477a21742d2827176264f4bbfe2')

    def test_sha256():
        sha256 = hashlib.sha256()
        sha256.update("Nobody inspects")
        sha256.update(" the spammish repetition")
        #raise Exception(sha1.hexdigest())
        do_assert(sha256.hexdigest(), '031edd7d41651593c5fe5c006fa5752b37fddff7bc4e843aa6af0c950f4b9406')

    def test_random():
        #state1 = random.getstate()
        r1 = random.Random().random()
        do_assert(r1 > 0 and r1 < 1.0, True)

    def test_hmac_sha256():
        h = hmac.new(bin, digestmod=hashlib.sha256)
        h.update(b"hello")
        d = h.hexdigest()
        do_assert(d, 'a4d000deb3faec0b6d3acf5730c5973727478fa918fb65195c75b0a62f7f12c8')

    def test_hmac_sha1():
        h = hmac.new(bin, digestmod=hashlib.sha1)
        h.update(b"hello")
        d = h.hexdigest()
        do_assert(d, 'e3d6ee7f48a94e137b1a8de06dec9ac54d6230cd')

    def test_sha3():
        k = sha3.sha3_512()
        k.update(b"data")
        hd = k.hexdigest()
        do_assert(hd, '1065aceeded3a5e4412e2187e919bffeadf815f5bd73d37fe00d384fe29f55f08462fdabe1007b993ce5b8119630e7db93101d9425d6e352e22ffe3dcb56b825')

    def test_pyaes():
        iv = b'Ze~o&G\xadvH\xc2v\x04\x86\xbc\x84\x92'
        ciphertext = b''
        encrypter = pyaes.Encrypter(
            pyaes.AESModeOfOperationCBC(bin, iv)
        )
        ciphertext += encrypter.feed("abc123")
        ciphertext += encrypter.feed()
        do_assert(b'\x19\xd6X\x1c\xcf\x91\xb2\xd2\\\xa4\x91\xeb\xf9\xb9Yo', ciphertext)

    def test_ecdsa():
        sk = ecdsa.SigningKey.generate()
        #print(sk)

        #sk = SigningKey.generate() # uses NIST192p
        #vk = sk.verifying_key
        #signature = sk.sign(b"message")
        #assert vk.verify(signature, b"message")

    module = json.loads(request.data)['module']
    if module:
        locals()["test_%s" % module]()
    else:
        # test all modules
        errors = []
        for test in locals().copy():
            if not test.startswith("test_"):
                continue
            try:
                locals()[test]()
            except Exception as exc:
                errors.append("%s -> %s: %s" % (test, type(exc).__name__, str(exc)))

        response.add('\n'.join(errors))
