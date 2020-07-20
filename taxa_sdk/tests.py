from __future__ import print_function

import os
import unittest
import json
import binascii

from .taxa_request import TaxaRequest, IdentityKeyManager
from .exceptions import *

FORCEIP = None

class BaseServerTest(unittest.TestCase):
    def code_path(self, filename):
        this_folder = os.path.dirname(__file__)
        return os.path.join(this_folder, 'code', filename)

class TestEmptyConstructor(BaseServerTest):
    """
    Tests that initializing a KeyManager with an empty identity path will
    create a new file in the form profile_{hash}.json in the home folder.
    """
    filename = None
    def test_code(self):
        manager = IdentityKeyManager(verbose=True)
        manager.do_attestation(ip='13.90.172.233')
        self.filename = manager.identity_path

        self.assertTrue(self.filename.startswith("/home"))
        self.assertTrue("{hash}" not in self.filename)
        self.assertTrue(len(os.path.basename(self.filename)) == 21)

    def tearDown(self):
        if not self.filename:
            return # test failed, no file to delete
        if os.path.exists(self.filename):
            os.remove(self.filename)

class TestMillionaire(BaseServerTest):
    """
    Tests thast the millionaire problem works using taxa production servers.
    """

    def _send_millionaire(self, num, networth):
        request = self._make_request(num)
        if FORCEIP: request.ip = FORCEIP
        return request, request.send(
            function="submit",
            json_data=networth,
            code_path=self.code_path("millionaire.py")
        )

    def test_millionaire(self):
        ######################### millionaire 1 send

        request_1, result_1 = self._send_millionaire(1, {"value": 2300000})
        self.assertEqual(
            result_1['decrypted_data'], request_1.key_manager.client_cert,
            "Millionaire 1 taxa.globals.getUserCert()"
        )

        ######################### millionaire 2 send

        request_2, result_2 = self._send_millionaire(2, {"value": 1800000})
        self.assertEqual(
            result_2['decrypted_data'], request_2.key_manager.client_cert,
            "Millionaire 2 taxa.globals.getUserCert()"
        )

        ######################### millionaire 1 reveal

        cert_b64 = binascii.b2a_base64(request_2.key_manager.client_cert).decode()
        result = request_1.send(
            json_data={"opponent": cert_b64},
            function="reveal"
        )

        self.assertEqual(
            result['decrypted_data'], 'Your value is no less than your opponent', "Result"
        )

        ######################### millionaire 2 reveal

        cert_b64 = binascii.b2a_base64(request_1.key_manager.client_cert).decode()
        result = request_2.send(
            json_data={"opponent": cert_b64},
            function="reveal"
        )

        self.assertEqual(
            result['decrypted_data'], 'Your value is less than your opponent', "Result"
        )

    def tearDown(self):
        for num in [1, 2]:
            filename = "profile_millionaire_%d.json" % num
            if os.path.exists(filename):
                os.remove(filename)


class TestMillionaireByKey(TestMillionaire):
        def _make_request(self, num):
            return TaxaRequest(client_key_path="millionaire_%s.key" % num)

class TestMillionaireByIdentity(TestMillionaire):
        def _make_request(self, num):
            return TaxaRequest("profile_millionaire_%s.json" % num)


if __name__ == '__main__':
    unittest.main()
