from __future__ import print_function

import argparse
import os
import re
import unittest
import json
import binascii
import subprocess
import sys
import time

from .taxa_request import TaxaRequest, IdentityKeyManager
from .key_managers import check_attestation_status
from .exceptions import *

FORCEIP = None
KEEP_KEYS = False
NO_P2P = False
USE_PACKAGED = True

def delete_keys(filename):
    if KEEP_KEYS:
        return
    if os.path.exists(filename):
        os.remove(filename)

class BaseServerTest(unittest.TestCase):
    server_path = "/path-to-taxa-core/Taxa-Core/server/Application/"
    client_path = "/path-to-taxa-core/Taxa-Core/client/ServiceProvider/"

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
        manager.do_attestation(ip='localhost')
        self.filename = manager.identity_path

        self.assertTrue(self.filename.startswith("/home"))
        self.assertTrue("{hash}" not in self.filename)
        self.assertTrue(len(os.path.basename(self.filename)) == 21)

    def tearDown(self):
        if not self.filename:
            return # test failed, no file to delete
        delete_keys(self.filename)

class TestMillionaire(BaseServerTest):
    """
    Tests thast the millionaire problem works using taxa production servers.
    """

    def _send_millionaire(self, num, networth, peer_cert=None):
        request = self._make_request(num, peer_cert)
        if NO_P2P:
            request.node_source = 'node_distributor'
        if FORCEIP: request.ip = FORCEIP
        return request, request.send(
            function="submit",
            json_data=networth,
            code_path=self.code_path("millionaire.py")
        )

    def test_millionaire(self):
        ######################### millionaire 1 send

        request_1, result_1 = self._send_millionaire(1, {"value": 2300000})
        self.assertTrue(result_1['decrypted_data'].startswith(b"TAXA:"), "Result 1 Invalid encryption")
        dd = result_1['decrypted_data'][5:]

        self.assertFalse(
            len(dd) >
            len(request_1.key_manager.client_cert),
            "millionaire 1 taxa.globals.getUserCert() too long: getUserCert: %s key_manager.client_cert: %s" % (
                binascii.b2a_hex(dd),
                binascii.b2a_hex(request_1.key_manager.client_cert)
            )
        )
        self.assertFalse(
            len(dd) <
            len(request_1.key_manager.client_cert),
            "millionaire 1 taxa.globals.getUserCert() too short: getUserCert: %s key_manager.client_cert: %s" % (
                binascii.b2a_hex(dd),
                binascii.b2a_hex(request_1.key_manager.client_cert)
            )
        )
        self.assertEqual(
            dd, request_1.key_manager.client_cert,
            "Millionaire 1 taxa.globals.getUserCert() not correct"
        )

        ######################### millionaire 2 send

        request_2, result_2 = self._send_millionaire(2, {"value": 1800000}, peer_cert=request_1.key_manager.client_cert)
        self.assertTrue(result_2['decrypted_data'].startswith(b"TAXA:"), "Result 2 Invalid encryption")
        dd = result_2['decrypted_data'][5:]
        self.assertEqual(
            len(dd),
            len(request_2.key_manager.client_cert)
        )
        self.assertEqual(
            dd, request_2.key_manager.client_cert,
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
            delete_keys("profile_millionaire_%d.json" % num)


class TestMillionaireByKey(TestMillionaire):
    def _make_request(self, num, peer_cert):
        #return TaxaRequest(client_key_path="millionaire_%s.key" % num, verbose=True)
        return TaxaRequest(client_key_path="bypass.key", master_key_path="bypass.aes", verbose=True, peer_cert_bytes=peer_cert)

class TestMillionaireByIdentity(TestMillionaire):
    def _make_request(self, num, peer_cert):
        return TaxaRequest("profile_millionaire_%s.json" % num, verbose=True, peer_cert_bytes=peer_cert)

class TestAttestationWebUI(BaseServerTest):
    def test_attestation(self):
        manager = IdentityKeyManager("attestation_test.json", verbose=True)
        manager.do_attestation(ip=FORCEIP or 'localhost')
        self.assertTrue(manager.master_key)

    def tearDown(self):
        delete_keys("attestation_test.json")


class TestErrorHandling(BaseServerTest):
    def test_error(self):
        request = TaxaRequest("error.json", verbose=True)
        if FORCEIP: request.ip = FORCEIP
        with self.assertRaises(TserviceError) as exc:
            response = request.send(
                function="broke",
                code_path=self.code_path("millionaire.py"),
            )
        self.assertTrue("NameError" in str(exc.exception))

    def tearDown(self):
        delete_keys("error.json")


class TestP2P(BaseServerTest):
    def test_p2p(self):
        tr = TaxaRequest()
        tr.code_path = self.code_path("millionaire.py")
        tr._ip_from_p2p()
        self.assertTrue(re.match("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", tr.ip))

class TestBypassWebUI(BaseServerTest):
    """
    Tests the client/server without going throught the WebUI.
    """
    key_path = None

    def execute_client(self, cmd):
        full_cmd = "cd " + self.client_path + "; ./taxa_client " + cmd
        print("COMMAND: %s" % full_cmd)
        return subprocess.Popen(
            full_cmd, shell=True, stdout=subprocess.PIPE, #stderr=subprocess.PIPE
        )
    def execute_server(self, cmd):
        full_cmd = "cd " + self.server_path + "; ./taxa_server " + cmd
        print("COMMAND: %s" % full_cmd)
        return subprocess.Popen(
            full_cmd, shell=True, stdout=subprocess.PIPE, #stderr=subprocess.PIPE
        )

    def test_attestation(self):
        if self.key_path:
            return # to avoid running attestation twice

        cwd = os.path.abspath(os.getcwd())
        self.key_path = os.path.join(cwd, "bypass.key")
        self.cert_path = os.path.join(cwd, "bypass.cert")
        self.master_key_path = os.path.join(cwd, "bypass.aes")
        self.session_path = os.path.join(cwd, "bypass_session")

        # generate keys
        keygen = self.execute_client(
            "keygen {cert} {key}".format(cert=self.cert_path, key=self.key_path),
        )
        keygen.wait()
        keygen.stdout.close()

        self.assertTrue(os.path.exists(self.key_path), "Key doesn't exist")
        self.assertTrue(os.path.getsize(self.key_path) == 32, "Key is not right size")
        self.assertTrue(os.path.exists(self.cert_path), "Cert doesn't exist")
        self.assertTrue(os.path.getsize(self.cert_path) == 64, "Cert is not right size")

        # perform attestation
        subprocess.Popen(['fuser', '-k', '22222/tcp']) # kill processes using 22222
        server = self.execute_server(
            "attestation {cert}".format(cert=self.cert_path)
        )
        time.sleep(2)
        connect = self.execute_client("connect {key} {master_key}".format(
            key=self.key_path, master_key=self.master_key_path
        ))
        out, error = connect.communicate()
        print(out.decode())
        check_attestation_status(out)
        server.stdout.close()
        connect.stdout.close()

        self.assertTrue(os.path.exists(self.master_key_path), "Master key doesn't exist")
        self.assertTrue(os.path.getsize(self.master_key_path) == 32, "Master key is not right size")

    def _call_pythonClassWithContext(self, tservice_args):
        if not self.key_path:
            self.test_attestation()

        # generate request and write it to file
        req = TaxaRequest(
            client_key_path=self.key_path, client_cert_path=self.cert_path,
            master_key_path=self.master_key_path, verbose=False
        )
        req.ip = 'localhost'

        body = req.request_body(code_path=self.code_path("millionaire.py"), **tservice_args)
        body['param'] = {"t": "33"}
        del body['cert']

        with open(self.session_path, 'w') as f:
            f.write(json.dumps(body))

        # execute request
        server = self.execute_server(
            "pythonClassWithContext {cert} {code_path} {code_name} {session}".format(
                cert=self.cert_path, key=self.key_path, session=self.session_path,
                code_name='millionaire.py', code_path=self.code_path("")
            )
        )
        out, error = server.communicate()
        server.stdout.close()
        fixed_out = out.decode().replace("'", '"')
        print("Output from pythonClassWithContext:", fixed_out)
        try:
            return req, json.loads(fixed_out)
        except json.decoder.JSONDecodeError:
            return req, {}

    def test_working_tservice(self):
        """
        Tests that the correctly functioning part of the millionaire test is working
        """
        req, result = self._call_pythonClassWithContext(
            {'function': "submit",'json_data': {"value": 1800000}}
        )
        self.assertEqual(result.get('response-code'), '1000')
        decrypted = req.decrypt_data(result['data'])
        just_key = decrypted[5:]
        self.assertTrue(decrypted.startswith(b"TAXA:"))
        req.key_dump()

        self.assertEqual(just_key, req.key_manager.client_cert)

    def test_broke_tservice(self):
        """
        Tests that the error reporting part of the millionaire test is working
        """
        req, result = self._call_pythonClassWithContext({'function': "broke"})
        self.assertEqual(result.get('response-code'), '4000')

    def tearDown(self):
        for f in ['key_path', 'cert_path', 'master_key_path', 'session_path']:
            filename = getattr(self, f)
            delete_keys(filename)

class SnippetTest(BaseServerTest):
    def test_snippet(self):
        extra = {}

        if not USE_PACKAGED:
            extra['core_path'] = self.client_path + "taxa_client"

        request = TaxaRequest("snippet.json", verbose=True, do_export=USE_PACKAGED, **extra)
        if FORCEIP: request.ip = FORCEIP
        response = request.send(
            function="test",
            json_data={"module": DO_MODULE},
            code_path=self.code_path("snippet_tests.py"),
        )
        self.assertEqual(response['decrypted_data'], '')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--forceip', default=None)
    parser.add_argument('--nopackagedcore', action='store_true', default=False)
    parser.add_argument('--keepkeys', action='store_true', default=False)
    parser.add_argument('--module', default=None)
    parser.add_argument('--nop2p', action='store_true', default=False)
    parser.add_argument('unittest_args', nargs='*')

    args = parser.parse_args()
    FORCEIP = args.forceip

    USE_PACKAGED = not args.nopackagedcore
    KEEP_KEYS = args.keepkeys
    NO_P2P = args.nop2p
    DO_MODULE = args.module

    sys.argv[1:] = args.unittest_args
    unittest.main()
