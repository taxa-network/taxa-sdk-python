from __future__ import print_function

import os
import pyaes
import re
import json
import base64
import binascii
from subprocess import Popen, PIPE
import hashlib
import warnings
import random

from .multihash_py2_py3 import sha256_multihash
import requests

from .key_managers import FileKeyManager, IdentityKeyManager
from .exceptions import *



# Request generation and sending.
class TaxaRequest(object):
    # Header -> Type in request, see doc
    content_type = "text/plain"

    # Data in request, see doc
    __data = ""

    # Encoding mode for data, see doc
    __dataEncoding = ""

    # App ID (code hash)
    appId = ""

    # Function requested
    function = None

    # Full codes
    code = None

    # Devnet node distributor.
    node_distributor = "devnode.taxa.dev:8081"

    # IP of the server the request will get sent to, if not set manually,
    # it will call the node distrinuter to get an IP.
    ip = None

    # ignore https certificate errors
    verify = False

    protocol = "http"
    port = 80

    # where the node IP comes from, wither 'p2p', or 'node_distributor'
    node_source = 'p2p'

    p2p_seeds = [
        '/ip4/52.138.26.47/tcp/6868/p2p/12D3KooWBwQ6R1cxmptkxK9RGwfb6qfn27auCd5DWwxaBKPV5UZL'
    ]

    # only for debugging
    last_encrypted_response = None
    last_decrypted_response = None

    # cert used to find the appropriate node to send request to. If not passed in
    # tot he constructor, it uses the normal client_cert.
    peer_cert = None

    # Initialze the request object with key paths
    def __init__(self, identity=None, core_path=None, client_cert_path=None,
                 client_key_path=None, master_key_path=None, verbose=False,
                 p2p_node=None, peer_cert_path=None, peer_cert_bytes=None,
                 peer_cert_b64=None, do_export=True):
        self.verbose = verbose
        if client_cert_path or client_key_path or master_key_path:
            self.key_manager = FileKeyManager(
                core_path=core_path, client_cert_path=client_cert_path,
                client_key_path=client_key_path, master_key_path=master_key_path,
                verbose=verbose, do_export=do_export
            )
        else:
            self.key_manager = IdentityKeyManager(
                identity, core_path=core_path, verbose=verbose, do_export=do_export
            )

        if p2p_node:
            self.p2p_seeds = [p2p_node]
            self.node_source = 'p2p'

        if peer_cert_path:
            with open(peer_cert_path) as f:
                self.peer_cert = peer_cert_path.read()
        elif peer_cert_bytes:
            self.peer_cert = peer_cert_bytes
        elif peer_cert_b64:
            self.peer_cert = base64.b64decode(peer_cert_b64)
        else:
            self.peer_cert = self.key_manager.client_cert

    def p(self, *args):
        if self.verbose: print("SDK:", *args)

    # Encrypt the request data section with master AES key
    def __encryptData(self, data):
        ciphertext = b''

        # We can encrypt one line at a time, regardles of length
        encrypter = pyaes.Encrypter(
            pyaes.AESModeOfOperationCBC(
                self.key_manager.master_key_key, self.key_manager.master_key_iv
            )
        )
        ciphertext += encrypter.feed(data)

        # Make a final call to flush any remaining bytes and add padding
        ciphertext += encrypter.feed()

        return ciphertext

    def force_attestation(self):
        self.key_manager.ip = self.get_ip()
        self.key_manager.master_key

    def decrypt_data(self, encrypted_data):
        data = binascii.a2b_base64(encrypted_data)
        decrypted_data = b''

        # We can encrypt one line at a time, regardless of length
        decrypter = pyaes.Decrypter(
            pyaes.AESModeOfOperationCBC(
                self.key_manager.master_key_key, self.key_manager.master_key_iv
            )
        )
        decrypted_data += decrypter.feed(data)

        # Make a final call to flush any remaining bytes and add padding
        decrypted_data += decrypter.feed()

        self.last_encrypted_response = encrypted_data # for debugging
        self.last_decrypted_response = decrypted_data # for debugging

        try:
            ret = decrypted_data.decode("utf-8") # interpret as text
            self.p("Interpreping decrypted response as text")
            return ret
        except UnicodeDecodeError:
            self.p("Interpreping decrypted response as binary")
            return decrypted_data

    # Encode the encryped data with base64 so they can be put in JSON
    def __getJsonDataItemKey(self, encoding_mode, data):
        if encoding_mode != "base64":
            return data
        enc = self.__encryptData(data)
        return binascii.b2a_base64(enc).decode().replace("\n", '')

    # Read the tSerevice python code file and covert to base64
    def code_to_base64(self, code_path=None, raw_code=None):
        if code_path:
            with open(code_path, 'rb') as file:
                raw_code = file.read().strip()

        try:
            return binascii.b2a_base64(raw_code)[:-1] # python 2.7
        except TypeError:
            return binascii.b2a_base64(bytes(raw_code,"utf-8"))[:-1] # python 3

    # Data in request, see doc
    def set_data(self, data, encoding="base64"):
        self.__data = json.dumps(data)
        self.__dataEncoding = encoding

    def set_appid_from_code_path(self, code_path):
        """
        Set App ID by providing full code. The full code will not appear in
        request field
        """
        code = self.code_to_base64(code_path=code_path)
        self.appId = sha256_multihash(code)

    def set_code(self, code_path=None, raw_code=None):
        """
        Set App ID by providing full code file. The full code will also appear
        in request field
        """
        self.code_path = code_path
        self.code = self.code_to_base64(code_path=code_path, raw_code=raw_code)
        self.appId = sha256_multihash(self.code)

    # Output request JSON
    def request_body(self, function=None, code_path=None, code=None, appid_from_code_path=None, data=None, json_data=None):
        if function:
            self.function = function

        if code_path or code:
            self.set_code(code_path=code_path, raw_code=code)

        if appid_from_code_path:
            self.set_appid_from_code(appid_from_code_path)

        if data:
            self.set_data(data)
        if json_data: # kept for backwards compatibility. Remove later.
            self.set_data(json_data)

        # As of v0.1, we only support raw and base64 as encoding mode
        if self.__dataEncoding != "base64":
            self.__dataEncoding = "raw"

        # set ip so attestation goes to the proper server if attestation is needed
        # and/or the correct aes key is selected.
        self.key_manager.ip = self.get_ip()

        # If needed, encode the data with assigned encoding mode
        json_data = ""
        if self.__data != "":
            json_data = self.__getJsonDataItemKey(self.__dataEncoding, self.__data)
        else:
            self.key_manager.master_key # force attestation if needed

        # appID and code, at least 1 must be set. __function must be set.
        if not self.appId and not self.code:
            raise InvalidRequest("AppID or Code must be set")

        if self.function == "":
            raise InvalidRequest("Function must be set")

        request = {
            "taxa_version": "0",
            "app_id": self.appId,
            "cert": base64.b64encode(self.key_manager.client_cert).decode(),
            "function": "/" + self.function,
            "header": {"src": "user", "type": self.content_type},
            "data": json_data,
            "content-transfer-encoding":self.__dataEncoding
        }

        if self.code:
            request['code'] = self.code.decode()
        return request

    @property
    def base_url(self):
        return "%s://%s:%d" % (self.protocol, self.get_ip(), self.port)

    def send(self, **convenient):
        """
        Send the encoded request to node, expect a dictionary of the response
        from the server.
        """
        d = self.request_body(**convenient)
        url = self.base_url + "/api/contract/request"
        headers = {'accept': 'application/json'}
        self.p("Sending raw data:", d)
        self.p("Sending to:", url)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self.raw_response = requests.post(url, verify=self.verify, data=d, headers=headers)

        self.p("Got raw response from WebUI:", self.raw_response.text)

        j = self.raw_response.json()
        if not j['status'] == 200:
            raise TaxaException('Taxa server returned %s: %s' % (
            j['status'], j['response']
        ))

        taxa_core_response = j['response']
        if taxa_core_response.startswith('taxa-server.log.1'):
            # working around a bug in taxa-server
            taxa_core_response = taxa_core_response[18:]

        try:
            response = json.loads(taxa_core_response.replace("\'", '"'))
        except ValueError:
            raise WebUIError("Got invalid JSON: %s" % j)

        rc = response['response-code']
        if rc == '4000':
            error_msg = self.decrypt_response(response)['decrypted_data']
            raise TserviceError(error_msg)
        elif rc == '4001':
            raise SessionLimitsExceeded()

        return self.decrypt_response(response)

    def decrypt_response(self, response):
        response['encrypted_data'] = response['data']
        response['decrypted_data'] = self.decrypt_data(response.pop('data'))
        return response

    def get_ip(self):
        if self.ip:
            return self.ip

        if self.node_source == "p2p":
            self.ip = self._ip_from_p2p()
        elif self.node_source == 'node_distributor':
            self.ip = self._ip_from_node_distributor()
        else:
            raise TaxaException("Unknown node source: " + self.node_source)

        self.p("Using IP of:", self.ip)
        return self.ip

    def _ip_from_node_distributor(self):
        appID = self.appId.replace('/', "%2F")
        self.p("Getting IP from node distributor")
        url = "http://%s/appId/%s" % (self.node_distributor, appID)
        resp = requests.get(url)
        try:
            return resp.json()['serverIp']
        except json.decoder.JSONDecodeError as exc:
            raise TaxaException("Can't get node IP: %s" % resp.text)

    def _ip_from_p2p(self):
        this_dir = os.path.dirname(os.path.abspath(__file__))
        p2p_path = os.path.join(this_dir, "bin")
        self.p("Getting IP from Peer-to-Peer network")

        random.shuffle(self.p2p_seeds)
        for node in self.p2p_seeds:
            ip = self._try_p2p_node(p2p_path, node)
            if ip:
                return ip
        raise Exception("Peer-to-peer network failed to return a taxa node IP")

    def _try_p2p_node(self, p2p_path, node):
        peer_cert = os.path.join(os.path.expanduser("~"), ".taxa_peer_cert")
        with open(peer_cert, 'wb') as f:
            f.write(self.peer_cert)
        command = "./taxa-p2p-node -d %s -appIdPath %s -client" % (
            node, peer_cert
        )
        full_cmd = "cd %s; %s" % (p2p_path, command)
        self.p("p2p called: %s" % full_cmd)
        get_ip = Popen(
            full_cmd, shell=True, stdout=PIPE
        )

        while not get_ip.poll():
            output = get_ip.stdout.readline().decode()
            if output.startswith("IP Address is"):
                break

        get_ip.terminate()
        get_ip.stdout.close()
        os.remove(peer_cert)
        return output[14:-1]


    def key_dump(self):
        """
        For debugging. Prints out all keys and tells you their length
        """
        print("========")
        print("keydump for: %s" % self.key_manager)
        client_cert = self.key_manager.client_cert
        print(
            "Client Cert:    (%d) %s" % (len(client_cert), binascii.b2a_base64(client_cert))
        )
        client_key = self.key_manager.client_key
        print(
            "Client key:     (%d) %s" % (len(client_key), binascii.b2a_base64(client_key))
        )
        master_key = self.key_manager.master_key_key
        print(
            "Master Key:     (%d) %s" % (len(master_key), binascii.b2a_base64(master_key))
        )
        iv = self.key_manager.master_key_iv
        print(
            "IV:             (%d) %s" % (len(iv), binascii.b2a_base64(iv))
        )
        if self.last_encrypted_response:
            ler = binascii.a2b_base64(self.last_encrypted_response)
            print(
                "Encrypted resp: (%d) %s" % (len(ler), binascii.b2a_base64(ler))
            )
        if self.last_decrypted_response:
            ldr = self.last_decrypted_response
            print(
                "Decrypted resp: (%d) %s" % (len(ldr), binascii.b2a_base64(ldr))
            )
        print("========")
