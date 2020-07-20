from __future__ import print_function

import os
import pyaes
import json
import base64
import binascii
import hashlib
import warnings

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

    # Initialze the request object with key paths
    def __init__(self, identity=None, core_path=None, client_cert_path=None,
                 client_key_path=None, master_key_path=None, verbose=True):
        self.verbose = verbose
        if client_cert_path or client_key_path or master_key_path:
            self.key_manager = FileKeyManager(
                core_path=core_path, client_cert_path=client_cert_path,
                client_key_path=client_key_path, master_key_path=master_key_path,
                verbose=verbose
            )
        else:
            self.key_manager = IdentityKeyManager(
                identity, core_path=core_path, verbose=verbose
            )

    def p(self, *args):
        if self.verbose: print(*args)

    # Encrypt the request data section with master AES key
    def __encryptData(self, data):
        ciphertext = b''

        # set ip so attestation goes to the proper server if attestation is needed
        # and/or the correct aes key is selected.
        self.key_manager.ip = self.get_ip()

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

        try:
            return decrypted_data.decode("utf-8") # interpret as text
        except UnicodeDecodeError:
            return decrypted_data

    # Encode the encryped data with base64 so they can be put in JSON
    def __getJsonDataItemKey(self, encoding_mode, data):
        if encoding_mode != "base64":
            return data
        enc = self.__encryptData(data)
        return binascii.b2a_base64(enc).decode().replace("\n", '')

    # Read the tSerevice python code file and
    def read_code_bytes(self, python_code_path):
        with open(python_code_path, 'rb') as file:
            codeContent = file.read()
        return binascii.b2a_base64(codeContent)

    def set_json_data(self, json_data, encoding='base64'):
        """
        Wrapper for `set_data` that runs the data through json.dumps,
        for use when the server wants data in json format. This will ensure
        that data going to the server is always valid json.
        """
        self.set_data(json.dumps(json_data), encoding)

    # Data in request, see doc
    def set_data(self, data, encoding="base64"):
        self.__data = data
        self.__dataEncoding = encoding

    def set_appid_from_code(self, code_path):
        """
        Set App ID by providing full code. The full code will not appear in
        request field
        """
        code = self.read_code_bytes(code_path)
        self.appId = sha256_multihash(code)

    def set_code(self, code_file):
        """
        Set App ID by providing full code file. The full code will also appear
        in request field
        """
        self.code = self.read_code_bytes(code_file)
        self.appId = sha256_multihash(self.code)

    # Output request JSON
    def getRawRequest(self):
        # As of v0.1, we only support raw and base64 as encoding mode
        if self.__dataEncoding != "base64":
            self.__dataEncoding = "raw"

        # If needed, encode the data with assigned encoding mode
        json_data = ""
        if self.__data != "":
            json_data = self.__getJsonDataItemKey(self.__dataEncoding, self.__data)

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
        return "https://" + self.get_ip() + ":8002"

    def send(self, function=None, code_path=None, appid_from_code=None, data=None, json_data=None):
        """
        Send the encoded request to node, expect a dictionary of the response
        from the server.
        """
        if function:
            self.function = function
        if code_path:
            self.set_code(code_path)
        if appid_from_code:
            self.set_appid_from_code(appid_from_code)
        if data:
            self.set_data(data)
        if json_data:
            self.set_json_data(json_data)

        url = self.base_url + "/api/contract/request"
        headers = {'accept': 'application/json'}
        d = self.getRawRequest()
        self.p("Sending raw data:", d)
        self.p("Sending to:", url)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            resp = requests.post(url, verify=self.verify, data=d, headers=headers)

        j = resp.json()
        if not j['status'] == 200:
            raise TaxaException('Taxa server returned %s: %s' % (
            j['status'], j['response']
        ))

        response = json.loads(j['response'].replace("\'", '"'))
        return self.decrypt_response(response)

    def decrypt_response(self, response):
        response['encrypted_data'] = response['data']
        response['decrypted_data'] = self.decrypt_data(response.pop('data'))
        return response

    def get_ip(self):
        if self.ip:
            return self.ip

        appID = self.appId.replace('/', "%2F")
        url = "http://%s/appId/%s" % (self.node_distributor, appID)
        resp = requests.get(url)
        try:
            self.ip = resp.json()['serverIp']
            self.p("Connecting to node:", self.ip)
            return self.ip
        except json.decoder.JSONDecodeError as exc:
            raise TaxaException("Can't get node IP: %s" % resp.text)
