from __future__ import print_function

try:
    import configparser
except ImportError: # py2
    import ConfigParser as configparser

import os
import subprocess
import platform
import requests
import json
import base64
import hashlib
import time
import sys
import shutil
import warnings

from .exceptions import *

def find_lib_dir():
    this_dir = os.path.dirname(os.path.abspath(__file__))
    for p in sys.path:
        if p == this_dir:
            continue
        if os.path.isdir(p) and 'taxa_sdk' in os.listdir(p):
            install_path = os.path.join(p, 'taxa_sdk')
            break
    else:
        raise Exception(
            "Could not find SDK install path to add taxa_client libs to library path"
        )

    return "%s/bin/libs" % install_path

def parse_os_release(item, start, end, verbose=False):
    before_parsed = subprocess.Popen(
        ["grep '^%s' /etc/os-release" % item], shell=True, stdout=subprocess.PIPE
    ).stdout.read().decode().strip()

    if verbose: print("before parse:", type(before_parsed), before_parsed)
    return before_parsed[start:end]

def get_os_dir():
    plat = platform.platform()
    if plat.startswith("Darwin") or plat.startswith("macOS"):
        return "OSX"
    os_name = parse_os_release("NAME", 6, -1)
    version = parse_os_release("VERSION_ID", 12, -1)
    return "%s_%s" % (os_name, version)

def get_os_specific_lib_dir():
    return os.path.join(find_lib_dir(), get_os_dir())

class BaseKeyManager(object):

    # the filename of the keys if no filename is passed in when initializing.
    DEFAULT_HOME_KEY_NAME = "profile_{hash}"

    # cache to avoid reading the key from disk twice.
    __master_key_bytes = None

    # must be set before calling self.master_key if attestation has not already
    # been performed
    ip = None

    # to skip https certificate verification (for beta)
    verify = False
    protocol = "http"
    port = 80

    # the amount of times attestation will be retried before giving up
    attestation_retries = 3

    # seconds to pause before each attestation retry
    attestation_retry_pause = 2

    def pre_attestation_hook(self):
        return
    def post_attestation_hook(self, output):
        return
    def pre_keygen_hook(self):
        return
    def post_keygen_hook(self):
        return

    @property
    def export(self):
        if self.do_export:
            env_var = "LD_LIBRARY_PATH"
            if "OSX" in get_os_dir():
                env_var = "DYLD_LIBRARY_PATH"

            return "export {env_var}=${env_var}:{libdir};".format(
                libdir=get_os_specific_lib_dir(), env_var=env_var
            )
        else:
            return ""

    @property
    def client_connect_cmd(self):
        return "cd; {export} ./taxa_client connect {client_key} {master_key}".format(
            core_dir=self.core_dir, client_key=self.client_key_path,
            master_key=self.master_key_path, export=self.export
        )

    @property
    def gen_key_cmd(self):
        return "cd; {export} ./taxa_client keygen {client_cert} {client_key}".format(
            core_dir=self.core_dir, client_cert=self.client_cert_path,
            client_key=self.client_key_path, export=self.export
        )

    @property
    def core_dir(self):
        return os.path.dirname(os.path.abspath(self.core_path))

    @property
    def ini_path(self):
        return os.path.join(self.core_dir, "../../taxaclient.ini")

    @property
    def copied_ini_path(self):
        return os.path.join(os.path.expanduser("~"), "taxaclient.ini")

    @property
    def server_cert_path(self):
        return os.path.join(self.core_dir, "../../sp_server.crt")

    @property
    def copied_server_cert_path(self):
        return os.path.join(os.path.expanduser("~"), "sp_server.crt")

    @property
    def copied_core_path(self):
        return os.path.join(os.path.expanduser("~"), "taxa_client")

    def p(self, *args):
        if self.verbose: print("SDK:", *args)

    def __init__(self, core_path=None, verbose=False, do_export=True):
        self.verbose = verbose
        self.do_export = do_export
        if not core_path:
            # use defaults that come packaged with this module
            base_path = os.path.dirname(os.path.abspath(__file__))
            bin_path = os.path.join(base_path, "bin")
            client = os.path.join(get_os_specific_lib_dir(), "taxa_client")
            self.core_path = os.path.join(bin_path, client)
        else:
            self.core_path = core_path

        self.p("Using core path: %s" %  self.core_path)

    def validate_ini(self, config):
        spid_len = 32
        if len(config.get('IAS', 'SPID')) != spid_len:
            raise ValueError(
                "IAS.SPID not valid in configuration file at %s (should be %s chars long)"
                % (self.ini_path, spid_len)
            )

        pk_len = 32
        if len(config.get('IAS', 'PRIMARY_KEY')) != pk_len:
            raise ValueError(
                "IAS.PRIMARY_KEY not valid in configuration file at %s (should be %s chars long)"
                % (self.ini_path, pk_len)
            )

    def get_config(self):
        config = configparser.ConfigParser()
        config.optionxform = str # to preserve case sensitivity
        config.read(self.ini_path)
        self.validate_ini(config)
        return config

    def write_hostname_to_ini(self, hostname):
        config = self.get_config()
        config.set('NETWORK', 'TAXA_SERVER_HOST', hostname)
        with open(self.copied_ini_path, 'w') as configfile:
            config.write(configfile)

    def check_size(self, which, key_bytes, size):
        length = len(key_bytes)
        if length != size:
            raise InvalidKey(
                "%s must be exactly %s bytes, it is instead %d bytes" %
                (which, size, length)
            )

    def upload_client_cert(self):
        if not self.ip:
            raise TaxaException("IP not set, can't do attestation")

        url = "%s://%s:%d/api/files/user_cert_init" % (self.protocol, self.ip, self.port)
        headers = {'accept': 'application/json'}

        client_cert_content = base64.b64encode(self.client_cert)
        self.p("About to upload client_cert to: %s" % url)

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            response = requests.post(
                url, headers=headers, verify=self.verify, timeout=20, data={
                    "contentTransferEncoding": "base64",
                    "content": client_cert_content,
                }
            )

        if response.status_code != 200:
            raise TaxaException("user_cert_init returned: %s" % response.status_code)

        j = response.json()
        if 'code' in j and j['code'] == 0:
            raise TaxaException(j['message'])

        self.p("Successfully uploaded client_cert: %s" % j)

        return j

    def _copy_to_home(self):
        shutil.copy(self.core_path, self.copied_core_path)
        shutil.copy(self.ini_path, self.copied_ini_path)
        shutil.copy(self.server_cert_path, self.copied_server_cert_path)

    def _delete_home_copies(self):
        os.remove(self.copied_core_path)
        os.remove(self.copied_ini_path)
        os.remove(self.copied_server_cert_path)

    def _call_taxa_client(self, cmd):
        self.p("calling taxa_client:", cmd)
        process = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        output = process.communicate()
        self.p("taxa_client result:", str(output[0].decode()))
        if process.returncode != 0:
            raise TaxaClientException("Taxa client call failed, check log.")
        return output[0]

    def do_keygen(self, which):
        self.pre_keygen_hook()
        self.p("%s does not exist, generating keypairs..." % which)
        self._copy_to_home()
        try:
            self._call_taxa_client(self.gen_key_cmd)
        finally:
            self._delete_home_copies()
        self.post_keygen_hook()

    def do_attestation(self, ip=None, retry_count=0):
        if ip: self.ip = ip
        self.pre_attestation_hook()
        self.upload_client_cert()
        self._copy_to_home()
        self.write_hostname_to_ini(self.ip)
        try:
            output = self._call_taxa_client(self.client_connect_cmd)
        finally:
            self._delete_home_copies()

        try:
            attestation_status = check_attestation_status(output)
        except InvalidAttestationStatus as exc:
            if retry_count > self.attestation_retries:
                raise InvalidAttestationStatus(
                    "Still invalid after %s tries" % self.attestation_retries
                )
            self.p("Invalid status: %s, trying again after %s seconds" % (
                exc, self.attestation_retry_pause
            ))
            time.sleep(self.attestation_retry_pause)
            return self.do_attestation(retry_count=retry_count+1)
        except UnknownAttestationException:
            raise UnknownAttestationException(
                "Attestation Failed! output was: %s" % output
            )

        self.p("Attestation status was: %s" % attestation_status)
        self.post_attestation_hook(output)

    @property
    def client_cert(self):
        if not self.key_exists('client_cert'):
            self.do_keygen('Client Cert')

        client_cert_bytes = self.get_key_bytes("client_cert")
        self.check_size("Cert", client_cert_bytes, 64)
        return client_cert_bytes

    @property
    def client_pubkeyhash(self):
        import hashlib
        h = hashlib.sha256()
        h.update(self.client_cert)
        return h.digest()

    @property
    def client_key(self):
        if not self.key_exists('client_key'):
            self.do_keygen("Keyfile")

        client_key_bytes = self.get_key_bytes("client_key")
        self.check_size("Keyfile", client_key_bytes, 32)
        return client_key_bytes

    @property
    def master_key(self):
        if self.__master_key_bytes:
            return self.__master_key_bytes

        if not self.key_exists('master_key'):
            self.do_attestation()
        else:
            self.p("master_key for %s already exists, skipping attestation" % self.ip)

        self.__master_key_bytes = self.get_key_bytes('master_key')
        self.check_size("Aeskey", self.__master_key_bytes, 32)
        return self.__master_key_bytes

    @property
    def master_key_iv(self):
        #self.p("Using AES IV:", self.master_key[16:21], "...")
        return self.master_key[16:]

    @property
    def master_key_key(self):
        #self.p("Using AES Key:", self.master_key[:5], "...")
        return self.master_key[:16]


class FileKeyManager(BaseKeyManager):
    """
    Used for when the keys are passed in as seperate files.
    """
    __master_key_path = None # if passed in manually

    def __init__(self, client_cert_path=None, client_key_path=None, master_key_path=None, **kwargs):
        self.client_key_path = client_key_path or self.default_client_key_path
        identity_base = self.client_key_path.replace(".key", '')
        self.client_cert_path = client_cert_path or identity_base + ".cert"
        self.__master_key_path = master_key_path

        return super(FileKeyManager, self).__init__(**kwargs)

    def __unicode__(self):
        return self.client_key_path

    def __str__(self):
        return self.__unicode__()

    @property
    def default_client_key_path(self):
        key_name = self.DEFAULT_HOME_KEY_NAME + ".key"
        return os.path.join(os.path.expanduser("~"), key_name)

    @property
    def master_key_path(self):
        if self.__master_key_path:
            return self.__master_key_path
        identity_base = self.client_key_path.replace(".key", '')
        return "%s.%s.aes" % (identity_base, self.ip)

    def key_exists(self, which):
        return os.path.exists(getattr(self, "%s_path" % which))

    def get_key_bytes(self, which):
        path = getattr(self, "%s_path" % which)
        self.p("opening:", path)
        with open(path, 'rb') as key:
            return key.read()

class IdentityKeyManager(BaseKeyManager):
    """
    Used for when the keys are passed in as a taxa identity file.
    """
    empty_identity = '{"version": 1, "client_cert": null, "client_key": null, "master_key": {}}'

    def __init__(self, identity_path=None, **kwargs):
        if not identity_path:
            path = self.DEFAULT_HOME_KEY_NAME + ".json"
            self.identity_path = os.path.join(os.path.expanduser("~"), path)
        else:
            self.identity_path = os.path.abspath(identity_path)

        if os.path.exists(self.identity_path):
            with open(self.identity_path) as identity:
                self.keys = json.loads(identity.read())
        else:
            self.keys = json.loads(self.empty_identity)

        self.client_cert_path = self.identity_path + ".cert"
        self.client_key_path = self.identity_path + ".key"

        return super(IdentityKeyManager, self).__init__(**kwargs)

    def __unicode__(self):
        return self.identity_path

    def __str__(self):
        return self.__unicode__()

    @property
    def master_key_path(self):
        return "%s.%s.aes" % (self.identity_path, self.ip)

    def key_exists(self, which):
        if which == 'master_key':
            return bool(self.keys['master_key'].get(self.ip))
        return bool(self.keys[which])

    def get_key_bytes(self, which):
        to_b64 = self.keys[which]
        if which == 'master_key':
            to_b64 = to_b64[self.ip]
        return base64.b64decode(to_b64.replace("\n", ''))

    def pre_attestation_hook(self):
        self.write_key_to_file("client_cert")
        self.write_key_to_file("client_key")

    def write_key_to_file(self, which, path=None, ip=None):
        """
        Write a key within the identity file to a new file.
        `which` should be either `"client_cert"`,`"client_key"`, or `"master_key"`
        `path` is the path the file should be written to. Default is
           the path of the identity file with an extension appended.
        `ip` is only for writing the master_key.
        """
        if not path:
            if ip:
                old_ip = self.ip
                self.ip = ip
            path = getattr(self, "%s_path" % which)
            if ip:
                self.ip = old_ip

        if os.path.exists(path):
            pass #raise Exception("Path already exists, not overwriting")

        with open(path, 'wb') as f:
            f.write(getattr(self, which))

    def post_attestation_hook(self, output):
        try:
            with open(self.master_key_path, 'rb') as master_key:
                b64 = base64.b64encode(master_key.read()).decode()
                self.keys['master_key'][self.ip] = b64
        except IOError:
            raise AttestationException(
                "No AES key written, taxa_client output was: %s" % str(output)
            )

        os.remove(self.client_cert_path)
        os.remove(self.master_key_path)
        os.remove(self.client_key_path)
        self.write_identity_file()

    def post_keygen_hook(self):
        with open(self.client_cert_path, 'rb') as client_cert:
            self.keys['client_cert'] = base64.b64encode(client_cert.read()).decode()
        with open(self.client_key_path, 'rb') as client_key:
            self.keys['client_key'] = base64.b64encode(client_key.read()).decode()

    def write_identity_file(self):
        if "{hash}" in self.identity_path:
            # using default path... put a hash of the client cert in filename
            hash = hashlib.sha256(self.get_key_bytes('client_cert')).hexdigest()[:8]
            self.identity_path = self.identity_path.format(hash=hash)

        with open(self.identity_path, 'w') as identity:
            identity.write(json.dumps(self.keys))

def check_attestation_status(output):
    """
    From the raw output of the attestation command, parse the output for the status
    code, then raise exceptions of the status code shows the attestation failed.
    """
    try:
        status = int(output.decode().split('\n')[14].split(' ')[1])
    except:
        raise UnknownAttestationException("Can't parse status, Try Again.")

    if status < 0:
        raise InvalidAttestationStatus(status)

    return status
