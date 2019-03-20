# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/monkey_paramiko.py
# Compiled at: 2019-02-15 12:42:10
import base64
from pyasn1.codec.der.decoder import decode as der_decoder
import paramiko
from paramiko.ssh_exception import SSHException
PKCS8_BEGIN = '-----BEGIN PRIVATE KEY-----'
PKCS8_END = '-----END PRIVATE KEY-----'

class PKey(paramiko.pkey.PKey):

    def _read_private_key(self, tag, f, password=None):
        key_lines = f.read().splitlines()
        try:
            if key_lines[0] == PKCS8_BEGIN and key_lines[-1] == PKCS8_END:
                return base64.b64decode(('').join(key_lines[1:-1]))
        except (IndexError, TypeError):
            pass

        f.seek(0)
        return super(PKey, self)._read_private_key(tag, f, password=password)


class RSAKey(paramiko.rsakey.RSAKey, PKey):

    def _decode_key(self, data):
        OID_RSA = (1, 2, 840, 113549, 1, 1, 1)
        try:
            pk = der_decoder(data)
            if pk[0][1][0].asTuple() == OID_RSA:
                return super(RSAKey, self)._decode_key(pk[0][2].asOctets())
        except (IndexError, AttributeError, TypeError, SSHException):
            pass

        return super(RSAKey, self)._decode_key(data)