# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/monkey.py
# Compiled at: 2019-02-15 12:42:10
import base64, errno, hashlib, os, platform, select, subprocess, warnings, paramiko
from foundation.monkey_paramiko import RSAKey
saved = {}
_PIPE_BUF = getattr(select, 'PIPE_BUF', 512)
UNITTEST_ALWAYS_CLOSE = False

def _communicate_with_poll(self, input, endtime):
    stdout = None
    stderr = None
    if not self._communication_started:
        self._fd2file = {}
    poller = select.poll()

    def register_and_append(file_obj, eventmask):
        poller.register(file_obj.fileno(), eventmask)
        self._fd2file[file_obj.fileno()] = file_obj

    def close_unregister_and_remove(fd):
        poller.unregister(fd)
        try:
            self._fd2file[fd].close()
        except IOError as e:
            if e.errno == errno.EBADF:
                warnings.warn('Hit EBADF on close, ignoring', RuntimeWarning)
            else:
                raise
        finally:
            self._fd2file.pop(fd)

    if self.stdin and input:
        register_and_append(self.stdin, select.POLLOUT)
    if not self._communication_started:
        self._fd2output = {}
        if self.stdout:
            self._fd2output[self.stdout.fileno()] = []
        if self.stderr:
            self._fd2output[self.stderr.fileno()] = []
    select_POLLIN_POLLPRI = select.POLLIN | select.POLLPRI
    if self.stdout:
        register_and_append(self.stdout, select_POLLIN_POLLPRI)
        stdout = self._fd2output[self.stdout.fileno()]
    if self.stderr:
        register_and_append(self.stderr, select_POLLIN_POLLPRI)
        stderr = self._fd2output[self.stderr.fileno()]
    if not self._input:
        self._input_offset = 0
        self._input = input
    while self._fd2file:
        try:
            ready = poller.poll(self._remaining_time(endtime))
        except select.error as e:
            if e.args[0] == errno.EINTR:
                continue
            raise

        self._check_timeout(endtime)
        for fd, mode in ready:
            if mode & select.POLLOUT:
                chunk = self._input[self._input_offset:self._input_offset + _PIPE_BUF]
                try:
                    self._input_offset += os.write(fd, chunk)
                except OSError as e:
                    if e.errno == errno.EPIPE:
                        close_unregister_and_remove(fd)
                    else:
                        raise
                else:
                    if self._input_offset >= len(self._input):
                        close_unregister_and_remove(fd)
            elif mode & select_POLLIN_POLLPRI:
                data = os.read(fd, 4096)
                if not data:
                    close_unregister_and_remove(fd)
                self._fd2output[fd].append(data)
            else:
                if UNITTEST_ALWAYS_CLOSE:
                    os.close(fd)
                close_unregister_and_remove(fd)

    return (
     stdout, stderr)


def patch_subprocess():
    """
    This patch fixes the process.communicate glitch in
    close_unregister_and_remove as seen in ENG-62095.
    
    Returns:
      True if patched, otherwise False
    """
    if platform.python_version() == '2.6.6' and platform.linux_distribution()[0] == 'CentOS' and getattr(subprocess.Popen, '_communicate_with_poll', None):
        key = 'subprocess.Popen._communicate_with_poll'
        saved[key] = subprocess.Popen._communicate_with_poll
        subprocess.Popen._communicate_with_poll = _communicate_with_poll
        return True
    warnings.warn("The patch for ENG-62095 is not for this platform: '%s', '%s', skipping" % (
     platform.python_version(), platform.linux_distribution()), DeprecationWarning)
    return False
    return


def patch_paramiko_fips(force=False):
    """
    paramiko.pkey.get_fingerprint is using MD5 as hashing algo, however, this is
    not allowed in FIPS mode.
    This will patch paramiko.pkey.get_fingerprint to use sha256 as hashing algo
    to fix ENG-145154.
    
    Returns:
      True if patched, otherwise False
    """
    if not force:
        try:
            hashlib.md5(usedforsecurity=False)
        except TypeError:
            return False

    warnings.warn('Patching paramiko to use SHA256 for fingerprint')

    def get_sha256_fingerprint(self):
        """
        Return an SHA256 fingerprint of the public part of this key. Nothing secret
        is revealed.
        
        :return:
          an 43-byte `string <str>` (base64) of the SHA256 fingerprint, in SSH
          format.
        """
        return base64.b64encode(hashlib.sha256(self.asbytes()).digest())[:-1]

    paramiko.pkey.PKey.get_fingerprint = get_sha256_fingerprint
    return True


def patch_paramiko_pkcs():
    """
    paramiko.{pkey,ber,rsakey} doesn't support RSA private keys in PKCS#8 format,
    which will be generated from ssh-keygen in FIPS mode CentOS.
    
    This patch will use our hacked version and it will
      - parse rsa keys from encrypted pkcs#8 format file
        - the proper fix is to switch to paramiko 2.x with
          the cryptography.hazmat.primitives.serialization parser
      - load rsa keys with "-----BEGIN PRIVATE KEY-----" header
        - seems won't be fixed anytime soon
    """
    paramiko.client.RSAKey = RSAKey
    return True