# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/remote_boot_xcc.py
# Compiled at: 2019-02-15 12:42:10
import logging
from pyghmi.ipmi.oem.lenovo.imm import XCCClient
from foundation_tools import get_my_ip
from http_server import FileServer
from lenovo_util import get_boot_mode_str, LEGACY
from remote_boot_tsmm import RemoteBootTSMM
logger = logging.getLogger('xcc')
BOOT_MODE_URL = '/api/providers/bootmode'

class XCCClient2(XCCClient):

    def get_boot_mode(self):
        rt = self.wc.grab_json_response(BOOT_MODE_URL)
        if rt['return'] == 0:
            return rt['mode']
        logger.error('Unable to get boot mode')
        return

    def set_boot_mode(self, mode=LEGACY):
        rt = self.wc.grab_json_response(BOOT_MODE_URL, {'param': '%d' % mode})
        if rt['return'] == 0:
            return
        raise StandardError('Set boot mode to %s (%d) failed with return %d' % (
         get_boot_mode_str(mode), mode,
         rt['return']))


class RemoteBootXCC(RemoteBootTSMM):
    xcc = None
    session = None

    def _init_xcc_client(self):
        self.util.get_session()
        self.session = self.util.session
        self.xcc = XCCClient2(self.session)

    def get_iso_url(self, iso):
        my_ip = get_my_ip(self.node_config.ipmi_ip)
        return FileServer.make_url_and_hash(iso, self.node_config, foundation_ip=my_ip)['url']

    def set_boot_mode(self, mode=LEGACY):
        self._init_xcc_client()
        if self.xcc.get_boot_mode() != mode:
            logger.info('Setting boot mode to %s (%d)' % (get_boot_mode_str(mode),
             mode))
            self.xcc.set_boot_mode(mode)