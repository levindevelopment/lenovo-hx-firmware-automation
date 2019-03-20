# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/remote_boot_tsmm.py
# Compiled at: 2019-02-15 12:42:10
import logging, folder_central, foundation_tools, remote_boot_ipmi
from lenovo_util import LenovoUtil, LEGACY
logger = logging.getLogger('tsmm')

class RemoteBootTSMM(remote_boot_ipmi.RemoteBootIPMI):

    def __init__(self, node_config):
        remote_boot_ipmi.RemoteBootIPMI.__init__(self, node_config)
        self.util = LenovoUtil(self.node_config.ipmi_ip, self.node_config.ipmi_user, self.node_config.ipmi_password)

    def set_first_boot_device(self):
        bootdev = 'cdrom'
        self.util.set_boot_device(bootdev)

    def get_iso_url(self, iso):
        iso_path = folder_central.get_nfs_path_from_tmp_path(iso)
        my_ip = foundation_tools.get_my_ip(self.node_config.ipmi_ip)
        return 'nfs://%s%s' % (my_ip, iso_path)

    def set_boot_mode(self, mode=LEGACY):
        pass

    def boot(self, iso, do_reset=True):
        self.stop()
        self.set_boot_mode()
        iso_url = self.get_iso_url(iso)
        logger.info("Mounting '%s' as '%s'" % (iso, iso_url))
        self.util.attach_media(iso_url)
        if do_reset:
            self.util.set_power('off')
            self.util.set_power('on')

    def stop(self):
        self.util.detach_media()

    def poweroff(self):
        self.util.set_power('off')