# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/remote_boot_pxe.py
# Compiled at: 2019-02-15 12:42:10
import remote_boot, foundation_tools

class RemoteBootPXE(remote_boot.RemoteBoot):

    def set_first_boot_device(self):
        pass

    def boot(self, iso=None, do_reset=True):
        logger = self.node_config.get_logger()
        logger.info('Setting next boot to PXE')
        foundation_tools.ipmitool_with_retry(self.node_config, ['chassis', 'bootdev', 'pxe'])
        if do_reset:
            foundation_tools.ipmitool_with_retry(self.node_config, ['chassis', 'power', 'off'])
            foundation_tools.ipmitool_with_retry(self.node_config, ['chassis', 'power', 'on'])

    def stop(self):
        pass

    def poweroff(self):
        foundation_tools.ipmitool_with_retry(self.node_config, ['chassis', 'power', 'off'])