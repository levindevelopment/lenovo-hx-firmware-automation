# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/remote_boot_ipmi.py
# Compiled at: 2019-02-15 12:42:10
import time, foundation_tools, remote_boot

class RemoteBootIPMI(remote_boot.RemoteBoot):

    def __init__(self, node_config):
        remote_boot.RemoteBoot.__init__(self, node_config)
        self.ipmitool = foundation_tools.ipmitool

    def poweroff(self):
        out, err, ret = foundation_tools.ipmitool_with_retry(self.node_config, ['chassis', 'power', 'down'], ipmitool_=self.ipmitool)

    def wait_for_poweroff(self):
        logger = self.node_config.get_logger()
        powered_off = False
        retries = 200
        while not powered_off and retries:
            out, err, ret = foundation_tools.ipmitool_with_retry(self.node_config, ['chassis', 'power', 'status'], ipmitool_=self.ipmitool)
            logger.debug('ipmitool response: ' + out)
            if 'is off' in out.lower():
                powered_off = True
            if powered_off:
                logger.debug('Node powered off')
                break
            logger.debug('Waiting for node to power off')
            retries -= 1
            time.sleep(3)

        if not powered_off and not retries:
            raise StandardError('Node did not shut down in a timely manner.')
        time.sleep(15)