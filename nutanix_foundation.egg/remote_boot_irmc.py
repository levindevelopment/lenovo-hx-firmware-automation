# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/remote_boot_irmc.py
# Compiled at: 2019-02-15 12:42:10
import time
from foundation.ipmi_util import ipmi_context
from foundation.ironwood import FujitsuIRMC
from foundation.remote_boot import RemoteBoot

class RemoteBootIRMC(RemoteBoot):
    """
    Implements RemoteBoot interface for Fujitsu via iRMC and standard IPMI.
    
    NB: We intentionally do not subclass RemoteBootIPMI in order to use pyghmi
    rather than wrapping ipmitool.
    """
    POWER_OFF_TIMEOUT_SECS = 300

    def __init__(self, node_config):
        super(RemoteBootIRMC, self).__init__(node_config)
        self._irmc = FujitsuIRMC(node_config.ipmi_ip, node_config.ipmi_user, node_config.ipmi_password)
        self._log = self.node_config.get_logger()

    def boot(self, iso, do_reset=True):
        """
        Set boot mode to Legacy.
        Mount 'iso' via iRMC virtual media support and set boot device to CDROM.
        """
        self._log.info('Setting boot mode to Legacy')
        self._irmc.set_legacy_boot()
        self._log.info("Mounting '%s' as virtual CD drive" % iso)
        self._irmc.mount_iso(iso)
        self.set_bootdev_cdrom()
        if do_reset:
            self.powerreset()

    def stop(self):
        """
        Unmount virtual media if mounted.
        """
        self._log.info('Unmounting virtual media')
        self._irmc.unmount_iso()

    def poweron(self):
        """
        Power off node.
        """
        with ipmi_context(self.node_config, 10) as (ipmi):
            ipmi.set_power('on')

    def poweroff(self):
        """
        Power off node.
        """
        with ipmi_context(self.node_config, 10) as (ipmi):
            ipmi.set_power('off')

    def powerreset(self):
        """
        Power off node, wait for node to complete powering off, and power on.
        """
        self.poweroff()
        self.wait_for_poweroff()
        self.poweron()

    def wait_for_poweroff(self):
        """
        Polls power status via IPMI until node reports powered off.
        """
        log = self.node_config.get_logger()
        timeout_epoch = time.time() + self.POWER_OFF_TIMEOUT_SECS
        self._log.info('Waiting up to %d second for node to power off' % self.POWER_OFF_TIMEOUT_SECS)
        with ipmi_context(self.node_config, 10) as (ipmi):
            while 1:
                if time.time() < timeout_epoch:
                    resp = ipmi.get_power()
                    if resp.get('powerstate') == 'off':
                        break
                    log.info('Sleeping 1 second prior to polling node power state')
                    time.sleep(1)
            else:
                raise StandardError('Timed out after %d seconds waiting for node to power off' % self.POWER_OFF_TIMEOUT_SECS)

    def set_bootdev_cdrom(self):
        """
        Set the node to boot from CDROM on next boot.
        """
        self._log.info('Setting boot device to CDROM for next boot')
        with ipmi_context(self.node_config, 10) as (ipmi):
            ipmi.set_bootdev('cdrom', persist=False)

    def set_first_boot_device(self):
        """
          Virtual method for setting satadom / raid as first boot device
        """
        pass