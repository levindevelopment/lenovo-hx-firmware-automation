# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_init_cvm.py
# Compiled at: 2019-02-15 12:42:10
import time, logging, phoenix_prep
from imaging_step import ImagingStepNodeTask
import foundation_tools as tools, cvm_utilities as utils
from foundation.imaging_step_type_detection import CLASS_VM_INSTALLER
EVENT_IN_PHOENIX = 'phoenix_callback'
STATE_DISCOVER_HYP = 'Discovering current hypervisor on target node'
STATE_STAGING_FILES = 'Preparing to reboot into installer'
STATE_REBOOTING_INTO_PHOENIX = 'Rebooting into installer'
STATE_WAIT_FOR_PHOENIX = 'Waiting for installer to boot'
STATE_INIT_COMPLETE = 'Booted into installer successfully'
INSTALLATION_TIMEOUT_S = 3600
MAX_BOOT_TIMEOUT_S = 1200
CHECK_INTERVAL_S = 10
MAX_SSH_RETRIES = 10

class ImagingStepInitCVM(ImagingStepNodeTask):
    """
    This module places a kernel,initrd and a bootloader conf
    for the target hypervisor and reboots into it
    """

    def ssh(self, node_config, command, throw_on_error=True, log_on_error=True, timeout=None):
        return tools.ssh(config=node_config, ip=node_config.phoenix_ip, command=command, throw_on_error=throw_on_error, log_on_error=log_on_error, user='root', password='nutanix/4u', timeout=timeout)

    def _umount_phoenix_local_cdrom(self):
        logger = self.logger
        node_config = self.config
        path = '/mnt/local'
        out, _, _ = self.ssh(node_config, command=[
         'mount'], throw_on_error=False, log_on_error=True)
        if path in out:
            self.ssh(node_config, [
             'umount', path], throw_on_error=False, log_on_error=True)
            logger.debug('umount %s to enable imaging', path)

    def _check_if_in_phoenix(self, node_config):
        logger = self.logger
        message = 'Checking if target node is already in Phoenix'
        logger.info(message)
        for i in range(2):
            if tools.in_phoenix(node_config, log_on_error=True):
                message = 'Target node is running Phoenix. Moving to next step.'
                logger.info(message)
                node_config.booted_into_phoenix_manually = True
                return True
            time.sleep(utils.CHECK_INTERVAL_S)

        message = 'Target node is not running Phoenix.'
        logger.info(message)
        return False

    def get_finished_message(self):
        return STATE_INIT_COMPLETE

    def get_progress_timing(self):
        return [
         (
          STATE_DISCOVER_HYP, 0.5),
         (
          STATE_STAGING_FILES, 1.0),
         (
          STATE_REBOOTING_INTO_PHOENIX, 5.0)]

    def _will_run(self):
        logger = self.logger
        node_config = self.config
        if not node_config.image_now:
            logger.info('skipped, image_now is False')
            return False
        if self.config.type != CLASS_VM_INSTALLER:
            logger.debug('skipped, this node will be imaged via IPMI')
            return False
        return True

    def run(self):
        logger = self.logger
        node_config = self.config
        if not self._will_run():
            return
        image_delay = getattr(node_config, 'image_delay', 0)
        if image_delay:
            logger.info('Conditional delay specified in node_config. Sleeping for %s seconds', image_delay)
            time.sleep(image_delay)
        arch = utils.detect_remote_arch(node_config)
        logger.info('Discovered arch %s', arch)
        node_config.arch = arch
        is_unit = getattr(node_config, 'is_unit', False)
        if not is_unit:
            if self._check_if_in_phoenix(node_config):
                self._umount_phoenix_local_cdrom()
                return
        try:
            utils.stage_best_hcl(node_config)
        except StandardError:
            logger.exception('Could not stage the latest HCL')
        else:
            self.set_status(STATE_DISCOVER_HYP)
            self.set_status(STATE_STAGING_FILES)
            self.set_status(STATE_REBOOTING_INTO_PHOENIX)
            utils.reboot_to_phoenix(node_config)
            logger.info('Waiting for remote node to boot into phoenix, this may take %s minutes' % (MAX_BOOT_TIMEOUT_S / 60))
            try:
                self.wait_for_event(EVENT_IN_PHOENIX, timeout=MAX_BOOT_TIMEOUT_S)
            except StandardError as e:
                if 'Timeout' in str(e):
                    pass

        stdout, stderr, retval = self.ssh(node_config, [
         'test', '-f', '/phoenix/layout/layout_finder.py'], log_on_error=False, throw_on_error=False)
        if retval != 0:
            logger.warn('The target is not ssh-able or not in phoenix')
            raise StandardError('Failed to connect to Phoenix at %s' % node_config.phoenix_ip)
        logger.info('Rebooted into Phoenix successfully')