# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_misc_hw_checks.py
# Compiled at: 2019-02-15 12:42:10
import foundation_tools as tools, re, time
from foundation.imaging_step import ImagingStepNodeTask
from foundation.imaging_step_pre_install import STATE_WAIT_FOR_PHOENIX, MAX_BOOT_WAIT_CYCLES, CHECK_INTERVAL_S
STATE_MISC_HW_ACTIONS = 'Running Miscellaneous HW Actions'
RAID_CHECK_COUNT = 5

class ImagingStepMiscHWChecks(ImagingStepNodeTask):

    def ssh(self, node_config, command, throw_on_error=True, log_on_error=True, timeout=None):
        return tools.ssh(config=node_config, ip=node_config.cvm_ip, command=command, throw_on_error=throw_on_error, log_on_error=log_on_error, user='root', password='nutanix/4u', timeout=timeout)

    def get_progress_timing(self):
        return [
         (
          STATE_WAIT_FOR_PHOENIX, 1),
         (
          STATE_MISC_HW_ACTIONS, 1)]

    def _will_run(self):
        logger = self.logger
        node_config = self.config
        if not node_config.image_now:
            logger.info('skipped, image_now is False')
            return False
        return True

    def _check_raid_status(self):
        """
        Check RAID status on a node
        
        Returns:
          True if RAID is created else False
        """
        r = re.compile('(.*?)RAID mode\\:\\s*(.*?)\\s*Cache')
        raid_mode = None
        cmd = [
         'mvcli', 'info', '-o', 'vd']
        out, _, _ = self.ssh(self.config, cmd, throw_on_error=False)
        search_obj = r.search(out)
        if search_obj:
            raid_mode = search_obj.group(2)
        if raid_mode == 'RAID1':
            return True
        return False

    def run(self):
        logger = self.logger
        node_config = self.config
        if not self._will_run():
            return
        self.set_status(STATE_MISC_HW_ACTIONS)
        hardware_config = tools.read_hardware_config_from_phoenix(node_config)
        if not hardware_config:
            raise StandardError("Couldn't figure out what platform %s is. Either foundation can't reach it over the network or the system doesn't match foundation's expectations. log/node_%s.manifest contains more diagnosticinformation." % (
             node_config.phoenix_ip,
             node_config.node_id))
        if hardware_config['chassis']['class'] != 'SMIPMI' or 'smc' not in hardware_config['node']['hardware_attributes']['lcm_family'] or '1b4b:9230' not in hardware_config['node']['boot_device']['controller']:
            logger.info('Miscellaneous HW actions bypassed for non SMC nodes or any non G7 platform nodes')
        else:
            if not self._check_raid_status():
                cmd = [
                 'echo', 'y', '|', 'mvcli', 'create', '-o', 'vd', '-n', 'New_VD',
                 '-r', '1', '-d', '0,1']
                stdout, stderr, retval = self.ssh(node_config, cmd, log_on_error=False, throw_on_error=False)
                if retval != 0:
                    raise StandardError('Something unexpected during RAID creation, failed with exit code %s:\nStdout: %s\n Stderr: %s' % (
                     retval, stdout, stderr))
                attempt = 0
                while 1:
                    if attempt <= RAID_CHECK_COUNT:
                        logger.info('Waiting for RAID create, attempt %s out of attempts %d', attempt, RAID_CHECK_COUNT)
                        if self._check_raid_status():
                            logger.info('RAID volume created successfully')
                            break
                        time.sleep(2)
                        attempt = attempt + 1
                else:
                    logger.warn('RAID status check failed in all %d attempts', attempt)
                    raise StandardError("Required RAID can't be created")

            else:
                logger.info('RAID volume already created on this node, nothing to do')