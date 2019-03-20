# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_factory_erase.py
# Compiled at: 2019-02-15 12:42:10
import os, tempfile
from foundation import foundation_tools as tools
from foundation import ipmi_util
from foundation.imaging_step import ImagingStepNodeTask
STATE_ERASING_DISK = 'Erasing disks'
STATE_ERASING_DISK_DONE = 'Erased all disks'
SH_TEMPLATE = '#!/bin/bash\n\nFAIL=0\n\nDISK="{disks}"\n\n\nfor disk in $DISK; do\n  echo wiping disk $disk\n  SEEK=$(($(sudo blockdev --getsz $disk) - 1024))\n  sudo dd if=/dev/zero of=$disk bs=512 count=1024 oflag=direct &&        sudo dd if=/dev/zero of=$disk bs=512             seek=$SEEK count=1024 oflag=direct &&        sync &&        echo wiped $disk &\ndone\n\necho waiting for all jobs\nfor job in `jobs -p`; do\n  echo waiting for pid $job\n  wait $job || let "FAIL+=1"\ndone\n\nif [ "$FAIL" == "0" ]; then\n  echo "Wiped all disk"\nelse\n  echo "Failed wiping $FAIL disks"\nfi\n\nexit $FAIL\n'

class ImagingStepDiskErase(ImagingStepNodeTask):
    """
    Erase SSDs on CVM, host and poweroff the node
    """

    @classmethod
    def is_compatible(cls, config):
        return getattr(config, 'erase_disks', None) is not None

    def get_progress_timing(self):
        return [
         (
          STATE_ERASING_DISK, 5)]

    def get_finished_message(self):
        return STATE_ERASING_DISK_DONE

    def collect_disks(self, ip, user, ssd_only=True):
        """
        Collect SSD disks
        
        Since we are using wipefs, we are going to treat all disks as sata
        """
        logger = self.logger
        disks = {'sata': [], 'sas': []}
        lsblk_out, _, _ = tools.ssh(self.config, ip, [
         'lsblk', '-dr'], user=user)
        for line in lsblk_out.splitlines()[1:]:
            dev = line.split(' ', 1)[0]
            if not dev.startswith('sd'):
                logger.debug('ignore drive %s', dev)
                continue
            dev_path = '/dev/%s' % dev
            if ssd_only:
                rotational, _, _ = tools.ssh(self.config, ip, [
                 'sudo', 'sg_vpd', '--page=bdc', dev_path])
                if 'Non-rotating medium' not in rotational:
                    logger.debug('ignore disk %s, not SSD', dev)
                    continue
            disks['sata'].append(dev_path)

        return disks

    def erase_system(self, ip, user, ssd_only=True):
        logger = self.logger
        disks = self.collect_disks(ip, user, ssd_only=ssd_only)
        logger.debug('erasing disk on %s: %s', ip, disks)
        script = SH_TEMPLATE.format(disks=(' ').join(disks['sas'] + disks['sata']))
        with tempfile.NamedTemporaryFile(suffix='erase.sh') as (tf):
            tf.write(script)
            tf.flush()
            tools.scp(self.config, ip, '/tmp', files=[tf.name], user=user)
        out, _, _ = tools.ssh(self.config, ip, [
         'bash', os.path.join('/tmp', os.path.basename(tf.name))], user=user)
        logger.debug('erase output: %s', out)
        logger.info('erased disk on %s: %s', ip, disks)

    def erase_cvm(self):
        self.erase_system(self.config.cvm_ip, 'nutanix')

    def erase_host(self):
        self.erase_system(self.config.hypervisor_ip, 'root', ssd_only=False)

    def power_off_node(self):
        self.logger.info('Powering off node via IPMI')
        with ipmi_util.ipmi_context(self.config) as (ipmi):
            ipmi.set_power('off', wait=True)

    def run(self):
        self.set_status(STATE_ERASING_DISK)
        logger = self.logger
        logger.info('foundation will erase all SSD disks on this node')
        self.erase_cvm()
        self.erase_host()
        self.power_off_node()
        logger.info('finished erasing all SSD disks')


if __name__ == '__main__':
    import sys, logging
    from config_manager import NodeConfig
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) != 4:
        print 'usage: %s <IP> <username> <password>'
    else:
        nc = NodeConfig()
        nc.ipmi_ip, nc.ipmi_user, nc.impi_password = sys.argv[1:]
        nc._session_id = 'test_session'
        step = ImagingStepDiskErase(nc)
        step.run()