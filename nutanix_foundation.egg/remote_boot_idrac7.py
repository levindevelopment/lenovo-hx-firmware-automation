# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/remote_boot_idrac7.py
# Compiled at: 2019-02-15 12:42:10
import time, racadm, remote_boot, foundation_tools, folder_central
API_BREAK_VERSION = [
 1, 50, 0]
API_VERSION_14G = [3, 0, 0, 0]
RFS_BOOT_FLAG = 'RFS'
VCD_BOOT_FLAG = 'vCD-DVD'
VCD_BOOT_FLAG_14G = 'VCD-DVD'

class RemoteBootIDRAC7(remote_boot.RemoteBoot):

    def set_first_boot_device(self):
        pass

    def racadm(self, command_list):
        return racadm.execute_with_retry(self.node_config, command_list)

    def _unmount(self):
        logger = self.node_config.get_logger()
        self.racadm(['remoteimage', '-d'])
        retries = 10
        while 1:
            if retries > 0:
                stdout, _, _ = self.racadm(['remoteimage', '-s'])
                if 'Remote File Share is Disabled' in stdout:
                    break
                retries -= 1
                time.sleep(5)
        else:
            logger.info(stdout)
            raise StandardError('Unable to unmount virtual media')

    def boot(self, iso, do_reset=True):
        logger = self.node_config.get_logger()
        nfs_path = folder_central.get_nfs_path_from_tmp_path(iso)
        logger.info('Mounting %s as %s' % (iso, nfs_path))
        self.racadm(['serveraction', 'powerdown'])
        drac_version = racadm.get_idrac_firmware_version(self.node_config)
        if drac_version >= API_VERSION_14G:
            boot_flag = VCD_BOOT_FLAG_14G
        else:
            if drac_version >= API_BREAK_VERSION:
                boot_flag = VCD_BOOT_FLAG
            else:
                boot_flag = RFS_BOOT_FLAG

        def mount_iso():
            self._unmount()
            self.racadm(['remoteimage', '-c', '-l',
             '%s:%s' % (
              foundation_tools.get_my_ip(self.node_config.ipmi_ip), nfs_path),
             '-u', 'nutanix', '-p', 'nutanix/4u'])
            stdout, _, _ = self.racadm(['remoteimage', '-s'])
            logger.debug(stdout)
            return nfs_path in stdout

        if not mount_iso():
            logger.debug('Virtual media mount failed, will reset BMC and try again.')
            racadm.rac_reset(self.node_config)
            if not mount_iso():
                logger.warn('RFS mount of %s failed. Try to mount this path from a different machine to make sure NFS is configured correctly.' % nfs_path)
                raise StandardError("Mount failed: NFS path not in 'remoteimage -s'")
        else:
            logger.debug('Successfully mounted virtual media.')
        self.racadm(['set', 'iDrac.ServerBoot.BootOnce', 'Enabled'])
        self.racadm(['set', 'iDrac.ServerBoot.FirstBootDevice', boot_flag])
        if do_reset:
            self.racadm(['serveraction', 'powerup'])

    def stop(self):
        self._unmount()

    def powerup(self):
        self.racadm(['serveraction', 'powerup'])

    def poweroff(self):
        self.racadm(['serveraction', 'powerdown'])

    def powerreset(self):
        self.poweroff()
        self.wait_for_poweroff()
        self.powerup()

    def wait_for_poweroff(self):
        logger = self.node_config.get_logger()
        powered_off = False
        retries = 200
        while not powered_off and retries:
            out, err, ret = self.racadm(['serveraction', 'powerstatus'])
            logger.info('racadm response: ' + out)
            if 'Server power status: OFF' in out:
                powered_off = True
            if powered_off:
                logger.info('Node powered off')
                break
            logger.info('Waiting for node to power off')
            retries -= 1
            time.sleep(3)

        if not powered_off and not retries:
            raise StandardError('Node did not shut down in a timely manner.')

    def wait_for_poweron(self):
        logger = self.node_config.get_logger()
        powered_on = False
        retries = 200
        while not powered_on and retries:
            out, err, ret = self.racadm(['serveraction', 'powerstatus'])
            logger.info('racadm response: ' + out)
            if 'Server power status: ON' in out:
                powered_on = True
            if powered_on:
                logger.info('Node powered on')
                break
            logger.info('Waiting for node to power on')
            retries -= 1
            time.sleep(3)

        if not powered_on and not retries:
            raise StandardError('Node did not poweron in a timely manner.')