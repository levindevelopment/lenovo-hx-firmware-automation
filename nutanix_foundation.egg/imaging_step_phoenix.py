# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_phoenix.py
# Compiled at: 2019-02-15 12:42:10
import os, threading, time
from foundation import config_persistence
from foundation import features
from foundation import folder_central
from foundation import foundation_tools
from foundation import phoenix_prep
from foundation.decorators import persist_config_on_failure
from foundation.factory_mode import factory_mode
from foundation.imaging_step import ImagingStepNodeTask
from foundation.imaging_step_type_detection import CLASS_PXE
STATE_STARTING_PHOENIX = 'Will run CVM Installer in a while'
STATE_DOWNLOAD_NOS = 'Downloading AOS tarball'
STATE_DOWNLOAD_HYP = 'Downloading hypervisor iso'
STATE_DOWNLOAD_SLOW = 'Downloading resources (slow network detected)'
STATE_RUNNING_PHOENIX = 'Running CVM Installer'
STATE_FIRMWARE_DETECTION = 'Running firmware detection'
STATE_REBOOT_INTO_HYP = 'Rebooting node. This may take several minutes'
STATE_RUNNING_FB = 'Running firstboot scripts'
STATE_CHECKING_NICS = 'Testing connectivity on all NICs'
STATE_VSWITCH_DONE = 'vSwitch configuration done'
STATE_CREATE_PARTITIONS = 'Creating necessary partitions'
STATE_FIRST_HOST_REBOOT = 'Rebooting host, this may take several minutes'
STATE_CREATE_CVM = 'Creating a new CVM'
STATE_CVM_FB = 'CVM booted up successfully'
STATE_FIRST_REBOOT_HYPERV = 'Host reboot needed for drivers. This will take a few minutes'
STATE_LAST_REBOOT = 'Last reboot complete'
STATE_DONE_FRIENDLY = 'Imaging complete'

def make_dict_for_runtimes(kvm, esx=None, hyperv=None):
    esx = esx or kvm
    hyperv = hyperv or kvm
    return {'kvm': kvm, 'esx': esx, 'hyperv': hyperv, 'linux': kvm, 'xen': kvm}


ESTIMATED_RUN_TIMES = {STATE_STARTING_PHOENIX: make_dict_for_runtimes(1.0), 
   STATE_DOWNLOAD_NOS: make_dict_for_runtimes(1.0), 
   STATE_DOWNLOAD_HYP: make_dict_for_runtimes(0.25, 0.25, 1.0), 
   STATE_DOWNLOAD_SLOW: make_dict_for_runtimes(1.0), 
   STATE_RUNNING_PHOENIX: make_dict_for_runtimes(10.0), 
   STATE_FIRMWARE_DETECTION: make_dict_for_runtimes(15.0), 
   STATE_REBOOT_INTO_HYP: make_dict_for_runtimes(6.0, 6.0, 8.0), 
   STATE_RUNNING_FB: make_dict_for_runtimes(0.1, 2.0, 10.0), 
   STATE_CHECKING_NICS: make_dict_for_runtimes(10.0), 
   STATE_VSWITCH_DONE: make_dict_for_runtimes(1.0), 
   STATE_CREATE_PARTITIONS: make_dict_for_runtimes(2.0), 
   STATE_FIRST_HOST_REBOOT: make_dict_for_runtimes(6.0), 
   STATE_FIRST_REBOOT_HYPERV: make_dict_for_runtimes(0.0, 0.0, 6.0), 
   STATE_CREATE_CVM: make_dict_for_runtimes(1.0, 1.0, 1.0), 
   STATE_CVM_FB: make_dict_for_runtimes(0.1, 3.0, 4.0), 
   STATE_LAST_REBOOT: make_dict_for_runtimes(0.1, 6.0, 6.0)}
ALWAYS_NEEDED = lambda x: True
STATUS_IN_EXPECTED_ORDER = [
 (
  STATE_STARTING_PHOENIX, ALWAYS_NEEDED),
 (
  STATE_DOWNLOAD_NOS, lambda x: bool(x.svm_install_type)),
 (
  STATE_DOWNLOAD_HYP, ALWAYS_NEEDED),
 (
  STATE_DOWNLOAD_SLOW, ALWAYS_NEEDED),
 (
  STATE_RUNNING_PHOENIX, ALWAYS_NEEDED),
 (
  STATE_FIRMWARE_DETECTION, ALWAYS_NEEDED),
 (
  STATE_REBOOT_INTO_HYP, ALWAYS_NEEDED),
 (
  STATE_RUNNING_FB, ALWAYS_NEEDED),
 (
  STATE_CHECKING_NICS, lambda x: x.hyp_type == 'esx'),
 (
  STATE_VSWITCH_DONE, lambda x: x.hyp_type == 'esx'),
 (
  STATE_CREATE_PARTITIONS, lambda x: x.hyp_type == 'esx'),
 (
  STATE_FIRST_HOST_REBOOT, lambda x: x.hyp_type == 'esx'),
 (
  STATE_FIRST_REBOOT_HYPERV, lambda x: x.hyp_type == 'hyperv'),
 (
  STATE_CREATE_CVM, ALWAYS_NEEDED),
 (
  STATE_CVM_FB, lambda x: bool(x.svm_install_type)),
 (
  STATE_LAST_REBOOT, ALWAYS_NEEDED)]
DOWNLOAD_TIMEOUT_S = 900
INSTALLATION_TIMEOUT_S = 5400
FACTORY_TIMEOUT = 2400
MAX_BOOT_WAIT_CYCLES = 90
CHECK_INTERVAL_S = 10
MAX_SSH_RETRIES = 10
HTTP_SERVER_THREADS = 10
CONCURRENT_DOWNLOAD_LIMIT = int(HTTP_SERVER_THREADS / 2) - 1
DOWNLOADING_SEMA = threading.Semaphore(CONCURRENT_DOWNLOAD_LIMIT)
cd_image_lock = threading.Lock()
PHOENIX_DL_HB_S = 30

class ImagingStepPhoenix(ImagingStepNodeTask):

    def get_finished_message(self):
        return STATE_DONE_FRIENDLY

    def get_progress_timing(self):
        states = []
        hyp = self.config.hyp_type
        for state, func in STATUS_IN_EXPECTED_ORDER:
            if func(self.config):
                states.append((state, ESTIMATED_RUN_TIMES[state][hyp]))

        return states

    def _prep_phoenix(self):
        node_config = self.config
        if not getattr(node_config, 'foundation_payload', None):
            node_config.foundation_payload = node_config._cache.get(phoenix_prep.generate_foundation_payload_if_necessary, node_config.nos_package)
        phoenix_prep.make_json_for_node(node_config)
        return

    def ssh(self, node_config, command, throw_on_error=True, timeout=60, retries=MAX_SSH_RETRIES):
        phoenix_ip = node_config.phoenix_ip
        for i in range(retries + 1):
            out, err, ret = foundation_tools.ssh(node_config, phoenix_ip, command, throw_on_error=False, user='root', password='nutanix/4u', timeout=timeout)
            if not ret:
                return (out, err, ret)
            time.sleep(CHECK_INTERVAL_S)
        else:
            if throw_on_error:
                raise StandardError("Command '%s' failed. " % (' ').join(command), 'The stdout, stderr are: \n', 'stdout:\n%s' % out, 'stderr:\n%s' % err)
            return (out, err, ret)

    def on_failed(self, exception):
        self.set_fatal_event(str(exception))

    def cb_slow_network(self, event):
        self.logger.warn('It seems this imaging is over a network slower than 1G.Foundation will proceed but the overall imaging time might be longer than expected')
        self.set_status(STATE_DOWNLOAD_SLOW)

    @persist_config_on_failure
    def run(self):
        node_config = self.config
        logger = self.logger
        is_unit = getattr(self.config, 'is_unit', False)
        if not node_config.image_now:
            logger.info('%s skipped', __name__)
            return
        self.set_status(STATE_STARTING_PHOENIX)
        if not is_unit:
            logger.info('Making node specific Phoenix json. This may take few minutes')
            with cd_image_lock:
                self._prep_phoenix()
        if not is_unit:
            for i in range(MAX_BOOT_WAIT_CYCLES):
                stdout, stderr, retval = self.ssh(node_config, ['true'], throw_on_error=False)
                if retval == 0:
                    break
                logger.info('[%s/%s] Waiting for Phoenix' % (i, MAX_BOOT_WAIT_CYCLES))
                time.sleep(CHECK_INTERVAL_S)
            else:
                raise StandardError('Failed to connect to Phoenix at %s' % node_config.phoenix_ip)

            time.sleep(10)
            args = []
            if getattr(node_config, 'booted_into_phoenix_manually', False) or node_config.type == CLASS_PXE:
                args.append('AZ_CONF_URL=%s' % node_config.arizona_loc)
                self.ssh(node_config, ['rm', '/tmp/bg_installer.lock'], throw_on_error=False, retries=0)
            _, _, retval = self.ssh(node_config, ['test', '-f', '/tmp/fatal_marker'], throw_on_error=False, retries=0)
            if retval == 0:
                logger.info('A previous Phoenix failure detected. Clearing temp files')
                self.ssh(node_config, ['rm -rf', '/tmp'], throw_on_error=False)
                self.ssh(node_config, ['mkdir', '/tmp'], throw_on_error=False)
                self.ssh(node_config, ['touch', '/tmp/fatal_marker'], throw_on_error=False)
            logger.info('Start downloading resources, this may take several minutes')
            if features.is_enabled(features.CENTOS):
                bg_path = '/root/bg_installer.sh'
            else:
                bg_path = '/bg_installer.sh'
            with DOWNLOADING_SEMA:
                stdout, stderr, retval = self.ssh(node_config, [
                 '/bin/sh', bg_path] + args, throw_on_error=True)
                if retval != 0 or 'OK' not in stdout:
                    raise StandardError('Failed to start CVM installation at %s' % node_config.phoenix_ip)
                logger.info('Waiting for Phoenix to finish downloading resources')
                try:
                    self.wait_for_event(STATE_RUNNING_PHOENIX, DOWNLOAD_TIMEOUT_S, hb_timeout=PHOENIX_DL_HB_S, hb_callback=self.cb_slow_network)
                except StandardError:
                    logger.warning('Foundation timed out waiting for phoenix to download resources. Fataling other imaging steps which are waiting')
                    raise

        timeout = FACTORY_TIMEOUT if factory_mode() else INSTALLATION_TIMEOUT_S
        self.wait_for_event(STATE_REBOOT_INTO_HYP, timeout)
        last_reboot_timeout = INSTALLATION_TIMEOUT_S
        if factory_mode():
            last_reboot_timeout = FACTORY_TIMEOUT
            if node_config.hyp_type == 'hyperv':
                last_reboot_timeout *= 2
        self.wait_for_event(STATE_LAST_REBOOT, last_reboot_timeout)
        if getattr(node_config, 'compute_only', False):
            src_ip, user, prefix = node_config.hypervisor_ip, 'root', '/root/'
        else:
            src_ip, user, prefix = node_config.cvm_ip, 'nutanix', '/etc/nutanix/'
        command = [
         'cat', os.path.join(prefix, 'factory_config.json')]
        out, err, ret = foundation_tools.ssh(node_config, src_ip, command, throw_on_error=False, user=user, password='nutanix/4u', timeout=10)
        if ret:
            error_message = 'Foundation could not read the factory_config.json from the CVM. The stdout is\n%s\nand stderr is\n%s'
            error_message = error_message % (out, err)
            logger.error(error_message)
        else:
            node_id = node_config.node_id
            log_path = '%s/factory_config_node_%s.json' % (
             folder_central.get_session_log_folder(node_config._session_id), node_id)
            with open(log_path, 'w') as (fd):
                fd.write(out)
        if getattr(node_config, 'timezone', None):
            ret, err = foundation_tools.set_timezone(node_config, node_config.timezone)
            if not ret:
                logger.error('Failed to set timezone, error: %s' % err)
            else:
                logger.info('Timezone %s set successfully' % node_config.timezone)
        config_persistence.post_imaging_result(node_config.node_id, True)
        return