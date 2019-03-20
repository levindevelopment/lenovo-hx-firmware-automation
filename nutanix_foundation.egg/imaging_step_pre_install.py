# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_pre_install.py
# Compiled at: 2019-02-15 12:42:10
import json, os, re, threading, time
from operator import itemgetter
import features, folder_central, foundation_tools, factory_mode, iso_whitelist, phoenix_prep, parameter_validation as pv, shared_functions
from consts import ARCH_PPC
from decorators import persist_config_on_failure
from imaging_step import ImagingStepNodeTask
from imaging_step_type_detection import CLASS_UCSM, CLASS_CIMC
from remote_boot_cimc import CiscoCIMC
from remote_boot_ucsm import CiscoUCSM
STATE_PHOENIX_ISO = 'Pre-processing Acropolis base software'
STATE_PHOENIX_ISO_DONE = 'Pre-processing Acropolis base software done'
STATE_GETTING_RESOURCE_LOCK = 'Getting ready to run sanity tests'
STATE_GOT_RESOURCE_LOCK = 'Preparing staging environment'
STATE_WAIT_FOR_PHOENIX = 'Rebooting into staging environment'
STATE_PRE_INSTALL_ACTIONS = 'Running pre-install sanity tests'
STATE_PRE_INSTALL_DONE = 'Pre-install sanity tests complete'
INSTALLATION_TIMEOUT_S = 3600
NODES_ALLOWED = 20
IMAGING_SEMA = threading.Semaphore(NODES_ALLOWED)
MAX_BOOT_WAIT_CYCLES = 90
CHECK_INTERVAL_S = 10
MAX_SSH_RETRIES = 10
IPMICFG = '/usr/bin/ipmicfg-linux.x86_64'
BLOCK_SERIAL_RE = re.compile('Product Serial\\s+:\\s+(\\S+)')
IBM_BLOCK_SERIAL_RE = re.compile('Chassis Serial\\s+:\\s+(\\S+)')
UCS_REF_PHOENIX_PATH = '/phoenix/hardware_pre_checks/ucs/updates'
CRYSTAL_REF_PHOENIX_PATH = '/phoenix/hardware_pre_checks/crystal/updates'

class ImagingStepPreInstall(ImagingStepNodeTask):

    def get_finished_message(self):
        return STATE_PRE_INSTALL_DONE

    def get_progress_timing(self):
        return [
         (
          STATE_WAIT_FOR_PHOENIX, 1.0),
         (
          STATE_PRE_INSTALL_ACTIONS, 4.0)]

    def ssh(self, node_config, command, throw_on_error=True, log_on_error=True, timeout=60, retries=MAX_SSH_RETRIES, escape_cmd=False):
        ip = node_config.phoenix_ip
        for i in range(retries):
            out, err, ret = foundation_tools.ssh(node_config, ip, command, throw_on_error=False, log_on_error=log_on_error, user='root', password='nutanix/4u', timeout=timeout, escape_cmd=escape_cmd)
            if not ret:
                return (out, err, ret)
            if i < retries - 1:
                time.sleep(CHECK_INTERVAL_S)
        else:
            if throw_on_error:
                raise StandardError("Command '%s' failed. " % (' ').join(command), 'The stdout, stderr are: \n', 'stdout:\n%s' % out, 'stderr:\n%s' % err)
            return (out, err, ret)

    def _log_system_info(self, node_config):
        node_id = node_config.node_id
        log_path = os.path.join(folder_central.get_log_folder(), node_config._session_id, 'node_%s.manifest' % node_id)
        timeout = 10
        try:
            if node_config.hardware_config['chassis']['class'] in ('IMM2', 'TSMM'):
                timeout = 45
        except AttributeError:
            timeout = 45

        with open(log_path, 'w') as (f):
            for cmd in [['timeout', str(timeout), 'ipmitool', 'fru'], ['timeout', str(timeout), 'ipmitool', 'mc', 'info'],
             [
              'timeout', str(timeout), 'ipmitool', 'sdr'],
             [
              'timeout', str(timeout), 'dmidecode'],
             [
              'timeout', str(timeout), 'lspci', '-nn'],
             [
              'timeout', str(timeout), 'lsscsi'],
             [
              'timeout', str(timeout), 'lsscsi', '--hosts'],
             [
              'timeout', str(timeout), 'cat /proc/meminfo']]:
                stdout, stderr, retval = self.ssh(node_config, cmd, throw_on_error=False, log_on_error=False, timeout=timeout + 10)
                f.write("Command: '%s' = %d\n" % ((' ').join(cmd), retval))
                f.write('----\n')
                if retval:
                    f.write(stderr)
                f.write(stdout)
                f.write('*' * 75 + '\n')

    def check_sed_disk(self):
        """
        Check the number of SED disks, to extend some timeouts in foundation.
        """
        node_config = self.config
        node_config.sed_count = 0
        logger = self.logger
        cmd = ['python', '/phoenix/find_sed.py']
        stdout, stderr, retval = self.ssh(node_config, cmd, throw_on_error=False, log_on_error=True, timeout=60)
        if not retval:
            logger.debug('Failed to detect number of SED')
        else:
            if stdout.strip():
                sed_str = (',').join(stdout.splitlines())
                logger.info('Detected the following SEDs: %s', sed_str)
                node_config.sed_count = len(stdout.splitlines())
            else:
                logger.debug('No SED detected')

    def get_ucs_firmware_versions_from_template(self):
        """
        Returns the cimc and sd card firmware version details from ucs template.
        """
        ucsm_template_file = folder_central.get_ucsm_profile_template()
        template = json.load(open(ucsm_template_file))
        if 'last_updated' not in template:
            raise StandardError('Invalid template file: %s' % ucsm_template_file)
        if not template.get('ucsm_firmware'):
            return None
        return template['ucsm_firmware']

    def verify_ucs_managed_firmware(self):
        """
        Verifies the firmware versions for a managed node.
        """
        if not all([self.config.ucsm_managed_mode,
         getattr(self.config, 'type', None) == CLASS_UCSM]):
            return
        node_config = self.config
        fw_template = self.get_ucs_firmware_versions_from_template()
        if not fw_template:
            return
        ucsm = CiscoUCSM(node_config.ucsm_ip, node_config.ucsm_user, node_config.ucsm_password)
        ucsm.login()
        server = node_config.ucsm_node_serial
        cimc_version_req = fw_template.get('cimc')
        sd_card_version_req = fw_template.get('sd_card')
        cimc_version = ucsm.get_cimc_version(server)
        sd_card_version = None
        if ucsm.has_flexflash_drive(server):
            sd_card_version = ucsm.get_flexflash_firmware(server)
        self.verify_ucs_firmware_version(cimc_version, cimc_version_req, sd_card_version, sd_card_version_req)
        return

    def verify_ucs_standalone_firmware(self):
        """
        Verifies the firmware versions for a standalone UCS node.
        """
        if not getattr(self.config, 'type', None) == CLASS_CIMC:
            return
        node_config = self.config
        fw_template = self.get_ucs_firmware_versions_from_template()
        if not fw_template:
            return
        cimc = CiscoCIMC(node_config.ipmi_ip, node_config.ipmi_user, node_config.ipmi_password)
        cimc.login()
        cimc_version_req = fw_template.get('cimc')
        sd_card_version_req = fw_template.get('sd_card')
        cimc_version = cimc.get_cimc_version()
        sd_card_version = cimc.get_flexflash_firmware()
        self.verify_ucs_firmware_version(cimc_version, cimc_version_req, sd_card_version, sd_card_version_req)
        return

    def verify_ucs_firmware_version(self, cimc_version_cur, cimc_version_req, sd_card_version_cur, sd_card_version_req):
        """
        Validates the current cimc and sd card firmware versions against the
        expected version.
        Args:
          cimc_version_cur: Current cimc firmware version of the node.
          cimc_version_req: List of supported cimc firmware versions.
          sd_card_version_cur: Current sd card firmware version of the node.
          sd_card_version_req: List of supported sd card firmware versions.
        
        Returns:
          None
        """
        logger = self.logger
        if cimc_version_req:
            if cimc_version_cur not in cimc_version_req:
                logger.warning('Supported cimc firmware versions are %s. But current firmware version is %s' % (
                 cimc_version_req, cimc_version_cur))
        if sd_card_version_cur and sd_card_version_req:
            if sd_card_version_cur not in sd_card_version_req:
                logger.warning('Supported sd card firmware versions are %s. But current firmware version is %s' % (
                 sd_card_version_req, sd_card_version_cur))

    def copy_platform_reference(self, plat_type):
        """
        Copies platform_reference.json from Foundation to Phoenix for UCS or
        Crystal nodes. Phoenix will override the actual file with this file during
        the execution of minimum_reqs.py.
        """
        logger = self.logger
        if plat_type not in ('CISCO', 'CRYSTAL'):
            logger.warning('Unsupported platform type: %s. Not copying the platform reference file.' % plat_type)
            return
        ref = None
        if plat_type == 'CISCO':
            path = UCS_REF_PHOENIX_PATH
            if not any([self.config.ucsm_managed_mode,
             getattr(self.config, 'type', None) == CLASS_UCSM,
             getattr(self.config, 'type', None) == CLASS_CIMC]):
                return
            ref = folder_central.get_ucs_platform_reference()
            if not os.path.exists(ref):
                logger.error('UCS platform_reference.json file is not found at %s. Skipping override' % ref)
                return
        else:
            if plat_type == 'CRYSTAL':
                path = CRYSTAL_REF_PHOENIX_PATH
                ref = folder_central.get_crystal_platform_reference()
                if not os.path.exists(ref):
                    logger.error("Crystal's crystal_plat_reference.json file is not found at %s. Skipping override" % ref)
                    return
        for _ in range(MAX_SSH_RETRIES):
            out, err, ret = foundation_tools.ssh(self.config, self.config.phoenix_ip, ['mkdir', '-p', path], throw_on_error=False, user='root')
            if ret:
                logger.warning('Failed to create updates folder %s in phoenix' % path)
                continue
            out, err, ret = foundation_tools.scp(self.config, self.config.phoenix_ip, path, [ref], throw_on_error=False, log_on_error=True, user='root')
            if not ret:
                logger.info('Copied %s to phoenix at ip %s' % (
                 ref, self.config.phoenix_ip))
                return
        else:
            logger.warning('Failed to copy the %s to phoenix. Skipping override' % ref)

        return

    def validate_ucs_firmware(self):
        """
        Validates ucs firmware versions.
        """
        self.verify_ucs_standalone_firmware()
        self.verify_ucs_managed_firmware()
        self.copy_platform_reference('CISCO')

    def check_minimum_requirements(self, node_config):
        minimum_reqs_cmd = [
         '/usr/bin/python', '/phoenix/minimum_reqs.py',
         'hyp_type=%s' % node_config.hyp_type]
        if hasattr(node_config, 'nos_version'):
            minimum_reqs_cmd.append('nos_version=%s' % self.config.nos_version)
        if getattr(node_config, 'hardware_attributes_override', {}):
            hw_attrs = re.escape(json.dumps(node_config.hardware_attributes_override, separators=(',',
                                                                                                  ':')))
            minimum_reqs_cmd.append('hardware_attributes_override=%s' % hw_attrs)
        if getattr(node_config, 'exclude_boot_serial', None):
            minimum_reqs_cmd.append('exclude_boot_serial=%s' % node_config.exclude_boot_serial)
        self.ssh(node_config, minimum_reqs_cmd, throw_on_error=True, timeout=180, retries=3, escape_cmd=True)
        return

    @persist_config_on_failure
    def run(self):
        node_config = self.config
        logger = self.logger
        if not self.config.image_now:
            logger.info('%s skipped', __name__)
            return
        logger.info(STATE_WAIT_FOR_PHOENIX)
        self.set_status(STATE_WAIT_FOR_PHOENIX)
        for _ in range(MAX_BOOT_WAIT_CYCLES):
            if foundation_tools.in_phoenix(node_config, log_on_error=True, timeout=60):
                break
            time.sleep(CHECK_INTERVAL_S)
        else:
            raise StandardError('Failed to connect to Phoenix at %s' % node_config.phoenix_ip)

        self.set_status(STATE_PRE_INSTALL_ACTIONS)
        node_config.incoming_nos_package = node_config.nos_package
        nos_package = node_config.nos_package
        if nos_package:
            node_config.nos_version = node_config._cache.get(shared_functions.get_nos_version_from_tarball, nos_package)
            node_config.svm_version = node_config.nos_version
            logger.info('NOS version is %s', node_config.nos_version)
        logger.info('Preparing NOS package (%s)', nos_package)
        phoenix_prep.prep_image(node_config)
        foundation_tools.record_system_information(node_config)
        hardware_config = foundation_tools.read_hardware_config_from_phoenix(node_config)
        if not hardware_config:
            self._log_system_info(node_config)
            raise StandardError("Couldn't figure out what platform %s is. Either foundation can't reach it over the network or the system doesn't match foundation's expectations. log/node_%s.manifest contains more diagnostic information." % (
             node_config.phoenix_ip,
             node_config.node_id))
        node_config.hardware_config = hardware_config
        session_id = node_config._session_id
        foundation_tools.update_metadata({'hardware_config': node_config.hardware_config}, session_id)
        if node_config.hyp_type in node_config.md5sum_hyp_iso:
            md5sum = node_config.md5sum_hyp_iso[node_config.hyp_type]
            node_model = str(node_config.hardware_config['node']['model_string'])
            if not pv.does_hypervisor_support_nodemodel(md5sum, node_model):
                raise StandardError('Installer iso (%s, %s) with md5sum %s is not supported on %s' % (
                 node_config.hyp_type.upper(),
                 iso_whitelist.whitelist['iso_whitelist'][md5sum]['version'],
                 md5sum, node_model))
        if node_config.hardware_config['chassis']['class'] == 'IDRAC7' and node_config.hyp_type == 'hyperv' and node_config.hyperv_sku == 'free':
            raise StandardError("Dell nodes can't be imaged with HyperV and SKU as free")
        node = node_config.hardware_config['node']
        hw_attr = node.get('hardware_attributes')
        if hw_attr and 'is_xpress_node' in hw_attr and hw_attr['is_xpress_node']:
            logger.info('Node belongs to Xpress platform')
        if node_config.arch == ARCH_PPC and node_config.hyp_type != 'kvm':
            raise StandardError('PPC nodes can be imaged only with AHV')
        boot_config = node.get('boot_device')
        if boot_config:
            exclude_boot_serial_args = []
            exclude_boot_serial = getattr(node_config, 'exclude_boot_serial', None)
            if exclude_boot_serial:
                exclude_boot_serial_args = [
                 '--exclude_boot_serial',
                 exclude_boot_serial]
            stdout, stderr, retval = self.ssh(node_config, [
             '/usr/bin/python', '/phoenix/layout_tools.py',
             'hardware_config.json', 'wwn'] + exclude_boot_serial_args, True)
            result = stdout.strip()
            if result == 'None':
                logger.info('Boot device has no WWN')
            else:
                node_config.boot_device_wwn = stdout.strip()
                logger.info('Boot device WWN: %s' % node_config.boot_device_wwn)
            stdout, stderr, retval = self.ssh(node_config, [
             '/usr/bin/python',
             '/phoenix/layout_tools.py',
             'hardware_config.json', 'serial'] + exclude_boot_serial_args, True)
            node_config.boot_device_serial = stdout.strip()
            logger.info('Boot device serial: %s' % node_config.boot_device_serial)
            self.validate_ucs_firmware()
            self.copy_platform_reference('CRYSTAL')
            self.check_minimum_requirements(node_config)
            stdout, stderr, retval = self.ssh(node_config, [
             '/bin/cat', '/active_nic/address'], throw_on_error=False, retries=1)
            if retval == 0:
                result = stdout.strip()
                node_config.hypervisor_mac = result
            cmd = [
             'cat', '/tmp/online_interfaces']
            out, err, ret = self.ssh(node_config, cmd, throw_on_error=False, retries=1)
            if ret == 0:
                interfaces = [ x.split(' ') for x in out.strip().splitlines() ]
                interfaces = [ [x[0], int(x[1])] for x in interfaces ]
                interfaces = sorted(interfaces, key=itemgetter(1), reverse=True)
                interface = interfaces[0][0]
                cmd = ['ethtool', '-i', interface]
                out, err, ret = self.ssh(node_config, cmd, throw_on_error=True)
                out = [ line.strip() for line in out.splitlines() if 'bus-info' in line
                      ][0]
                bus_info = out.split(':', 2)[2].replace('.', ':')
                node_config.bus_info_for_nic_teaming = bus_info
                logger.info('NIC with PCI address %s will be used for NIC teaming if default teaming fails' % bus_info)
            in_factory_mode = factory_mode.factory_mode()
            is_gold_node = 'gold' in getattr(node_config, 'block_id', '').lower() or 'gold' in getattr(node_config, 'node_serial', '').lower()
            logger.info('This node is%s a gold node', '' if is_gold_node else ' not')
            if not (in_factory_mode and is_gold_node):
                system_block_id = None
                stdout, stderr, retval = self.ssh(node_config, [
                 IPMICFG, '-tp', 'info'], throw_on_error=False, retries=1)
                if retval == 0 and stdout:
                    sn = re.findall('System S/N\\s+:\\s+(\\S+)', stdout)
                    if sn:
                        system_block_id = sn[0]
                if system_block_id:
                    if not foundation_tools.is_valid_block_id(system_block_id):
                        raise StandardError("Block id can only contain alphanumeric characters, '_' and '-'. block_id %s obtained from ipmicfg systemsn is invalid" % system_block_id)
                    if not getattr(node_config, 'block_id', None):
                        node_config.block_id = system_block_id
                    if in_factory_mode:
                        if system_block_id.lower() == node_config.block_id.lower():
                            logger.info('Backplane reported matching block ID; check passed')
                        else:
                            raise StandardError('Backplane reported chassis serial %s rather than expected serial %s' % (
                             system_block_id, node_config.block_id))
                    elif not system_block_id.lower() == node_config.block_id.lower():
                        logger.info('The backplane gave chassis serial %s, which we will use to replace parameter %s. This is okay.' % (
                         system_block_id, node_config.block_id))
                        node_config.block_id = system_block_id
                else:
                    if in_factory_mode:
                        stdout, stderr, retval = foundation_tools.ipmitool(node_config, [
                         'fru'], throw_on_error=True)
                        block_serial_match = BLOCK_SERIAL_RE.search(stdout)
                        if factory_mode.is_ibm():
                            block_serial_match = IBM_BLOCK_SERIAL_RE.search(stdout)
                        fru_block_serial = block_serial_match.groups()[0].strip().lower()
                        if not fru_block_serial == node_config.block_id.lower():
                            raise StandardError('FRU reported chassis serial %s rather than expected serial %s' % (
                             fru_block_serial, node_config.block_id))
                        else:
                            logger.info('FRU reported matching block ID; check passed.')
                stdout, stderr, retval = self.ssh(node_config, [IPMICFG, '-tp', 'nodeid'], throw_on_error=False, retries=1)
                if retval == 0 and stdout:
                    stdout = stdout.strip()[0]
                    system_node_position = stdout
                    if stdout.isdigit():
                        system_node_position = chr(ord('A') + int(stdout) - 1)
                    if in_factory_mode:
                        if system_node_position == node_config.node_position:
                            logger.info('Node position check passed for node %s' % node_config.node_position)
                        else:
                            raise StandardError('Backplane reported node position %s rather than expected position %s. Please scan nodes in the correct order and retry imaging' % (
                             system_node_position,
                             node_config.node_position))
                    if not system_node_position == node_config.node_position:
                        logger.info('The backplane gave node id %s, which we will use to replace parameter %s. This is okay' % (
                         system_node_position, node_config.node_position))
                        setattr(node_config, 'node_position', system_node_position)
                    logger.info('Node position is %s', node_config.node_position)
                elif in_factory_mode:
                    if factory_mode.is_ibm():
                        logger.info('Using node positon from UI for IBM node: %s.', node_config.node_position)
                    elif 'Not TwinPro' in stdout or 'Not TwinPro' in stderr:
                        logger.info("Can't get node position from the backplane on non TwinPro systems. Skipping node position check.")
                    else:
                        raise StandardError('Unable to get node position from backplane on what appears to be a TwinPro system. The node position request failed with exit code %s:\nStdout: %s\nStderr: %s' % (
                         retval, stdout, stderr))
            else:
                logger.info('Skipping block id and node position check because block %s is gold.' % node_config.block_id)
        return