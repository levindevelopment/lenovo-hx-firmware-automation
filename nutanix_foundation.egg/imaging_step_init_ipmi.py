# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_init_ipmi.py
# Compiled at: 2019-02-15 12:42:10
import os, threading, time, foundation_tools as tools, imaging_step, imaging_step_type_detection, ipmi_config, phoenix_prep, remote_boot
from foundation import shared_functions
from foundation.config_manager import EventTimeoutException
from foundation.decorators import persist_config_on_failure
from foundation.imaging_step_type_detection import CLASS_VM_INSTALLER
EVENT_IN_PHOENIX = 'phoenix_callback'
STATE_PREPARE = 'Preparing installer image'
STATE_POWER_OFF = 'Poweroff machine'
STATE_MOUNT_ISO = 'Mounting installer media'
STATE_WAIT_FOR_PHOENIX = 'Waiting for installer to boot up'
STATE_INIT_COMPLETE = 'Booted into installer successfully'
INSTALLATION_TIMEOUT_S = 3600
MAX_BOOT_TIMEOUT_S = 1200
MAX_BOOT_RETRY = 1
CHECK_INTERVAL_S = 15
MAX_SSH_RETRIES = 10
NODES_ALLOWED = 20
IMAGING_SEMA = threading.Semaphore(NODES_ALLOWED)

class ImagingStepInitIPMI(imaging_step.ImagingStepNodeTask):
    """
    Boots up a node using IPMI
    """

    def get_progress_timing(self):
        return [
         (
          STATE_PREPARE, 1),
         (
          STATE_POWER_OFF, 1),
         (
          STATE_MOUNT_ISO, 1),
         (
          STATE_WAIT_FOR_PHOENIX, 7)]

    def get_finished_message(self):
        return STATE_INIT_COMPLETE

    def _will_run(self):
        logger = self.logger
        node_config = self.config
        if not node_config.image_now:
            logger.info('skipped, image_now is False')
            return False
        if self.config.type == CLASS_VM_INSTALLER:
            logger.debug('skipped, this node will be imaged via CVM')
            return False
        return True

    @persist_config_on_failure
    def run(self):
        logger = self.logger
        node_config = self.config
        if not self._will_run():
            return
        self.set_status(STATE_PREPARE)
        logger.info('Making node specific Phoenix image')
        phoenix_prep.make_phoenix_for_node(node_config)
        remote = None
        with IMAGING_SEMA:
            try:
                remote = remote_boot.new_remote_boot_instance(node_config)
                if node_config.type == imaging_step_type_detection.CLASS_CIMC:
                    self.pre_boot_cisco_operations(node_config, remote)
                if node_config.type == imaging_step_type_detection.CLASS_ILO:
                    remote.pre_boot_bios_settings()
                self.set_status(STATE_POWER_OFF)
                remote.set_first_boot_device()
                logger.info('Powering off node')
                remote.poweroff()
                time.sleep(5)
                logger.info('Mounting phoenix iso image')
                self.set_status(STATE_MOUNT_ISO)
                remote.boot(node_config.phoenix_iso, do_reset=True)
                self.set_status(STATE_WAIT_FOR_PHOENIX)
                in_phoenix = False
                attempt = 0
                while attempt <= MAX_BOOT_RETRY:
                    logger.info('Waiting for remote node to boot into phoenix, this may take %s minutes' % (MAX_BOOT_TIMEOUT_S / 60))
                    if node_config.type == imaging_step_type_detection.CLASS_PXE:
                        intervals = MAX_BOOT_TIMEOUT_S / CHECK_INTERVAL_S
                        for i in range(intervals):
                            if self.configure_pxe_node(node_config):
                                break
                            try:
                                self.wait_for_event(EVENT_IN_PHOENIX, timeout=CHECK_INTERVAL_S)
                            except EventTimeoutException:
                                pass

                    else:
                        try:
                            self.wait_for_event(EVENT_IN_PHOENIX, timeout=MAX_BOOT_TIMEOUT_S)
                        except EventTimeoutException:
                            pass

                    if tools.in_phoenix(node_config, log_on_error=True):
                        break
                    else:
                        logger.warn('The target is not ssh-able or not in phoenix')
                        attempt += 1
                        if attempt <= MAX_BOOT_RETRY:
                            try:
                                remote.retry_boot_from_iso(node_config.phoenix_iso)
                                logger.warn('Retrying booting into phoenix')
                            except NotImplementedError:
                                logger.warn('Retry logic is NotImplemented for this platform')
                                attempt = MAX_BOOT_RETRY + 1

                    if in_phoenix:
                        break
                else:
                    raise StandardError('Failed to connect to Phoenix at %s' % node_config.phoenix_ip)

                logger.info('Rebooted into Phoenix successfully')
            finally:
                if remote:
                    remote.stop()
                if node_config.phoenix_iso and os.path.exists(node_config.phoenix_iso):
                    os.unlink(node_config.phoenix_iso)

        return

    def ssh(self, node_config, command, throw_on_error=True, log_on_error=True, timeout=None, use_ipv6=False):
        ip = node_config.phoenix_ip
        if use_ipv6:
            ip = node_config.ipv6_addr
        return tools.ssh(config=node_config, ip=ip, command=command, throw_on_error=throw_on_error, log_on_error=log_on_error, user='root', password='nutanix/4u', timeout=timeout)

    def pre_boot_cisco_operations(self, node_config, remote):
        """
        On Cisco standalone nodes, set SATA port to AHCI mode in BIOS and expose
        SD card to host.
        
        Args:
          node_config: NodeConfig object for the node.
          remote: RemoteBoot object for the node.
        
        Returns:
          None
        """
        logger = self.logger
        try:
            bios_config = {'vpSataModeSelect': 'AHCI', 'vpPCIOptionROMs': 'Disabled'}
            remote.set_bios_config(bios_config=bios_config)
        except:
            logger.exception('Failed to set BIOS config: %s. Ignoring failure' % bios_config)
        else:
            try:
                remote.enable_flexflash_virtualdrive()
                remote.sync_flexflash_virtualdrive()
            except:
                logger.exception('Failed to enable flex flash drive and sync option. Ignoring failure')

    def discover_pxe_node(self, node_config):
        """
          Using NDP discovery to discover the nodes.
          Set link local ipv6_address for discovered nodes.
        
          Args:
            node_config: NodeConfig object for the node.
        
          Returns:
            True if node is discovered, False otherwise
        """
        logger = self.logger
        logger.debug('Trying to discover node using CVM NDP node discovery')
        result = ipmi_config.discover_nodes()
        for block in result:
            for node in block['nodes']:
                if node['hypervisor'] == 'phoenix' and 'ipmi_mac' in node and node['ipmi_mac'] and node['ipmi_mac'].lower() == node_config.ipmi_mac.lower():
                    foundation_version = tools.read_foundation_version()
                    if foundation_version == shared_functions.MASTER_VERSION:
                        foundation_version = 'master'
                    phoenix_version = 'phoenix-%s' % foundation_version
                    if phoenix_version not in node['hypervisor_version']:
                        msg = 'Node should be PXE booted into phoenix with version %s (but it was %s)' % (
                         foundation_version, node['hypervisor_version'])
                        if foundation_version == 'master':
                            logger.warn(msg)
                        else:
                            raise StandardError(msg)
                    node_config.ipv6_addr = node['ipv6_address']
                    return True

        return False

    def configure_pxe_node(self, node_config):
        """
          Configure static phoenix ip on these nodes.
        
          Args:
            node_config: NodeConfig object for the node.
        
          Returns:
            None
        """
        logger = self.logger
        found = self.discover_pxe_node(node_config)
        if found:
            logger.info('Found PXE booted node with ipmi MAC address %s' % node_config.ipmi_mac)
            logger.info('Configuring IP %s for PXE booted phoenix' % node_config.phoenix_ip)
            _, _, _ = self.ssh(node_config, [
             'VLAN=%s' % getattr(node_config, 'cvm_vlan_id', ''),
             'PHOENIX_IP=%s' % node_config.phoenix_ip,
             'MASK=%s' % node_config.cvm_netmask,
             'GATEWAY=%s' % node_config.cvm_gateway,
             'FOUND_IP=%s' % node_config.foundation_ip,
             '/bin/sh', '/set_static_ip.sh'], use_ipv6=True)
        return found