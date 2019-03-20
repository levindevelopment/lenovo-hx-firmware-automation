# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_xen.py
# Compiled at: 2019-02-15 12:42:10
import json, time, foundation_tools as tools
from foundation.imaging_step import ImagingStepNodeTask
MASTER_WAIT_LIMIT = 1200
CVM_POWEROFF_LIMIT = 60
POOL_JOIN_LIMIT = 600
CVM_POWERON_LIMIT = 300
CVM_VIF_RETRY = 6
CVM_NETWORK_LIMIT = 600
TICK = 5
STATE_WAITING_MASTER = 'Waiting for Xenserver'
STATE_RUNNING = 'Joining Xenserver pool'
STATE_WAITING_CVM = 'Waiting for CVM up in Xenserver pool'
STATE_DONE = 'XenServer pool joined'
BOND_DESC = 'Nutanix-Bond'
NTNX_CVM_MD = 'cvm.md'
CVM_EXPORT = '/var/lib/xcp/xenopsd_md/' + NTNX_CVM_MD
SYSTEMD_SERVICE = 'nutanix-cvm.service'

class ImagingStepXenJoinPool(ImagingStepNodeTask):

    @classmethod
    def is_compatible(cls, config):
        """
        This step should only run for xen master or slave nodes.
        """
        return getattr(config, 'is_xs_master', False) or getattr(config, 'is_xs_slave', False)

    def get_progress_timing(self):
        return [
         (
          STATE_WAITING_MASTER, 10),
         (
          STATE_RUNNING, 1),
         (
          STATE_WAITING_CVM, 10)]

    def get_finished_message(self):
        return STATE_DONE

    def _ssh_cvm(self, command):
        config = self.config
        return tools.ssh(config, config.cvm_ip, command, throw_on_error=False, log_on_error=True)

    def _ssh_host(self, command):
        config = self.config
        return tools.ssh(config, config.hypervisor_ip, command, user='root', throw_on_error=False, log_on_error=True, timeout=20)

    def _ssh_master(self, command):
        config = self.config
        return tools.ssh(config, config.xs_master_ip, command, user=self.xs_master_username, password=self.xs_master_password, throw_on_error=False, log_on_error=True, timeout=20)

    def _xe_cmd(self, ssh_func, cmd, error_msg=None, retry=0):
        for _ in xrange(retry + 1):
            result, _, ret = ssh_func(cmd)
            if not ret:
                return result.strip()
            if not retry:
                continue
            else:
                self.logger.warn('Retrying to run %s', (' ').join(cmd))
                time.sleep(TICK)
        else:
            if not error_msg:
                error_msg = 'Failed to run %s' % cmd
            raise StandardError(error_msg)

    def _check_pool_status(self):
        """Check if current host is already in the master pool
        
        Returns:
          True: already in the target pool
          False: not in any pool
        
        Raises:
          StandardError: if it's in a pool but not the target pool
        """
        host_uuids = self._xe_cmd(self._ssh_host, [
         'xe', 'host-list', '--minimal'], 'Failed to get host uuid from this node').split(',')
        master_uuids = self._xe_cmd(self._ssh_master, [
         'xe', 'host-list', '--minimal'], 'Failed to get host uuid from master node').split(',')
        if len(host_uuids) > 1:
            self.logger.debug('Multiple hosts %s detected on this node', host_uuids)
            host_uuids = set(host_uuids)
            master_uuids = set(master_uuids)
            diff = host_uuids.symmetric_difference(master_uuids)
            if diff:
                self.logger.error('This host is already part of pool %s, not the master pool %s. Please eject this node and retry', host_uuids, master_uuids)
                raise StandardError('This host is already part of another pool, Please eject this node and retry')
            else:
                self.logger.info('This host is already in the pool %s', host_uuids)
                return True
        else:
            return False

    def _collect_node_info(self):
        """ Get CVM local SR and host name/uuid."""
        self.cvm_json, _, _ = self._ssh_host(['cat', CVM_EXPORT])
        self.cvm_json = json.loads(self.cvm_json)
        self.cvm_uuid = self.cvm_json['vm']['id']
        self.cvm_name = self.cvm_json['vm']['name']
        self.host_uuid = self._xe_cmd(self._ssh_host, [
         'xe', 'host-list', '--minimal'], 'Failed to get host uuid')
        if ',' in self.host_uuid:
            raise StandardError('Mulitple hosts found')
        self.host_name = self._xe_cmd(self._ssh_host, [
         'xe', 'host-param-get', 'uuid=%s' % self.host_uuid,
         'param-name=name-label'], 'Failed to get host name')
        bonds = self._xe_cmd(self._ssh_host, [
         'xe', 'bond-list', '--minimal'], 'Failed to check NIC bond')
        if bonds:
            raise StandardError('One or multiple NIC bond detected(%s), please remove them before joining pool' % bonds)

    def _wait_for_master(self):
        """ Waiting for master to be ready. """
        self.logger.debug('Waiting for master at %s', self.config.xs_master_ip)
        for i in range(0, MASTER_WAIT_LIMIT, TICK):
            _, _, ret = self._ssh_master(['test', '-f', '/root/.firstboot_success'])
            if not ret:
                self.logger.debug('XenServer pool master is up')
                return
            _, _, ret = self._ssh_master(['test', '-f', '/root/.firstboot_fail'])
            if not ret:
                raise StandardError('Cannot join to Xenserver master: firstboot failed')
            self.logger.debug('[%ss/%ss] Waiting for master to finish firstboot', i, MASTER_WAIT_LIMIT)
            time.sleep(TICK)
        else:
            raise StandardError('Failed to connect to Xenserver master')

    def _get_cvm_power_state(self):
        return self._xe_cmd(self._ssh_host, [
         'xe', 'vm-param-get', 'uuid=%s' % self.cvm_uuid,
         'param-name=power-state'], 'Failed to get CVM power state')

    def _poweroff_cvm(self):
        """ Poweroff cvm and wait for power state. """
        self.logger.debug('Poweroff CVM to join pool')
        self._ssh_cvm(['sudo', 'poweroff'])
        time.sleep(5)
        for i in range(0, CVM_POWEROFF_LIMIT, TICK):
            power_state = self._get_cvm_power_state()
            if power_state == 'running':
                self._ssh_host(['systemctl', 'stop', SYSTEMD_SERVICE])
                self.logger.debug('[%ss/%ss] Waiting for CVM to be poweroff', i, CVM_POWEROFF_LIMIT)
                time.sleep(TICK)
            else:
                self.logger.debug('CVM is powered off')
                return
        else:
            raise StandardError('Failed to poweroff CVM')

    def _join_master(self):
        """ Join to master pool and wait. """
        config = self.config
        self.logger.debug('Joining pool')
        _, err, ret = self._ssh_host([
         'xe', 'pool-join',
         'master-address=%s' % config.xs_master_ip,
         'master-username=%s' % self.xs_master_username,
         'master-password=%s' % self.xs_master_password,
         'force=true'])
        if ret:
            raise StandardError('Failed to join XenServer pool. %s' % err.strip())
        for i in range(0, POOL_JOIN_LIMIT, TICK):
            is_enabled, _, ret = self._ssh_master([
             'xe', 'host-param-get', 'uuid=%s' % self.host_uuid,
             'param-name=enabled'])
            is_enabled = is_enabled.strip() == 'true'
            if not ret and is_enabled:
                self.logger.debug('Host %s is now enabled', self.host_name)
                return
            self.logger.debug('[%ss/%ss] Waiting for pool join', i, POOL_JOIN_LIMIT)
            time.sleep(TICK)
        else:
            raise StandardError('Failed to join pool')

    def _wait_for_cvm_vif(self):
        """ Wait for XS host finish setting up CVM VIF """
        for retry in range(0, CVM_NETWORK_LIMIT, TICK):
            network_uuid = self._xe_cmd(self._ssh_host, [
             'xe', 'vif-list', 'vm-uuid=%s' % self.cvm_uuid, 'device=0',
             'params=network-uuid', '--minimal'], retry=CVM_VIF_RETRY)
            network_state = self._xe_cmd(self._ssh_host, [
             'xe', 'pif-list', 'network-uuid=%s' % network_uuid,
             'host-uuid=%s' % self.host_uuid, 'params=currently-attached',
             '--minimal'])
            if network_state != 'true':
                self.logger.debug('[%ss/%ss] Waiting for VIF for CVM to be attached', retry, CVM_NETWORK_LIMIT)
                time.sleep(TICK)
            else:
                self.logger.info('VIF for CVM is attached')
                break
        else:
            raise StandardError("XenServer didn't attach VIF to CVM in limited time")

    def _poweron_cvm(self):
        """ Poweron CVM and wait. """
        for i in range(0, CVM_POWERON_LIMIT, TICK):
            try:
                power_state = self._get_cvm_power_state()
            except StandardError:
                self.logger.debug('[%ss/%ss] Waiting for CVM to appear on master', i, CVM_POWERON_LIMIT)
                time.sleep(TICK)
                continue
            else:
                if power_state != 'running':
                    self._ssh_host(['systemctl', 'stop', SYSTEMD_SERVICE])
                _, _, ret = self._ssh_host([
                 'systemctl', 'start', SYSTEMD_SERVICE])
                if not ret:
                    break
                else:
                    self.logger.debug('[%ss/%ss] Waiting for CVM to start', i, CVM_POWERON_LIMIT)
                    time.sleep(TICK)
        else:
            raise StandardError('Failed to power on CVM, please check log for more information')

        for i in range(0, CVM_POWERON_LIMIT, TICK):
            _, _, ret = self._ssh_cvm(['true'])
            if not ret:
                return
            self.logger.debug('[%s/%s] Waiting for CVM to be ready', i, CVM_POWERON_LIMIT)
            time.sleep(TICK)
        else:
            raise StandardError('Failed to power on CVM after pool join')

    def _set_pool_master_label(self, label):
        self._ssh_master([
         'xe', 'pool-param-set',
         "name-label='%s'" % label,
         'uuid=%s', self.pool_uuid])

    def _fix_pool_settings(self):
        self._ssh_master([
         'xe', 'pool-param-set',
         'other-config:hci-limit-fault-tolerance=1',
         'uuid=%s' % self.pool_uuid])
        self._ssh_master([
         'xe', 'pool-param-set',
         'other-config:hci-forbid-update-auto-restart=1',
         'uuid=%s' % self.pool_uuid])
        self._ssh_master([
         'xe', 'pool-param-set',
         'other-config:hci-forbid-rpu=1',
         'uuid=%s' % self.pool_uuid])

    def run(self):
        node_config = self.config
        logger = self.logger
        self.xs_master_username = getattr(node_config, 'xs_master_username', 'root')
        self.xs_master_password = getattr(node_config, 'xs_master_password', 'nutanix/4u')
        if getattr(node_config, 'is_xs_master', False):
            self.pool_uuid = self._xe_cmd(self._ssh_master, ['xe', 'pool-list', '--minimal']).strip()
            if getattr(node_config, 'xs_master_label', ''):
                logger.info('Setting pool label to %s', node_config.xs_master_label)
                self._set_pool_master_label(node_config.xs_master_label)
            logger.info('Configuring Pool settings')
            self._fix_pool_settings()
            logger.info('This node is XenServer pool master, Skip join')
            return
        logger.info('This node is XenServer pool slave, joining master at %s', node_config.xs_master_ip)
        self.set_status(STATE_WAITING_MASTER)
        self._wait_for_master()
        self.set_status(STATE_RUNNING)
        if self._check_pool_status():
            return
        self._collect_node_info()
        self._poweroff_cvm()
        self._join_master()
        self.set_status(STATE_WAITING_CVM)
        self._wait_for_cvm_vif()
        self._poweron_cvm()
        logger.info('Joined pool %s', node_config.xs_master_ip)