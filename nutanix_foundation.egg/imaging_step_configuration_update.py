# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_configuration_update.py
# Compiled at: 2019-02-15 12:42:10
import json, time, urllib2
from cluster.genesis.node_manager import NodeManager
from util.net.rpc import RpcError
from foundation import config_persistence
from foundation import foundation_tools as tools
from foundation import imaging_context
from foundation import imaging_step_handoff
from foundation.cluster_genesis_mixin import GenesisMixin
from foundation.foundation_settings import settings as foundation_settings
from foundation.imaging_step import ImagingStepClusterTask
from foundation.session_manager import get_global_config, get_session_id
STATE_SCHEDULED = 'Will run configuration update shortly'
STATE_START = 'Running configuration update'
STATE_DONE_FRIENDLY = 'Configuration update successful'
STATE_HANDOFF = 'Handing off control to updated node'
CHECK_INTERVAL_S = 30
WAIT_CYCLES_PER_NODE = 60
CVM_REBOOT_WAIT_TIME = 300
TIMEOUT_FOR_REMOTE_CLUSTER_TO_BE_UP = CHECK_INTERVAL_S * WAIT_CYCLES_PER_NODE
GENESIS_PORT = 2100

class ImagingStepConfigurationUpdate(ImagingStepClusterTask, GenesisMixin):

    @classmethod
    def is_compatible(cls, config):
        cluster_members = config.cluster_members
        node_config = cluster_members[0]
        session_id = get_session_id()
        global_config = get_global_config(session_id)
        cluster_check = len(cluster_members) > 1 and len(global_config.clusters) < 2
        attributes_check = getattr(node_config, 'cvm_gb_ram', None) or getattr(node_config, 'hypervisor_hostname', None)
        if imaging_context.get_context() == imaging_context.FIELD_VM:
            if not node_config.image_now:
                return cluster_check and attributes_check
        return False

    def get_http_port(self):
        return foundation_settings['http_port']

    def handoff(self, target_cvm_ip):
        logger = self.logger
        json_config = config_persistence.get_persisted_config()
        url = 'http://%s:%s/foundation/image_nodes' % (
         target_cvm_ip,
         self.get_http_port())
        logger.info('Handing off to %s:%s' % (
         target_cvm_ip, self.get_http_port()))
        json_config['is_cvm_update_handoff'] = True
        req = urllib2.Request(url, json.dumps(json_config), {'Content-Type': 'application/json'})
        for _ in range(30):
            try:
                urllib2.urlopen(req).read()
                logger.info('Posted handoff request successfully')
                return True
            except urllib2.URLError:
                time.sleep(10)

        else:
            logger.error('Failed to handoff imaging to %s', target_cvm_ip)
            return False

    def is_nos_supported(self, cvm_ips):
        logger = self.logger
        nos_version = tools.get_nos_version_from_cvm(cvm_ips[0])
        nos_version_str = [ str(item) for item in nos_version ]
        logger.info('Reported nos version: %s' % ('.').join(nos_version_str))
        return nos_version and nos_version >= [5, 1]

    def wait_for_cvm(self, cvm_ips, may_cvm_reboot=True):
        logger = self.logger
        start_time = time.time()
        timeout = start_time + TIMEOUT_FOR_REMOTE_CLUSTER_TO_BE_UP
        time.sleep(CHECK_INTERVAL_S * 2)
        while time.time() < timeout:
            responses = [
             'PENDING'] * len(cvm_ips)
            for idx, cvm_ip in enumerate(cvm_ips):
                if responses[idx] != 'PENDING':
                    continue
                try:
                    logger.info('Checking cvm status of: %s', cvm_ip)
                    result = self._call_genesis_method(cvm_ip, NodeManager.get_ip)
                    if not result or isinstance(result, RpcError):
                        responses[idx] = 'PENDING'
                        logger.info('Still waiting on cvm %s to come up' % cvm_ip)
                        time.sleep(CHECK_INTERVAL_S)
                    else:
                        uptime = tools.get_cvm_uptime(cvm_ip)
                        if not uptime:
                            continue
                        else:
                            if may_cvm_reboot and uptime > time.time() - start_time:
                                if time.time() - start_time > CVM_REBOOT_WAIT_TIME:
                                    logger.error("CVM didn't reboot and apply configuration updates.")
                                    responses[idx] = 'FAILED'
                                else:
                                    responses[idx] = 'PENDING'
                                    logger.info('CVM %s still hasnt gone down. Waiting for cvm to go down' % cvm_ip)
                                    time.sleep(CHECK_INTERVAL_S)
                            else:
                                responses[idx] = 'PASSED'
                except Exception as inst:
                    logger.info('CVM seems to be still down: %s' % inst)

            if all((item is 'PASSED' for item in responses)):
                return True
            if all((item in ('PASSED', 'FAILED') for item in responses)):
                return False

        return False

    def finish_handoff_cvm_configuration_update(self):
        logger = self.logger
        cluster_members = self.config.cluster_members
        node_config = cluster_members[0]
        if len(cluster_members) < 2 or node_config.image_now or not getattr(node_config, 'cvm_gb_ram', None) and not getattr(node_config, 'hypervisor_hostname', None):
            logger.info('Skipping update configuration')
            return
        logger.info('Finishing off cvm memory and hostname configuration update on handoff')
        session_id = get_session_id()
        global_config = get_global_config(session_id)
        cvm_ips = []
        hostname_dict = {}
        for node in cluster_members:
            if node.cvm_ip == global_config.foundation_ip:
                continue
            else:
                cvm_ips.append(node.cvm_ip)
                hostname_dict[node.cvm_ip] = getattr(node, 'hypervisor_hostname', None)

        results = []
        for cvm_ip in cvm_ips:
            cvm_mem_mb = getattr(node_config, 'cvm_gb_ram', -1)
            if cvm_mem_mb:
                cvm_mem_mb = int(cvm_mem_mb) * 1024
                logger.info('Trying to post configuration %s to %s' % (str(cvm_ip),
                 str({'cvm_mem_mb': cvm_mem_mb, 'hostname': str(hostname_dict.get(cvm_ip))})))
            else:
                cvm_mem_mb = -1
                logger.info('Trying to post configuration %s to %s' % (str(cvm_ip),
                 str({'hostname': str(hostname_dict.get(cvm_ip))})))
            result = self._call_genesis_method(cvm_ip, NodeManager.update_configuration, (
             {'cvm_mem_mb': cvm_mem_mb, 'hostname': str(hostname_dict.get(cvm_ip))},), timeout_secs=60)
            results.append(result)

        if len(results) > 0:
            logger.info('Posted cvm configuration update intent! Now waiting...')
            if self.wait_for_cvm(cvm_ips):
                logger.info('Updating cvm memory and hostname configuration on handoff successful.')
            else:
                logger.fatal('Updating cvm memory and hostname configuration on handoff failed. Timeout out waiting for the CVM to come up')
        else:
            logger.warning('Updating cvm memory and hostname configuration on handoff failed.')
        return

    def update_cvm_configuration(self, need_handoff=False):
        logger = self.logger
        cluster_members = self.config.cluster_members
        node_config = cluster_members[0]
        session_id = get_session_id()
        global_config = get_global_config(session_id)
        handoff_config = None
        if len(cluster_members) < 2 or node_config.image_now or not getattr(node_config, 'cvm_gb_ram', None) and not getattr(node_config, 'hypervisor_hostname', None):
            logger.info('Skipping update configuration')
            return
        logger.info('Trying to update cvm memory and hostname configuration if set')
        cvm_ips = []
        hostname_dict = {}
        if need_handoff:
            logger.warning('Updating cvm configuration on a foundation running on cvm requires handoff. Starting update with handoff!')
            for node in cluster_members:
                if node.cvm_ip != global_config.foundation_ip:
                    cvm_ips.append(node.cvm_ip)
                    hostname_dict[node.cvm_ip] = getattr(node, 'hypervisor_hostname', None)
                    handoff_config = node
                    break

            if not handoff_config:
                logger.fatal('Foundation running on a single node cluster cannot  update cvm. Aborting cvm memory and hostname update')
                return
        else:
            for node in cluster_members:
                cvm_ips.append(node.cvm_ip)
                hostname_dict[node.cvm_ip] = getattr(node, 'hypervisor_hostname', None)

        results = []
        for cvm_ip in cvm_ips:
            cvm_mem_mb = getattr(node_config, 'cvm_gb_ram', -1)
            if cvm_mem_mb:
                cvm_mem_mb = int(cvm_mem_mb) * 1024
                logger.info('Trying to post configuration %s to %s' % (str(cvm_ip),
                 str({'cvm_mem_mb': cvm_mem_mb, 'hostname': str(hostname_dict.get(cvm_ip))})))
            else:
                cvm_mem_mb = -1
                logger.info('Trying to post configuration %s to %s' % (str(cvm_ip),
                 str({'hostname': str(hostname_dict.get(cvm_ip))})))
            result = self._call_genesis_method(cvm_ip, NodeManager.update_configuration, ({'cvm_mem_mb': cvm_mem_mb, 'hostname': str(hostname_dict.get(cvm_ip))},), timeout_secs=60)
            results.append(result)

        if len(results) > 0:
            logger.info('Posted cvm configuration update intent! Now waiting...')
            if self.wait_for_cvm(cvm_ips):
                if need_handoff:
                    logger.info('Handing off cvm update...')
                    handoff_handle = imaging_step_handoff.ImagingStepHandoff(handoff_config)
                    handoff_handle.transfer_logs()
                    self.set_status(STATE_HANDOFF)
                    self.handoff(cvm_ips[0])
                    imaging_step_handoff.set_redirect_status(ready=True, cvm_ip=cvm_ips[0])
                    time.sleep(600)
                    raise StandardError('Timeout in waiting for handoff(%s)' % cvm_ips[0])
                else:
                    logger.info('Updating cvm memory and hostname configuration successful.')
            else:
                logger.fatal('Updating cvm memory and hostname configuration failed. Timeout out waiting for the CVM to come up')
        else:
            logger.warning('Updating cvm memory and hostname configuration failed.')
        return

    def update_hardware_config(self):
        logger = self.logger
        cluster_members = self.config.cluster_members
        cvm_ips = []
        for node_config in cluster_members:
            try:
                attributes_override = getattr(node_config, 'hardware_attributes_override', None)
                if attributes_override:
                    hc = tools.read_hardware_config_from_cvm(node_config)
                    if hc:
                        for key, value in attributes_override.iteritems():
                            hc['node']['hardware_attributes'][key] = value

                        if not tools.update_hardware_config_on_cvm(node_config, hc):
                            logger.error('Could not update hardware config of node: %s' % node_config.cvm_ip)
                        else:
                            cvm_ips.append(node_config.cvm_ip)
                    else:
                        logger.warning('Could not read hardware config of node: %s' % node_config.cvm_ip)
            except Exception as e:
                logger.exception('Could not update hardware config of node: %s' % node_config.cvm_ip)

        if len(cvm_ips) == 0 or self._restart_genesis(cvm_ips, wait=True):
            logger.info('Updating hardware config finished succesfully')
        else:
            raise StandardError('Updating hardware config failed since Genesisdid not come up after restart')
        return

    def get_finished_message(self):
        return STATE_DONE_FRIENDLY

    def get_progress_timing(self):
        expected_runtime = 0.5
        if getattr(self.config, 'hypervisor', None) == 'hyperv':
            expected_runtime = 2.0
        return [
         (
          STATE_SCHEDULED, 1),
         (
          STATE_START, expected_runtime),
         (
          STATE_HANDOFF, 0.5)]

    def run(self):
        self.set_status(STATE_SCHEDULED)
        logger = self.logger
        self.set_status(STATE_START)
        cluster_members = self.config.cluster_members
        cvm_ip_list = list(map(lambda m: m.cvm_ip, cluster_members))
        need_handoff = False
        session_id = get_session_id()
        global_config = get_global_config(session_id)
        if self.wait_for_cvm(cvm_ip_list, may_cvm_reboot=False):
            if not self.is_nos_supported(cvm_ip_list):
                logger.warning('NOS version not supported for cvm memory and hostname configuration update. Skipping')
                return
            for cvm_ip in cvm_ip_list:
                if cvm_ip == global_config.foundation_ip:
                    need_handoff = True
                    break

            if getattr(global_config, 'is_cvm_update_handoff', None):
                self.finish_handoff_cvm_configuration_update()
            else:
                self.update_hardware_config()
                self.update_cvm_configuration(need_handoff)
        else:
            logger.fatal('Updating cvm memory and hostname configuration failed because CVMs failed to come up within timeout')
        return