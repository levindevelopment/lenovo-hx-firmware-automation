# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_cluster_destroy.py
# Compiled at: 2019-02-15 12:42:10
import time
from cluster.genesis.cluster_manager import ClusterManager
from util.net.rpc import RpcError
from foundation import config_persistence
from foundation import factory_mode
from foundation import foundation_tools as tools
from foundation.imaging_step import ImagingStepClusterTask
from foundation.cluster_genesis_mixin import GenesisMixin
STATE_DESTROYING_CLUSTER = 'Destroying cluster'
STATE_DESTROYING_CLUSTER_DONE = 'Destroying cluster complete'
CLUSTER_DESTROY_BACKOFF_S = 30
CLUSTER_DESTROY_RETRIES = 5
CLUSTER_DESTROY_TIMEOUT_BASE = 600
CLUSTER_DESTROY_TIMEOUT_PER_NODE = 10
CLUSTER_DESTROY_TIMEOUT_PER_SED = 60

class ImagingStepClusterDestroy(GenesisMixin, ImagingStepClusterTask):

    def get_progress_timing(self):
        return [
         (
          STATE_DESTROYING_CLUSTER, 3)]

    def get_finished_message(self):
        return STATE_DESTROYING_CLUSTER_DONE

    def get_cluster_destroy_timeout(self):
        cluster_config = self.config
        cluster_members = cluster_config.cluster_members
        timeout = CLUSTER_DESTROY_TIMEOUT_BASE
        timeout += CLUSTER_DESTROY_TIMEOUT_PER_NODE * len(cluster_members)
        sed_max = max(map(lambda nc: getattr(nc, 'sed_count', 0), cluster_members))
        timeout += CLUSTER_DESTROY_TIMEOUT_PER_SED * sed_max
        return timeout

    def check_password_protection(self):
        cluster_config = self.config
        logger = self.logger
        cluster_memebers = cluster_config.cluster_members
        first_node = cluster_memebers[0]
        passwd_state = self._call_genesis_method(first_node.cvm_ip, ClusterManager.password_state, timeout_secs=10)
        if isinstance(passwd_state, RpcError):
            logger.warn('Genesis RPC failure. Could not contact Genesis on node IP: %s to discover if this cluster has configured passwords. This might occur if CVM is down. Proceeding anyway.', first_node.cvm_ip)
        else:
            if passwd_state:
                raise StandardError('Cannot destroy the cluster when password protection is active. Please disable password protection and retry.')

    def destroy_cluster(self):
        cluster_config = self.config
        logger = self.logger
        cluster_memebers = cluster_config.cluster_members
        first_node = cluster_memebers[0]
        self.set_status(STATE_DESTROYING_CLUSTER)
        destroy_timeout = self.get_cluster_destroy_timeout()
        try:
            nos_version = tools.get_nos_version_from_cvm(first_node.cvm_ip, cluster_config)
            if nos_version < [4, 2]:
                logger.info('Stopping cluster.')
                for i in range(CLUSTER_DESTROY_RETRIES):
                    stdout, stderr, retval = self.ssh(first_node.svm_ip, ['bash', '-lc',
                     '"cluster stop"'], cluster_config, throw_on_error=False, escape_cmd=True)
                    if retval == 0:
                        break
                    time.sleep(CLUSTER_DESTROY_BACKOFF_S)
                else:
                    raise StandardError('Cluster stop failed multiple times for cluster %s' % cluster_config.cluster_name)

                logger.info('Cluster stopped.')
                logger.info('Destroying cluster.')
                for i in range(CLUSTER_DESTROY_RETRIES):
                    stdout, stderr, retval = self.ssh(first_node.cvm_ip, [
                     'SSH_KEY=/home/nutanix/.ssh/id_rsa', 'bash', '-lc',
                     '"cluster --yes destroy"'], cluster_config, throw_on_error=False, escape_cmd=True, timeout=destroy_timeout)
                    if retval == 0:
                        break
                    time.sleep(CLUSTER_DESTROY_BACKOFF_S)
                else:
                    raise StandardError('Cluster destroy failed multiple times for cluster %s' % cluster_config.cluster_name)

            else:
                logger.info('Destroying cluster.')
                for i in range(CLUSTER_DESTROY_RETRIES):
                    if self._destroy_cluster(cluster_config, first_node.svm_ip):
                        break
                    time.sleep(CLUSTER_DESTROY_BACKOFF_S)
                else:
                    raise StandardError('Cluster destroy failed multiple times for cluster %s' % cluster_config.cluster_name)

            logger.info('Cluster destroyed')
            if factory_mode.factory_mode():
                logger.info('Not persist cluster destroy result in factory')
            else:
                config_persistence.post_cluster_destroy_result(first_node.svm_ip, True)
        except:
            config_persistence.post_cluster_destroy_result(first_node.svm_ip, False)
            raise

    def run(self):
        cluster_config = self.config
        logger = self.logger
        if not getattr(cluster_config, 'cluster_destroy_now', False):
            logger.info('Cluster destroy skipped')
            return
        self.check_password_protection()
        logger.info('Destroying cluster')
        self._destroy_cluster()
        logger.info('Cluster destroyed')
        if factory_mode.factory_mode():
            nos_version = getattr(cluster_config.cluster_members[0], 'nos_version', 'UNDEFINED')
            logger.info('Done imaging with NOS %s', nos_version)