# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_setup_replication.py
# Compiled at: 2019-02-15 12:42:10
from cluster.genesis.cluster_manager import ClusterManager
from foundation.decorators import wait_for_cluster_creation
from foundation.imaging_step import ImagingStepClusterTask
from foundation.tinyrpc import call_genesis_method, RpcError
FRIENDLY_MSG = 'Setting up replication'

class ImagingStepSetupReplication(ImagingStepClusterTask):

    def get_progress_timing(self):
        return [
         (
          FRIENDLY_MSG, 1)]

    @wait_for_cluster_creation
    def _setup_replication(self):
        cluster = self.config
        logger = self.logger
        cluster_members = cluster.cluster_members
        target_cluster = cluster.replication_target_cluster
        self.set_status(FRIENDLY_MSG)
        logger.info('Seting up replication between %s and %s' % (
         cluster.cluster_name, target_cluster))
        result = call_genesis_method(cluster_members[0].cvm_ip, ClusterManager.get_default_container_name)
        if isinstance(result, RpcError):
            raise StandardError('Failed to get the local container name on %s because of: %s' % (
             cluster_members[0].cvm_ip, str(result)))
        ret, value = result
        if not ret:
            raise StandardError('Failed to get local container name because of: %s' % value)
        local_container_name = value
        result = call_genesis_method(cluster.replication_target_ips[0], ClusterManager.get_default_container_name)
        if isinstance(result, RpcError):
            raise StandardError('Failed to get the remote container name on %s because of: %s' % (
             cluster.replication_target_ips[0], str(result)))
        ret, value = result
        if not ret:
            raise StandardError('Failed to get remote container name because of: %s' % value)
        remote_container_name = value
        cap = {'backup': True, 'disaster_recovery': False}
        remote_site_info = {'remote_site_name': cluster.replication_target_name, 
           'remote_site_ips': cluster.replication_target_ips, 
           'capabilities': cap, 
           'local_container_names': [
                                   local_container_name], 
           'remote_container_names': [
                                    remote_container_name]}
        logger.info('Setting up replication with following params:\n%s' % remote_site_info)
        result = call_genesis_method(cluster_members[0].cvm_ip, ClusterManager.setup_remote_site, (
         remote_site_info,))
        if isinstance(result, RpcError):
            raise StandardError('Failed to setup replication because of: %s' % str(result))
        ret, value = result
        if not ret:
            raise StandardError('Failed to setup replication because of: %s' % value)
        logger.info('Replication setup successfully with %s' % target_cluster)

    def run(self):
        if not self.config.setup_replication:
            return
        self.config.target_cluster_name = self.config.replication_target_cluster
        self._setup_replication()