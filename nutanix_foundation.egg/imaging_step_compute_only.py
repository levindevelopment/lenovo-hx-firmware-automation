# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_compute_only.py
# Compiled at: 2019-02-15 12:42:10
import json, threading
from functools import partial
from cluster.genesis.node_manager import NodeManager
from cluster.genesis.cluster_manager import ClusterManager
from util.net.rpc import RpcError
from foundation import foundation_tools as tools
from foundation.imaging_step import ImagingStepNodeTask, ExtraDepsMixin
from foundation.cluster_genesis_mixin import GenesisMixin
STATE_CHECKING = 'Checking Compute Only node status'
STATE_JOINING = 'Adding Compute Only node to the cluster'
STATE_ADDED = 'Added Compute Only node to the cluster'
MARKER_CFG = '/root/configured'
RPC_LOCK = threading.Lock()

class ImagingStepComputeOnly(ExtraDepsMixin, GenesisMixin, ImagingStepNodeTask):

    def __init__(self, *args, **kwargs):
        super(ImagingStepComputeOnly, self).__init__(*args, **kwargs)
        self._ssh = partial(tools.ssh, self.config, self.config.hypervisor_ip, user='root')

    @classmethod
    def is_compatible(cls, config):
        """
        CO node requires the following attributes
         - .compute_only=True
         - .co_attach_to_cluster_ip=<cvm_ip>
        """
        return getattr(config, 'compute_only', False) and getattr(config, 'co_attach_to_cluster_ip', None)

    def extra_dep_config_filter(self, config):
        """
        this step depends on the `co_attach_to_cluster_ip` config
        """
        return getattr(config, 'cvm_ip', None) == self.config.co_attach_to_cluster_ip

    def get_progress_timing(self):
        return [
         (
          STATE_CHECKING, 1),
         (
          STATE_JOINING, 3)]

    def get_finished_message(self):
        return STATE_ADDED

    @property
    def _use_tunnel(self):
        return True

    def _is_cluster_configured(self):
        cluster_ip = self.config.co_attach_to_cluster_ip
        ret = self._call_genesis_method(cluster_ip, NodeManager.configured)
        self.logger.debug("the target node's cluster (%s) status is %s", cluster_ip, ret)
        if not isinstance(ret, RpcError):
            return ret
        return False

    def _collect_info(self):
        _, _, ret = self._ssh(command=[
         'test', '-f', MARKER_CFG], log_on_error=False, throw_on_error=False)
        if not ret:
            raise StandardError('This node is already part of a cluster')
        out, _, ret = self._ssh(command=[
         'cat', '/root/factory_config.json'])
        factory_config = json.loads(out)
        self.node_uuid = factory_config['node_uuid']
        self.logger.info('Compute only node %s is ready at %s', self.node_uuid, self.config.hypervisor_ip)

    def _add_to_cluster(self):
        self_ip = self.config.hypervisor_ip
        cluster_ip = self.config.co_attach_to_cluster_ip
        self.logger.info('Adding compute only node %s to cluster at %s', self_ip, cluster_ip)
        with RPC_LOCK:
            ret = self._call_genesis_method(cluster_ip, ClusterManager.add_node, node_uuid=self.node_uuid, node_svm_ip=self_ip, compute_only=True, timeout_secs=120)
            if not isinstance(ret, RpcError):
                if ret:
                    return
        raise StandardError('Failed to add compute only node to cluster: %s' % ret)

    def run(self):
        self.set_status(STATE_CHECKING)
        if not self._is_cluster_configured():
            raise StandardError('The target node is not in a valid cluster')
        self._collect_info()
        self.set_status(STATE_JOINING)
        self._add_to_cluster()