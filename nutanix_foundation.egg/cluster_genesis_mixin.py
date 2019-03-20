# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/cluster_genesis_mixin.py
# Compiled at: 2019-02-15 12:42:10
import time
from cluster.genesis.cluster_manager import ClusterManager
from cluster.genesis.node_manager import NodeManager
from util.net.rpc import RpcError
from foundation import foundation_tools as tools
from foundation.shared_functions import in_same_subnet
from foundation.tinyrpc import call_genesis_method, call_genesis_method_over_tunnel
NODE_DISCOVERY_BACKOFF_S = 60
NODE_DISCOVERY_RETRIES = 10
GENESIS_RESTART_TIMEOUT = 300
MARKER_COMMAND_TIMEOUT = 20
NODE_UNCONFIGURE_MARKER = '/home/nutanix/.node_unconfigure'
NODE_UNCONFIGURE_MARKER_DISAPPEAR_TIMEOUT = 900
RPC_TIMEOUT_BASE = 6
RPC_TIMEOUT_NODE = 1

class GenesisMixin(object):
    """
    Mixin for Genesis related operations
    
    Expecting same init args and to be mixed with ImagingStepClusterTask
    """

    @property
    def _use_tunnel(self):
        node_config = self.config.cluster_members[0]
        cvm_ip = node_config.cvm_ip
        foundation_ip = getattr(node_config, 'foundation_ip', None)
        if not foundation_ip:
            foundation_ip = tools.get_my_ip(cvm_ip)
        return not in_same_subnet(cvm_ip, foundation_ip, node_config.cvm_netmask)

    @property
    def _cvm_ips(self):
        return [ member.cvm_ip for member in self.config.cluster_members ]

    @property
    def _rpc_timeout(self):
        """
        The typical time usage vs max timeouts are:
          4 nodes: min 0.6s, max 5s, timeout=10 seconds
          20 nodoes: min 0.6s, max 16s, timeout=26 seconds
        """
        return RPC_TIMEOUT_BASE + RPC_TIMEOUT_NODE * len(self.config.cluster_members)

    def _call_genesis_method(self, *args, **kwargs):
        """
        Call genesis method over ssh tunnel if cvm different subnet
        
        Args:
          see tinyrpc.call_genesis_method
        """
        if self._use_tunnel:
            func = call_genesis_method_over_tunnel
        else:
            func = call_genesis_method
        return func(*args, **kwargs)

    def _wait_for_genesis(self, cvm_ips=None):
        """
        Wait for genesis to respond rpc request
        
        Args:
          cvm_ips: optional list of cvm IPs, default to all cvm ips
        """
        logger = self.logger
        if not cvm_ips:
            cvm_ips = self._cvm_ips
        for cvm_ip in cvm_ips:
            for i in range(NODE_DISCOVERY_RETRIES):
                logger.info('[%s/%s] waiting for genesis service', i + 1, NODE_DISCOVERY_RETRIES)
                results = self._call_genesis_method(cvm_ip, NodeManager.configured)
                if not isinstance(results, RpcError):
                    break
                else:
                    logger.warn('Got RpcError %s. Retrying in 60 seconds', results)
                time.sleep(NODE_DISCOVERY_BACKOFF_S)
            else:
                return False

        return True

    def _restart_genesis(self, cvm_ips=None, wait=False):
        """
        Restart Genesis service on this cluster
        
        Args:
          cvm_ips: optional list of cvm IPs, default to all cvm ips
          wait: block until genesis is up
        
        Returns True if Genesis is started on all cvms. Returns False otherwise.
        """
        cluster_config = self.config
        logger = self.logger
        result = True
        if not cvm_ips:
            cvm_ips = self._cvm_ips
        cmd_map = dict(((ip, ['cluster/bin/genesis', 'restart']) for ip in cvm_ips))
        logger.debug('Restarting Genesis on %s', cvm_ips)
        result_map = tools.run_command_on_cvms(cmd_map, cluster_config, timeout_secs=GENESIS_RESTART_TIMEOUT)
        for ip, (out, err, ret) in result_map.iteritems():
            if ret == 0:
                logger.info('Successfully restarted Genesis on %s', ip)
                continue
            result = False
            if not ret:
                logger.error('Error executing Genesis restart on %s', ip)
            elif ret == -9:
                logger.error('Restarting Genesis timed out on %s', ip)
            else:
                logger.error('Restarting Genesis failed on %s.\nstdout:\n%s\nstderr:\n%s', ip, out, err)

        if wait and result:
            return self._wait_for_genesis(cvm_ips)
        return result

    def _force_genesis_unconfig(self, cvm_ips=None, wait=True):
        """
        Unconfig the cluster forcefully
        
        Args:
          cvm_ips: optional list of cvm IPs, default to all cvm ips
          wait: wait for genesis to fully get unconfigured
        
        This will be a force destroy. We do not care about the current state of the
        cluster.
        """
        cluster_config = self.config
        logger = cluster_config.get_logger()
        marker_cmd = ['touch', str(NODE_UNCONFIGURE_MARKER)]
        if not cvm_ips:
            cvm_ips = self._cvm_ips
        cmd_map = dict(((ip, marker_cmd) for ip in cvm_ips))
        result = True
        result_map = tools.run_command_on_cvms(cmd_map, cluster_config, MARKER_COMMAND_TIMEOUT)
        for ip, (out, err, ret) in result_map.iteritems():
            if ret == 0:
                continue
            result = False
            if not ret:
                logger.error('Error executing command: %s on %s', marker_cmd, ip)
            elif ret == -9:
                logger.error('Command: %s timed out on %s', marker_cmd, ip)
            else:
                logger.error('Command: %s failed on %s.\nstdout:\n%s\nstderr:\n%s', marker_cmd, ip, out, err)

        if not result:
            logger.error('Failed to create unconfigure marker on all cvms')
        if self._restart_genesis(cvm_ips, wait=wait):
            if wait:
                logger.debug('Waiting for genesis to be unconfigured')
                return self._wait_for_marker(NODE_UNCONFIGURE_MARKER, cvm_ips, to_disappear=True)
            return True
        logger.error('Failed to restart genesis on all cvms')
        return False

    def _wait_for_marker(self, path, cvm_ips=None, to_disappear=False, timeout=NODE_UNCONFIGURE_MARKER_DISAPPEAR_TIMEOUT):
        """
        Wait for marker file to appear or disappear at path on all cvm_ips.
        
        Args:
          path: a file path on cvm
          cvm_ips: optional list of cvm IPs, default to all cvm ips
          to_disappear: appear or disappear
          timeout: timeout in seconds
        
        Returns:
          False: timeout
        """
        cluster_config = self.config
        logger = self.logger
        if to_disappear:
            cmd = [
             'test', '!', '-f', str(path)]
        else:
            cmd = [
             'test', '-f', str(path)]
        if not cvm_ips:
            cvm_ips = self._cvm_ips
        ips = cvm_ips[:]
        event = ['appear', 'disappear'][to_disappear]
        start_time = time.time()
        while ips:
            logger.info('Waiting for marker file %s to %s on ips %s', path, event, ips)
            cmd_map = dict(((ip, cmd) for ip in ips))
            result_map = tools.run_command_on_cvms(cmd_map, cluster_config, log_on_error=False)
            done = set()
            for ip, (out, err, ret) in result_map.iteritems():
                if ret is None:
                    logger.error('Error executing command %s on ip %s', cmd, ip)
                    continue
                if ret == 0:
                    done.add(ip)

            ips = list(set(ips).difference(done))
            if ips:
                time.sleep(2.0)
                if time.time() - start_time >= timeout:
                    logger.error('Timed out(%ss) while waiting for marker file %s to %s on %s.', timeout, path, event, cvm_ips)
                    return False

        return True

    def _destroy_cluster(self, cvm_ip=None):
        """
        Destroy the cluster
        
        Args:
          cvm_ip: one CVM node from some cluster, default to use first node from
                  the current cluster
        
        Returns:
          True on Success, False otherwise.
        """
        logger = self.logger
        if not cvm_ip:
            cvm_ip = self._cvm_ips[0]
        ret = self._call_genesis_method(cvm_ip, NodeManager.configured)
        if isinstance(ret, RpcError):
            logger.error('Failed to destroy the cluster: Could not reach CVM at %s', cvm_ip)
            return False
        if not ret:
            logger.error('CVM at %s is not configured to be part of a cluster. refusing to destory it', cvm_ip)
            return False
        ret = self._call_genesis_method(cvm_ip, ClusterManager.svm_ips, valid=lambda x: x)
        if isinstance(ret, RpcError):
            logger.error('Could not get the CVM IPs in the cluster from node %s', cvm_ip)
            return False
        cvm_ips = ret
        return self._force_genesis_unconfig(cvm_ips)