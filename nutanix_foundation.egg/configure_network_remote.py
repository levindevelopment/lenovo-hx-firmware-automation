# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/configure_network_remote.py
# Compiled at: 2019-02-15 12:42:10
import imaging_context, time
from foundation import cvm_utilities as utils
from foundation import foundation_tools as tools
from foundation import folder_central as fc
from foundation.cvm_utilities import KVMHost, LinuxHost, ESXHost, HypervHost, RemoteNode, CVMGuest
from foundation.session_manager import set_session_id
from util.net.rpc import RpcError
GENESIS_RPC_CONFIGURE_IP_TIMEOUT_SECS = 60
GENESIS_RPC_GET_IP_TIMEOUT_SECS = 6

class CVMExtendedGuest(CVMGuest):

    @property
    def ip(self):
        return self.node.ipv6_address


class HostNetworkUtils(KVMHost):

    def __init__(self, *arg, **kwarg):
        super(LinuxHost, self).__init__(*arg, **kwarg)
        self.cvm = CVMExtendedGuest(self.node)

    @property
    def default_user(self):
        return 'nutanix'

    @property
    def ip(self):
        return self.node.ipv6_address

    def get_network_utils_egg_name(self):
        return 'nutanix_provision_network_utils-1.0-py2.7.egg'

    def get_network_utils_egg(self):
        return fc.get_provision_network_utils_egg(self.get_network_utils_egg_name())

    def get_remote_network_utils_egg_path(self):
        raise NotImplementedError

    def get_remote_network_script_file_name(self):
        raise NotImplementedError

    def get_remote_network_dst_path(self):
        return self.get_remote_network_utils_egg_path() + 'network_utils/' + self.get_remote_network_script_file_name()

    def get_remote_network_script_path(self):
        return self.get_remote_network_dst_path() + '.py'

    def get_remote_network_config_log_file(self):
        return self.get_remote_network_dst_path() + '.log'

    def paranthesize(self, command):
        return [
         '"'] + command + ['"']

    def apply_vlan_config(self):
        logger = self.node.get_logger()
        current_cvm_vlan_tag = self.node.cvm_vlan_id
        logger.info('Configuring %s/%s with vlan %d', self.node.current_hyp_type, self.node.arch, current_cvm_vlan_tag)
        src = self.get_network_utils_egg()
        dst = self.get_remote_network_utils_egg_path() + self.get_network_utils_egg_name()
        self.scp(src, dst)
        dtemp, err, ret = self.ssh(['test', '-f', dst], log_on_error=False)
        if ret:
            raise StandardError('Failed to stage %s script', dst)
        command = self.paranthesize([
         'cd', self.get_remote_network_utils_egg_path(), '&&',
         'python', '-m', 'zipfile', '-e', self.get_network_utils_egg_name(), '.'])
        logger.info('Unzipping the egg %s', self.get_network_utils_egg_name())
        self.ssh(command, log_on_error=True)
        self.set_permissions()
        remote_script = self.get_remote_network_script_path()
        command = self.paranthesize([
         'nohup', 'python', remote_script, '-v', str(current_cvm_vlan_tag),
         '>&'] + [self.get_remote_network_config_log_file(), '&'])
        logger.info('Running the command %s', (' ').join(command))
        self.ssh(command, log_on_error=True)
        time.sleep(10)
        logger.info('Pinging to check if %s is configured', self.node.cvm_ip)
        if tools.generic_ping(self.node.cvm_ip, retries=10, sleep_time=1):
            logger.info('Successfully changed vlan to %s & CVM IP to %s', current_cvm_vlan_tag, self.node.cvm_ip)
        else:
            msg = 'Something failed in configure_ip_and_network_setup. Please checkthe log file %s' % self.get_remote_network_config_log_file()
            raise StandardError(msg)


class KvmNetworkUtils(HostNetworkUtils):

    def get_remote_network_utils_egg_path(self):
        return '/root/nutanix-network-crashcart/'

    def get_remote_network_script_file_name(self):
        return 'configure_kvm_host_networking'

    def set_permissions(self):
        logger = self.node.get_logger()
        command = [
         '"find',
         self.get_remote_network_utils_egg_path() + 'network_utils/', '-type', 'f', '-not', '-name', '"*.pyc"',
         '-exec', 'chmod', '+x', '{}', '\\;"']
        logger.info('Setting permissions...')
        self.ssh(command, log_on_error=True)


class EsxNetworkUtils(HostNetworkUtils):

    def get_remote_network_utils_egg_path(self):
        command = [
         '"find', '.', '-name', 'Nutanix"']
        output, _, _ = self.ssh(command)
        output = output.strip()
        return output + '/firstboot/'

    def get_remote_network_script_file_name(self):
        return 'configure_esx_host_networking'

    def set_permissions(self):
        pass


class HypervNetworkUtils(HostNetworkUtils):
    """
    Treating HyperV as a an Linux host.
    Instead of running the script on host, will be running inside CVM using
    winsh utility available for hyperv hosts.
    """

    def scp(self, src, dst):
        return self.cvm.scp(src, dst, throw_on_error=False, timeout=10)

    def ssh(self, command, *args, **kwargs):
        return self.cvm.ssh(command, *args, **kwargs)

    def get_remote_network_utils_egg_path(self):
        return '/tmp/'

    def get_remote_network_script_file_name(self):
        return 'configure_hyperv_host_networking'

    def set_permissions(self):
        pass

    def paranthesize(self, command):
        return command


def get_hostnet_class(hostCls):
    host_to_net_map = {KVMHost: KvmNetworkUtils, ESXHost: EsxNetworkUtils, HypervHost: HypervNetworkUtils}
    for key in host_to_net_map.keys():
        if hostCls == key:
            return host_to_net_map[key]

    raise StandardError('Unknown NetworkUtil class')


def threaded_provision_network(node_config, helper_method, rpc_method, session_id, current_node_info, timeout=None):
    """
    This API is run in a different thread context.
    Calls genesis_rpc method to change cvm_ip (reusing the existing API), then
    detect the remote hypervisor type and apply/remove vlan accordingly.
    """
    set_session_id(session_id)
    logger = node_config.get_logger()

    def get_dict(node_config, access):
        if access == 'ipmi':
            return
        return {'address': getattr(node_config, access + '_ip', None), 'gateway': getattr(node_config, access + '_gateway', None), 
           'netmask': getattr(node_config, access + '_netmask', None)}

    request_json = {'args': map(lambda x: get_dict(node_config, x), [
              'cvm', 'hypervisor', 'ipmi'])}
    timeout = timeout or GENESIS_RPC_CONFIGURE_IP_TIMEOUT_SECS
    ret = helper_method(rpc_method, node_config.ipv6_address, timeout, request_json)
    if isinstance(ret, RpcError):
        raise StandardError('rpc client error, %s failed', str(ret.error))
    current_cvm_vlan_tag = current_node_info.get('current_cvm_vlan_tag')
    if node_config.cvm_vlan_id == current_cvm_vlan_tag or current_cvm_vlan_tag in (None,
                                                                                   0,
                                                                                   '0') and node_config.cvm_vlan_id in (None,
                                                                                                                        0,
                                                                                                                        '0'):
        logger.debug('Skipping provision vlan as current vlan %s is same as the one to be configured', current_cvm_vlan_tag)
        return
    context = imaging_context.get_context()
    if context == imaging_context.FIELD_VM:
        if node_config.cvm_vlan_id != current_cvm_vlan_tag:
            logger.debug('Running in CVM, but proceeding with configuring vlan %s, as node discovered through vlan sniffer and not provisioned yet', node_config.cvm_vlan_id)
    node_config.arch = utils.detect_remote_arch(node_config, node_config.ipv6_address)
    node_config.current_hyp_type = utils.detect_remote_hypervisor_type(node_config, node_config.ipv6_address)
    cls = utils.get_host_class(node_config)
    netcls = get_hostnet_class(cls)
    hostnet = netcls(node_config)
    hostnet.apply_vlan_config()
    return


def threaded_node_network_details(node, helper_method, rpc_method, timeout=None):
    """
    This API is run in a different thread context.
    calls genesis_rpc method to get cvm, hypervisor & ipmi ip information.
    """

    def get_dict(info, access):
        if info is None:
            return {}
        lookup_gateway = access + '_gateway'
        lookup_netmask = access + '_netmask'
        lookup_ip = access + '_ip'
        result = {lookup_ip: info.get('address'), lookup_netmask: info.get('netmask'), 
           lookup_gateway: info.get('gateway')}
        current_cvm_vlan_tag = info.get('vlan')
        if current_cvm_vlan_tag:
            result['current_cvm_vlan_tag'] = current_cvm_vlan_tag
        return result

    ipv6_address = node.get('ipv6_address')
    if not ipv6_address:
        raise StandardError('Invalid ipv6_address')
    timeout = timeout or GENESIS_RPC_GET_IP_TIMEOUT_SECS
    ret = helper_method(rpc_method, ipv6_address, timeout, {})
    if isinstance(ret, RpcError):
        raise StandardError('rpc client error, %s failed', rpc_method)
    result = {}
    for entry in map(lambda a, x: get_dict(a, x), ret, [
     'cvm', 'hypervisor', 'ipmi']):
        result.update(entry)

    result.update({'ipv6_address': ipv6_address})
    return result


def provision_network(global_config, helper_method, rpc_method, get_ip_rpc_method, session_id):
    """
    Configure IP on CVM/Host on the remote Node and apply network config passed
    in POST call. This happens in multiple threads created one per the number
    of nodes passed.
    
    NodeManager.get_ip method is also passed to get current network information
    and skip applying vlan if it is same as the currently configured vlan
    
    Args:
      global_config, helper & rpc genesis API that is to be called
    """

    def get_node_ipv6(node_config):
        return {'ipv6_address': node_config.ipv6_address}

    nodes = global_config.nodes
    nodes_json = map(lambda x: get_node_ipv6(x), nodes)
    current_node_info = tools.tmap(threaded_node_network_details, map(lambda x: (
     x, helper_method, get_ip_rpc_method), nodes_json))
    context = imaging_context.get_context()
    if context == imaging_context.FIELD_VM:
        exist_vlan_id = None
        for node in current_node_info:
            vlan = node.get('current_cvm_vlan_tag')
            try:
                if int(vlan):
                    exist_vlan_id = vlan
                    break
            except TypeError:
                pass
            except ValueError:
                pass

        if exist_vlan_id:
            for node in nodes:
                node.cvm_vlan_id = exist_vlan_id

    tools.tmap(threaded_provision_network, map(lambda x, y: (x, helper_method, rpc_method, session_id, y), nodes, current_node_info))
    return


def node_network_details(helper_method, rpc_method, nodes):
    """
    Get CVM, Hypervisor & IPMI IP information of the nodes using ipv6 link local
    address. Uses tmap to get the results in a separate thread and join the
    results to send it GUI
    """
    try:
        result = tools.tmap(threaded_node_network_details, map(lambda x: (x, helper_method, rpc_method), nodes))
        return {'nodes': result}
    except StandardError as e:
        if len(e.args) == 3:
            msg, exceptions, results = e.args
            nodes = []
            for exception, result in zip(exceptions, results):
                nodes.append(result or {'error': str(exception)})

            return {'nodes': nodes, 'error': msg}
        raise