# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/network_validation.py
# Compiled at: 2019-02-15 12:42:10
import logging, re, threading, time
from collections import defaultdict
from cluster.genesis.cluster_manager import ClusterManager
from cluster.genesis.node_manager import NodeManager
from util.net.rpc import RpcError
from foundation import foundation_tools
from foundation import new_threading_model as ntm
from foundation import session_manager
from foundation.imaging_step import ImagingStepNodeTask, ImagingStepClusterTask
from foundation.tinyrpc import call_genesis_method
STATE_DISABLE_DUP_ARP = 'Fixing common arp related issues'
STATE_GET_BACKPLANE_IP = 'Getting backplane mapping from genesis'
STATE_GET_IP = 'Getting current IP config'
STATE_ARP_SCAN = 'Starting arp-scan to check for conflicts'
STATE_CONFIG_IP = 'Configuring IPs to check connectivity'
STATE_PING = 'Checking connectivity between CVM/Host, CVM/CVM'
VALIDATION_TIMEOUT_S = 180
ACTION = 'validation'
TIMEOUT_CONFIGURE_IP_VIA_GENESIS = 300
DEFAULT_LOGGER = logging.getLogger(__file__)
MAX_ATTEMPTS = 5
RETRY_INTERVAL = 10

def parse_ifconfig(stdout_ifconfig):
    """
    ENG-175958: Output of ifconfig is different in Gentoo and Centos.
    Args:
      stdout_ifconfig: Output of ifconfig either from Gentoo or Centos.
    Returns:
      (ip, broadcast_ip, netmask) on success.
    """
    gentoo_regex = re.compile('inet addr:([.0-9]+)\\s+Bcast:([.0-9]+)\\s+Mask:([.0-9]+)')
    centos_regex = re.compile('inet ([.0-9]+)\\s+netmask ([.0-9]+)\\s+broadcast ([.0-9]+)')
    parsed = gentoo_regex.findall(stdout_ifconfig)
    if parsed:
        return parsed[0]
    parsed = centos_regex.findall(stdout_ifconfig)
    if not parsed:
        raise StandardError('Unable to parse ifconfig = %s output.' % stdout_ifconfig)
    else:
        ip, netmask, broadcast_ip = parsed[0]
        return (
         ip, broadcast_ip, netmask)


def _fetch_backplane_ips_via_genesis(config):
    """
    Ask genesis for a mapping of cvm_ip to (cvm_backplane_ip, host_backplane_ip).
    Args:
      config : ClusterConfig object.
    Returns:
      (True, ip_tuple) on success.
      (False, errmsg) on failure.
      ip_tuple: dictionary mapping svm external IP to a tuple of
                      (svp backplane ip, host backplane ip).
    """
    if config.enable_ns is not True:
        return (False, 'Network segmentation is disabled for this cluster')
    cvm_ips = [ member.cvm_ip for member in config.cluster_members ]
    bp_subnet = config.backplane_subnet
    bp_netmask = config.backplane_netmask
    ret = call_genesis_method('localhost', ClusterManager.allocate_cluster_backplane_ips, (
     cvm_ips, bp_subnet, bp_netmask))
    if isinstance(ret, RpcError):
        return (False, 'RPC error occurred for allocate_cluster_backplane_ips')
    return ret


def configure_ip_via_genesis(node_position, cvm_ipv6, config_tuple, log_on_error=True, logger=None):
    """
    config_tuple is a tuple of (cvm_ip, hypervisor_ip, ipmi_ip), where each
    element is a dict with keys: 'address', 'netmask', 'gateway'.
    Returns True on success.
    """
    if not logger:
        logger = DEFAULT_LOGGER
    ret = call_genesis_method(cvm_ipv6, NodeManager.configure_ip, config_tuple, timeout_secs=TIMEOUT_CONFIGURE_IP_VIA_GENESIS)
    if isinstance(ret, RpcError):
        if log_on_error:
            logger.error('Error in setting IP %s for node at position %s. Error: %s Please try again. If this error is consistent, please confirm that genesis is up on the target node and that this machine can ping IPv6 IP %s' % (
             config_tuple, node_position, str(RpcError), cvm_ipv6))
        return False
    if len(ret) == 2 and not ret[0]:
        if log_on_error:
            logger.error('NodeManager.configure_ip RPC failed with the following reason %s' % ret[1])
        return False
    return True


def _configure_backplane_ip_via_genesis(config, cvm_ip, cvm_bp_ip, host_bp_ip, timeout_secs=40, log_on_error=True):
    """
    config_tuple is a tuple of (cvm_ip, hypervisor_ip), where each
    element is a dict with keys: 'address', 'netmask'.
    Returns True on success, False otherwise.
    """
    try:
        logger = config.get_logger()
    except:
        logger = DEFAULT_LOGGER

    bp_vlan = config.backplane_vlan
    bp_netmask = config.backplane_netmask
    ret = call_genesis_method(cvm_ip, NodeManager.configure_backplane_ip, (
     bp_netmask, cvm_bp_ip, host_bp_ip, bp_vlan), timeout_secs=timeout_secs)
    if isinstance(ret, RpcError):
        if log_on_error:
            logger.error('Error in setting Backplane IPs (CVM: %s , Host: %s) for node at position %s. Please try again. If this error is consistent, please confirm that genesis is up on the target node and that this machine can ping IP %s' % (
             cvm_bp_ip, host_bp_ip, config.node_position, cvm_ip))
        return False
    ret, reason = ret
    if not ret:
        if log_on_error:
            logger.error('NodeManager.configure_backplane_ip RPC failed with the following reason %s' % reason)
        return False
    return True


def _configure_temporary_cvm_ip_via_genesis(config, cvm_ipv6, interface, config_tuple, timeout_secs=40, log_on_error=True):
    """
    Configure temporary interface on cvm, required for vlan tagged kvm nodes.
    
    interface is network interface to be configured on cvm.
    config_tuple contains dictionary cvm_ip with keys:
    'address', 'netmask', 'gateway'.
    Returns True on success.
    """
    logger = config.get_logger()
    ret = call_genesis_method(cvm_ipv6, NodeManager.configure_temporary_cvm_ip, (
     interface, config_tuple), timeout_secs=timeout_secs)
    if isinstance(ret, RpcError):
        if log_on_error:
            logger.error('Error in setting IP %s on temporary interface %s for node at position %s. Please try again. If this error is consistent, please confirm that genesis is up on the target node and that this machine can ping IPv6 IP %s', config_tuple, interface, config.node_position, cvm_ipv6)
        return False
    if not ret:
        logger.error('Failed to configure temporary cvm interface %s', interface)
        return False
    return True


def get_ip_via_genesis(config, cvm_ipv6, timeout_secs=40, log_on_error=True):
    """
    Get ip config via genesis.
    Returns the Node IP configuration as tuple
      (cvm_ip, hypervisor_ip, ipmi_ip), where each element is a dict with
      keys:
        'address', 'netmask', 'gateway'.
    Raises Exception on RpcError.
    """
    logger = config.get_logger()
    remaining_attempts = MAX_ATTEMPTS
    while remaining_attempts:
        ret = call_genesis_method(cvm_ipv6, NodeManager.get_ip, timeout_secs=timeout_secs)
        if isinstance(ret, RpcError):
            if log_on_error:
                logger.error('Error in getting IP from node at position %s.Trying again in %s seconds. Remaining attempts: %s' % (
                 config.node_position, RETRY_INTERVAL, remaining_attempts))
                time.sleep(RETRY_INTERVAL)
        else:
            return ret
        remaining_attempts -= 1

    if log_on_error:
        logger.error('Error in getting IP from node at position %s.Please try again. If this error is consistent, please confirm that genesis is up on the target node and that this machine can ping IPv6 IP %s' % (
         config.node_position, cvm_ipv6))
    raise StandardError('Failed to get original IP')


def _get_backplane_ip_via_genesis(config, cvm_ipv6, timeout_secs=40, log_on_error=True):
    """
    Get backplane ip config via genesis.
    Returns the Node backplane IP configuration as tuple
    (svm_ip, hypervisor_ip), where each element is a dict with keys:
    'address', 'netmask'.
    Raises Exception on RpcError.
    """
    logger = config.get_logger()
    ret = call_genesis_method(cvm_ipv6, NodeManager.get_backplane_ip, timeout_secs=timeout_secs)
    if isinstance(ret, RpcError):
        if log_on_error:
            logger.error('Error in getting backplane IP from node at position %s.Please try again. If this error is consistent, please confirm that genesis is up on the target node and that this machine can ping IPv6 IP %s' % (
             config.node_position, cvm_ipv6))
            raise StandardError('Failed to get original backplane IP')
    return ret


def _get_temporary_ip_via_genesis(config, cvm_ipv6, interface, timeout_secs=40, log_on_error=True):
    """
    Get temporary ip config via genesis for interface provided.
    Required for vlan tagged kvm nodes.
    Returns the Node IP configuration as a list of dict with keys:
      'address', 'netmask', 'gateway'.
    raise Exception on RpcError
    """
    logger = config.get_logger()
    ret = call_genesis_method(cvm_ipv6, NodeManager.get_temporary_cvm_ip, (
     interface,), timeout_secs=timeout_secs)
    if isinstance(ret, RpcError):
        if log_on_error:
            logger.error('Error in getting temporary IP of interface %s from node at position %s. Please try again. If this error is consistent, please confirm that genesis is up on the target node and that this machine can ping IPv6 IP %s', interface, config.node_position, cvm_ipv6)
            raise StandardError('Failed to get temporary IP.')
    return [ret]


def _temporary_ip_required(node_config):
    """
    Finds out if temporary ip management is required.
    Returns True if required, False otherwise.
    """
    if not node_config:
        return False
    intf = getattr(node_config, 'current_network_interface', None)
    if not intf:
        return False
    return len(intf.split('.')) > 1


def _generic_arp_scan(interface, ip=None, netmask=None, ip_list=None):
    """
     Perform an ARP scan on
        - A list of IPs if ip_list is provided.
        - A subnet from ip and netmask.
        - A subnet generated from the network interface IP address and
          netmask if nothing provided.
     Return a dict of ip/mac mapping. eg,
        {'10.1.80.1':[('60:f8:de:ad:be:ef','some vendor')]}
     arp-scan can raise an error if interface does not exist.
    """
    if not ip_list:
        ip_list = []
    re_ip_mac_vendor = re.compile('([0-9.]+)\t([0-9a-f:]+)\t(.*)')
    cmds = ['sudo', 'arp-scan', '-N', '-I', interface]
    if ip_list:
        cmds.extend(ip_list)
    else:
        if ip and netmask:
            cmds.append('%s:%s' % (ip, netmask))
        else:
            cmds.append('-l')
    out, _, _ = foundation_tools.system(None, cmds)
    ip_mac_dict = defaultdict(list)
    for line in out.splitlines():
        for ip, mac, vendor in re_ip_mac_vendor.findall(line):
            ip_mac_dict[ip].append((mac, vendor))

    return ip_mac_dict


def _is_same_config_tuple(tuple1, tuple2):
    """
    compare tuple of used in get_ip and configure_ip
    Return True if tuple1 == tuple2 or both are None.
    """
    if tuple1 and tuple2:
        for item1, item2 in zip(tuple1, tuple2):
            if item1 and item2:
                for k, v in item1.items():
                    if k not in item2 or item2[k] != v:
                        return False

                for k, v in item2.items():
                    if k not in item1 or item1[k] != v:
                        return False

            else:
                return item1 == item2

    else:
        if not tuple1 and not tuple2:
            return True
    return False


def _is_node_in_phoenix(node_config):
    """
    NDP will report hypervisor: "phoenix" on phoenix nodes.
    """
    return getattr(node_config, 'hypervisor', None) == 'phoenix'


def _get_interface_by_ipv6(config, cvm_ipv6, retry=3):
    """
    Find the interface name by IPv6 IP.
    Raises StandardError if unable to do so.
    """
    ipv6_ip = cvm_ipv6.split('%')[0]
    for _ in range(retry):
        stdout, _, retval = foundation_tools.ssh(config, cvm_ipv6, [
         'ifconfig'], throw_on_error=False, user='root')
        if retval == 0:
            ifaces = stdout.split('\n\n')
            for iface in ifaces:
                if ipv6_ip in iface:
                    return iface.split(' ')[0].split(':')[0]

    raise StandardError('Failed to get interface of IP: %s' % cvm_ipv6)


def _configure_ip_via_ssh(config, cvm_ipv6, config_tuple, timeout_secs=40, log_on_error=True, retry=3):
    """
    Configure phoenix node to CVM IP using ssh.
    """
    iface = _get_interface_by_ipv6(config, cvm_ipv6)
    cvm_ip = config_tuple[0]
    for _ in range(retry):
        _, _, retval = foundation_tools.ssh(config, cvm_ipv6, [
         'ifconfig', iface, cvm_ip['address'], 'netmask', cvm_ip['netmask']], throw_on_error=False, user='root', log_on_error=log_on_error, timeout=timeout_secs)
        foundation_tools.ssh(config, cvm_ipv6, [
         'route', 'add', 'default', 'gw', cvm_ip['gateway']], throw_on_error=False, user='root', log_on_error=log_on_error, timeout=timeout_secs)
        if retval == 0:
            return True

    return False


def _configure_bp_ip_in_phoenix(node_config):
    """
    Configure the backplane ip on the same interface as cvm ip.
    Returns True on success, false otherwise.
    """
    iface = node_config.bp_iface
    ip = node_config.new_bp_ip_config[0]['address']
    netmask = node_config.new_bp_ip_config[0]['netmask']
    vlan = node_config.backplane_vlan or 0
    cmds = [['ifconfig', iface + ':0', ip, 'netmask', netmask]]
    if vlan > 0:
        cmds = [['vconfig', 'add', iface, str(vlan)],
         [
          'ifconfig', iface + '.' + str(vlan), ip, 'netmask', netmask]]
    for cmd in cmds:
        out, err, ret = foundation_tools.ssh(node_config, node_config.cvm_ip, cmd, throw_on_error=False, user='root')
        if ret:
            message = 'Failed to execute command: %s. ret: %s\nstdout: %s\nstderr: %s\n' % (
             cmd, ret, out, err)
            node_config.get_logger().error(message)
            return False

    return True


def _get_bp_ip_via_ssh(config, cvm_ipv6, iface):
    """
    Gets backplane ip if configured as ({"netmask" : <>, "ip" : <>})
    Returns ({}, {}, {}) otherwise.
    """
    vlan = config.backplane_vlan
    stdout_ifconfig, _, retval1 = foundation_tools.ssh(config, cvm_ipv6, [
     'ifconfig', iface + '.' + str(vlan)], throw_on_error=False, user='root', log_on_error=False)
    try:
        ip, _, netmask = parse_ifconfig(stdout_ifconfig)
        if ip and netmask:
            return ({'address': ip, 'netmask': netmask}, {}, {})
    except:
        pass

    return ({}, {}, {})


def _get_ip_via_ssh(config, cvm_ipv6, timeout_secs=40, log_on_error=True, retry=3):
    """
    Get IPv4 IP of phoenix node.
    When NS is enabled, also tries to get backplane ip and sets it in
      config.old_bp_ip_config
    Returns None if no IPv4 IP configured.
    """
    logger = config.get_logger()
    iface = _get_interface_by_ipv6(config, cvm_ipv6)
    ret = (None, None, None)
    for _ in range(retry):
        try:
            foundation_tools.ssh(config, cvm_ipv6, [
             'sysctl', '-w', 'net.ipv4.conf.default.arp_filter=1'], throw_on_error=False, user='root', log_on_error=log_on_error, timeout=timeout_secs)
            foundation_tools.ssh(config, cvm_ipv6, [
             'sysctl', '-w', 'net.ipv4.conf.all.arp_filter=1'], throw_on_error=False, user='root', log_on_error=log_on_error, timeout=timeout_secs)
            stdout_ifconfig, _, retval1 = foundation_tools.ssh(config, cvm_ipv6, [
             'ifconfig', iface], throw_on_error=False, user='root', log_on_error=log_on_error, timeout=timeout_secs)
            stdout_route, _, retval2 = foundation_tools.ssh(config, cvm_ipv6, [
             'route', '-n'], throw_on_error=False, user='root', log_on_error=log_on_error, timeout=timeout_secs)
            if retval1 == 0 and retval2 == 0:
                ip, _, netmask = parse_ifconfig(stdout_ifconfig)
                gw = None
                for line in stdout_route.splitlines():
                    if len(line.split()) != 8:
                        continue
                    _, _gw, _, _, _, _, _, _iface = line.split()
                    if _iface == iface and _gw != '0.0.0.0':
                        gw = _gw

                if gw and ip and netmask:
                    ret = (
                     dict(address=ip, netmask=netmask, gateway=gw), None, None)
                    break
        except (StandardError, IndexError) as e:
            logger.exception('Failed to read the ip address of %s, (%s)' % (
             iface, e))

    if config.enable_ns:
        config.old_bp_ip_config = _get_bp_ip_via_ssh(config, cvm_ipv6, iface)
        config.bp_iface = iface
    return ret


def _check_backplane_vlan(config, cvm_ip, vlan):
    """
    Check if the backplane vlan on given ip is same as `vlan`.
    Returns False in case of any error.
    """
    logger = config.get_logger()
    ret = call_genesis_method(cvm_ip, NodeManager.get_current_cvm_backplane_vlan_tag)
    if isinstance(ret, RpcError):
        logger.error('Failed to get the backplane vlan')
        return False
    ret, val = ret
    if ret is False:
        logger.warning('get_current_cvm_backplane_vlan_tag returned False. Assuming no backplane vlan is configured')
        return False
    return val == vlan


class ValidationStepGetBackplaneIPs(ImagingStepClusterTask):
    """
    Barrier step to get backplane ips.
    """

    def get_progress_timing(self):
        return [
         (
          STATE_GET_BACKPLANE_IP, 1)]

    def run(self):

        def assign_backplane_ip_dict(member, bp_cvm_ip, bp_host_ip, netmask):
            member.new_bp_ip_config = (
             {'address': bp_cvm_ip, 
                'netmask': netmask},
             {'address': bp_host_ip, 
                'netmask': netmask})

        cluster_config = self.config
        logger = self.logger
        enable_ns = cluster_config.enable_ns
        if not enable_ns:
            logger.info('Network segmentation is disabled for this cluster')
            return
        netmask = cluster_config.backplane_netmask
        auto_assign = getattr(cluster_config, 'backplane_auto_assign_ips', True)
        if auto_assign is False:
            logger.info('auto-assignment of backplane ips is False')
            for member in cluster_config.cluster_members:
                assign_backplane_ip_dict(member, member.backplane_cvm_ip, member.backplane_host_ip, netmask)

            return
        self.set_status(STATE_GET_BACKPLANE_IP)
        logger.info(STATE_GET_BACKPLANE_IP)
        ret, val = _fetch_backplane_ips_via_genesis(cluster_config)
        if ret is False:
            error = 'Failed to get backplane ips from genesis: %s' % val
            cluster_config = self.config
            cluster_config.results['backend_error'] = error
            raise StandardError(error)
        for cvm_ip, backplane_ips in val.iteritems():
            for member in cluster_config.cluster_members:
                if member.cvm_ip == cvm_ip:
                    member.backplane_cvm_ip = backplane_ips[0]
                    member.backplane_host_ip = backplane_ips[1]
                    assign_backplane_ip_dict(member, backplane_ips[0], backplane_ips[1], netmask)


class ValidationStepDisableDupArp(ImagingStepNodeTask):

    def get_progress_timing(self):
        return [(STATE_DISABLE_DUP_ARP, 1)]

    def run(self):
        node_config = self.config
        if getattr(node_config, 'hypervisor', '') != 'kvm':
            return
        self.set_status(STATE_DISABLE_DUP_ARP)
        cvm_ipv6 = node_config.ipv6_address
        out, err, ret = foundation_tools.ssh(node_config, cvm_ipv6, [
         'ssh', 'root@192.168.5.1',
         '"uname"'], log_on_error=False, throw_on_error=False)
        if ret or 'linux' not in out.lower():
            return
        for _ in range(3):
            _, _, retval = foundation_tools.ssh(node_config, cvm_ipv6, [
             'ssh', 'root@192.168.5.1',
             '"sysctl -w net.ipv4.conf.br0.arp_ignore=1"'], throw_on_error=False)
            if retval == 0:
                return


class ValidationStepGetIp(ImagingStepNodeTask):

    def get_progress_timing(self):
        return [
         (
          STATE_GET_IP, 1)]

    def run(self):
        node_config = self.config
        logger = self.logger
        enable_ns = node_config.enable_ns
        self.set_status(STATE_GET_IP)
        node_ip = node_config.cvm_ip
        if not (enable_ns and getattr(node_config, 'process_backplane_only', False)):
            if getattr(node_config, 'ipv6_address', None):
                node_ip = node_config.ipv6_address
        logger.info('Reading present IP configuration')
        ip_config = None
        is_node_in_phoenix = _is_node_in_phoenix(node_config)
        try:
            if is_node_in_phoenix:
                ip_config = _get_ip_via_ssh(node_config, node_ip)
            else:
                ip_config = get_ip_via_genesis(node_config, node_ip)
                if _temporary_ip_required(node_config):
                    temp_ip = _get_temporary_ip_via_genesis(node_config, node_ip, node_config.current_network_interface)
        except StandardError as e:
            message = 'Failed to get IP configuration: %s' % str(e)
            node_config.results[node_config.cvm_ip].append(message)
            raise StandardError(message)

        logger.info('Present IP configuration is: %s' % str(ip_config))
        node_config.old_ip_config = ip_config
        if _temporary_ip_required(node_config):
            logger.info('Temporary IP configuration is: %s' % str(temp_ip))
            node_config.old_temp_ip_config = temp_ip
        if enable_ns:
            if not is_node_in_phoenix:
                try:
                    node_config.old_bp_ip_config = _get_backplane_ip_via_genesis(node_config, node_ip)
                except StandardError as e:
                    message = 'Failed to get backplane IP configuration: %s' % str(e)
                    node_config.results[node_config.cvm_ip].append(message)
                    raise StandardError(message)

            logger.info('Present Backplane IP configuration is: %s' % str(node_config.old_bp_ip_config))
        return


class ValidationStepArpScan(ImagingStepClusterTask):

    def get_progress_timing(self):
        return [
         (
          STATE_ARP_SCAN, 1)]

    def run(self):
        cluster_config = self.config
        logger = self.logger
        enable_ns = cluster_config.enable_ns
        node_configs = cluster_config.cluster_members
        self.set_status(STATE_ARP_SCAN)
        logger.info(STATE_ARP_SCAN)
        old_ip_dict = defaultdict(list)
        ip_list_dict = defaultdict(list)
        bp_old_ip_dict = defaultdict(list)
        bp_ip_list_dict = defaultdict(list)
        for node in node_configs:
            if getattr(node, 'old_ip_config', None):
                for item in node.old_ip_config:
                    if item:
                        old_ip_dict[item['address']].append(node)

            if enable_ns and getattr(node, 'old_bp_ip_config', None):
                for item in node.old_bp_ip_config:
                    if item:
                        bp_old_ip_dict[item['address']].append(node)

            if getattr(node, 'old_temp_ip_config', None):
                logger.info('Old temporary IP is %s' % node.old_temp_ip_config)
                old_ip_dict[node.old_temp_ip_config[0]['address']].append(node)
            if _is_node_in_phoenix(node):
                logger.info('This node is running phoenix, IP conflicts in hypervisor IPs or IPMI IPs will not be tested')
                ip_list_dict[node.cvm_ip].append(node)
                if enable_ns:
                    logger.info('Host backplane IP conflicts will not be tested as well')
                    bp_ip_list_dict[getattr(node, 'backplane_host_ip')].append(node)
            else:
                ip_fields = [
                 'cvm_ip', 'hypervisor_ip', 'ipmi_ip']
                for attr in ip_fields:
                    if getattr(node, attr, None):
                        ip_list_dict[getattr(node, attr)].append(node)

                if enable_ns:
                    ip_fields = [
                     'backplane_cvm_ip', 'backplane_host_ip']
                    for attr in ip_fields:
                        bp_ip_list_dict[getattr(node, attr)].append(node)

        logger.info('Current IP usage is %s', str(sorted(ip_list_dict.keys())))
        if enable_ns:
            logger.info('Current backplane IP usage is %s', str(sorted(bp_ip_list_dict.keys())))
        for ip, nodes in ip_list_dict.items() + bp_ip_list_dict.items():
            if len(nodes) > 1:
                message = 'IP %s is being used in %d nodes' % (ip, len(nodes))
                logger.info(message)
                for node in nodes:
                    cluster_config.results[ip].append('IP appeared more than once (%d)' % len(nodes))

                raise StandardError(message)

        def perform_arp(inf, ip_map, old_ip_map):
            ip_mac_dict = _generic_arp_scan(inf, ip_list=ip_map.keys())
            ips_missing_in_arp = []
            if ip_mac_dict:
                for ip in ip_map.keys():
                    if ip not in ip_mac_dict.keys():
                        ips_missing_in_arp.append(ip)

                for ip, mac_vendors in ip_mac_dict.items():
                    unique_macs = set((mac for mac, vendor in mac_vendors))
                    if ip in old_ip_map and len(old_ip_map[ip]) >= len(unique_macs):
                        logger.warn('IP %s is being used by %s, and will be reconfigured to avoid confliction' % (
                         ip, str(mac_vendors)))
                        continue
                    for mac, vendor in mac_vendors:
                        logger.warn('IP(%s) in use by %s(%s)' % (ip, mac, vendor))
                        cluster_config.results[ip].append('IP in use by %s(%s)' % (
                         mac, vendor))
                        for node in ip_map[ip]:
                            logger.warn("Cannot configure IP %s, it's being used by %s(%s)" % (
                             ip, mac, vendor))

            else:
                ips_missing_in_arp = ip_map.keys()
            return ips_missing_in_arp

        ips_not_in_arp = perform_arp('eth0', ip_list_dict, old_ip_dict)
        try:
            ips_not_in_arp.remove(foundation_tools.get_interface_ip())
        except StandardError:
            pass

        if enable_ns:
            try:
                foundation_tools.system(cluster_config, ['sudo', 'ifconfig', 'eth2', 'up'], throw_on_error=False)
                ips_not_in_arp.extend(perform_arp('eth2', bp_ip_list_dict, bp_old_ip_dict))
                try:
                    ips_not_in_arp.remove(foundation_tools.get_interface_ip(ifname='eth2'))
                except StandardError:
                    pass

            except StandardError as exp:
                cluster_config.results['backend_error'] = str(exp)

        logger.info('IPs not reported by arp-scan but in user input: %s' % ips_not_in_arp)
        ips_to_configure = []
        for ip in ips_not_in_arp:
            if ip in old_ip_dict:
                logger.warn('IP %s is already configured, and will be reconfigured to avoid conflict' % ip)
            else:
                ips_to_configure.append(ip)

        cmd = [
         'ping', '-w6']
        for ip in ips_to_configure:
            try:
                foundation_tools.system(None, cmd + [ip], log_on_error=False)
                cluster_config.results[ip].append('IP in use in network')
            except StandardError as exp:
                continue

        if cluster_config.results:
            raise StandardError('IP in use')
        return


class ValidationStepConfigIp(ImagingStepNodeTask):

    def get_progress_timing(self):
        return [
         (
          STATE_CONFIG_IP, 2)]

    def run(self):
        node_config = self.config
        logger = self.logger
        enable_ns = node_config.enable_ns
        self.set_status(STATE_CONFIG_IP)
        logger.info(STATE_CONFIG_IP)
        node_ip = node_config.cvm_ip
        is_node_in_phoenix = _is_node_in_phoenix(node_config)
        if not (enable_ns and getattr(node_config, 'process_backplane_only', False)):
            if getattr(node_config, 'ipv6_address', None):
                node_ip = node_config.ipv6_address
        if enable_ns:
            if not is_node_in_phoenix:
                bp_vlan = node_config.backplane_vlan
                ip_configured_correctly = _is_same_config_tuple(node_config.old_bp_ip_config, node_config.new_bp_ip_config)
                ip_configured_correctly &= _check_backplane_vlan(node_config, node_ip, bp_vlan)
                if ip_configured_correctly:
                    logger.info('Backplane IPs are already configured correctly')
                else:
                    config_tuple = node_config.new_bp_ip_config
                    cvm_bp_ip = node_config.backplane_cvm_ip
                    host_bp_ip = node_config.backplane_host_ip
                    ret = _configure_backplane_ip_via_genesis(node_config, node_ip, cvm_bp_ip, host_bp_ip)
                    if not ret:
                        node_config.results[node_config.cvm_ip].append('Failed to configure backplane IPs')
                        raise StandardError('Failed to configure backplane IP')
                    logger.info('Backplane IPs are configured to %s' % str(config_tuple))
        if enable_ns and node_config.process_backplane_only:
            logger.info('Not proceeding to configure cvm/host/ipmi ips')
            return
        ip_configured_correctly = False
        if _temporary_ip_required(node_config):
            ip_configured_correctly = _is_same_config_tuple(node_config.old_temp_ip_config[0:1], node_config.new_ip_config[0:1])
            ip_configured_correctly &= _is_same_config_tuple(node_config.old_ip_config[1:3], node_config.new_ip_config[1:3])
        else:
            ip_configured_correctly = _is_same_config_tuple(node_config.old_ip_config, node_config.new_ip_config)
        if not ip_configured_correctly:
            config_tuple = node_config.new_ip_config
            if is_node_in_phoenix:
                logger.info('This node is running phoenix,  Hypervisor IP and IPMI IP will not be configured')
                ret = _configure_ip_via_ssh(node_config, node_ip, config_tuple)
            else:
                if _temporary_ip_required(node_config):
                    ret = _configure_temporary_cvm_ip_via_genesis(node_config, node_ip, node_config.current_network_interface, config_tuple[0])
                    if ret:
                        config_list = list(config_tuple)
                        localhost_ip = dict(address='127.0.0.2', netmask='255.255.255.0', gateway='127.0.0.2')
                        config_list[0] = localhost_ip
                        ret = configure_ip_via_genesis(node_config.node_position, node_ip, tuple(config_list), logger=node_config.get_logger())
                else:
                    ret = configure_ip_via_genesis(node_config.node_position, node_ip, config_tuple, logger=node_config.get_logger())
            if not ret:
                node_config.results[node_config.cvm_ip].append('Failed to config IP')
                raise StandardError('Failed to config IP')
            else:
                node_config.ip_changed = True
                logger.info('IP is configured to %s' % str(config_tuple))
        if enable_ns and is_node_in_phoenix:
            old = node_config.old_bp_ip_config
            new = node_config.new_bp_ip_config
            if old and old[0] == new[0]:
                logger.info('Backplane CVM IP already configured in Phoenix')
            else:
                ret = _configure_bp_ip_in_phoenix(node_config)
                if not ret:
                    node_config.results[node_config.cvm_ip].append('Failed to configure backplane IPs')
                    raise StandardError('Failed to configure backplane IP')
                logger.info('Backplane IP configured to %s' % str(new[0]))
        return


class ValidationStepBarrier(ImagingStepClusterTask):
    """
    Barrier to wait for all nodes finished ConfigIP.
    """

    def run(self):
        pass


class ValidationStepPingAll(ImagingStepNodeTask):

    def __init__(self, *args, **kwargs):
        super(ValidationStepPingAll, self).__init__(*args, **kwargs)
        node_config = self.config
        logger = self.logger
        node_configs = getattr(self.config, 'cluster_members', [
         self.config])
        self.node_configs = node_configs
        self.ip_list = []
        for node in node_configs:
            if node == node_config:
                if not _is_node_in_phoenix(node) and not _temporary_ip_required(node):
                    for attr in ['hypervisor_ip']:
                        self.ip_list.append(getattr(node, attr))

                continue
            if _is_node_in_phoenix(node):
                logger.info('This node is running phoenix, hypervisor and backplane connectivity will not be tested')
                for attr in ['cvm_ip']:
                    self.ip_list.append(getattr(node, attr))

            elif _temporary_ip_required(node):
                for attr in ['cvm_ip']:
                    self.ip_list.append(getattr(node, attr))

            else:
                for attr in ['cvm_ip', 'hypervisor_ip']:
                    self.ip_list.append(getattr(node, attr))

        if getattr(self.config, 'setup_replication', False):
            target_cluster_name = self.config.replication_target_cluster
            for cluster in session_manager.get_global_config(session_id=node_config._session_id).clusters:
                if cluster.cluster_name == target_cluster_name:
                    self.ip_list.extend([ node.cvm_ip for node in cluster.cluster_members ])
                    break
            else:
                raise StandardError('Could not find target cluster %s in clusters' % target_cluster_name)

    def get_progress_timing(self):
        return [
         (
          STATE_PING, 0.1 * len(self.ip_list) + 0.1)]

    def run(self):
        node_config = self.config
        logger = self.logger
        node_configs = self.node_configs
        enable_ns = node_config.enable_ns
        self.set_status(STATE_PING)
        logger.info(STATE_PING)
        if enable_ns:
            for node in node_configs:
                if _is_node_in_phoenix(node):
                    self.ip_list.extend([node.backplane_cvm_ip])
                    continue
                if node == node_config:
                    self.ip_list.extend([node.backplane_cvm_ip, node.backplane_host_ip])
                    continue
                if not _temporary_ip_required(node):
                    self.ip_list.extend([node.backplane_cvm_ip, node.backplane_host_ip])

        cvm_ip = node_config.cvm_ip
        error_count = 0
        for target in self.ip_list:
            try:
                if _is_node_in_phoenix(node_config):
                    user = 'root'
                    foundation_tools.ssh(node_config, cvm_ip, [
                     'ping', '-w6', '-c3', target], user=user, timeout=15)
                else:
                    foundation_tools.ssh(node_config, cvm_ip, [
                     'ping', '-w6', '-c3', target], timeout=15)
            except StandardError:
                node_config.results[target].append('Unreachable from %s' % cvm_ip)
                error_count += 1

        if error_count:
            message = '%d unreachable nodes detected from %s' % (error_count, cvm_ip)
            if not node_config.nv_recover_on_fail:
                raise StandardError(message)
            if getattr(node_config, 'ip_changed', False):
                config_tuple = getattr(node_config, 'old_ip_config', (None, None, None))
                logger.info('Trying to recover IP to %s.' % str(config_tuple))
                req_keys = [
                 'address', 'netmask', 'gateway']
                for config in config_tuple:
                    for key in config.keys():
                        if key not in req_keys:
                            config.pop(key)

                ret = configure_ip_via_genesis(node_config.node_position, node_config.ipv6_address, tuple(config_tuple), logger=node_config.get_logger())
                if ret:
                    msg = 'Falling back to old ip configuration'
                    logger.info(msg)
                else:
                    msg = 'Failed to recover IP, giving up.'
                    logger.error(msg)
                raise StandardError('%s. %s' % (message, msg))
        else:
            if getattr(node_config, 'fc_workflow', False):
                global_config = self.config.get_root()
                some_ip = node_config.phoenix_ip
                global_config.foundation_ip = foundation_tools.get_my_ip(some_ip)
        return


def run_validation_tasks(global_config):
    graph = global_config.graph
    logging.info('Validating')
    ntm.parallel_executor(graph, global_config)
    logging.info('Done')
    return ntm.get_ndone_nerror(global_config)


def validate_and_initialize(global_config):
    for node_config in global_config.nodes:
        node_config.old_ip_config = None
        node_config.old_temp_ip_config = None
        ipmi_info = None
        has_valid_ipmi_info = all(map(lambda attr: getattr(node_config, attr, None), [
         'ipmi_ip', 'ipmi_netmask', 'ipmi_gateway']))
        if has_valid_ipmi_info:
            ipmi_info = {'address': node_config.ipmi_ip, 'netmask': node_config.ipmi_netmask, 
               'gateway': node_config.ipmi_gateway}
        node_config.new_ip_config = (
         {'address': node_config.cvm_ip, 
            'netmask': node_config.cvm_netmask, 
            'gateway': node_config.cvm_gateway},
         {'address': node_config.hypervisor_ip, 
            'netmask': node_config.hypervisor_netmask, 
            'gateway': node_config.hypervisor_gateway},
         ipmi_info)

    return


def generate_validation_graph(global_config):
    validate_and_initialize(global_config)
    validation_tasks = [
     ValidationStepDisableDupArp,
     ValidationStepGetBackplaneIPs,
     ValidationStepGetIp,
     ValidationStepArpScan,
     ValidationStepConfigIp,
     ValidationStepBarrier,
     ValidationStepPingAll]
    graph = ntm.generate_graph(global_config, validation_tasks)
    global_config.graph = graph
    global_config.action = ACTION
    global_config.results = defaultdict(list)
    return graph


def do_validation_threaded_worker(global_config):
    try:
        ret = run_validation_tasks(global_config)
        if ret[1]:
            session_manager.mark_session_failure(global_config._session_id)
        else:
            session_manager.mark_session_success(global_config._session_id)
        return ret
    except:
        logging.exception('validaion failed')
        return (-999, -999)


def do_validation_threaded(global_config):
    """
    Start imaging thread in background.
    
    Caller is responsible to make sure not imaging session is not running.
    """
    imaging_thread = threading.Thread(target=do_validation_threaded_worker, args=(
     global_config,))
    imaging_thread.daemon = True
    imaging_thread.session_id = global_config._session_id
    global_config.imaging_thread = imaging_thread
    imaging_thread.start()


def do_validation(global_config):
    """
    Short cut of generate graph, and call run_validation_tasks.
    """
    generate_validation_graph(global_config)
    return do_validation_threaded_worker(global_config)


def get_result(session_id):
    """
    Get result of the network validation.
    
    Returns a dict of problematic IP as key, and list of errors as value.
    """
    global_config = session_manager.get_global_config(session_id=session_id)
    if getattr(global_config, 'action', None) is not ACTION:
        raise StandardError('Validation is not started yet')
    if ntm.is_running(session_id=session_id):
        raise StandardError('Validation in progress, try again later')
    else:
        return global_config.results
    return


def clear_result(session_id=None):
    """
    Clear result
    """
    global_config = session_manager.get_global_config(session_id=session_id)
    global_config.results = None
    global_config.action = None
    global_config.graph = None
    return