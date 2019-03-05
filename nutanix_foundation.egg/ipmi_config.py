# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/ipmi_config.py
# Compiled at: 2019-02-15 12:42:10
import logging, os, socket
from cluster.genesis.node_manager import NodeManager
from foundation import factory_mode
from foundation import foundation_settings
from foundation import foundation_tools as tools
from foundation import imaging_context
from foundation import ipmi_util
from foundation import network_validation
from foundation import remote_boot_ucsm
from foundation import set_cisco_cimc_ip
from foundation import set_dell_idrac_ip
from foundation import set_ironwood_irmc_ip
from foundation import set_hp_ilo_ip
from foundation import set_inspur_bmc_ip
from foundation import set_lenovo_imm_ip
from foundation import set_smc_ipmi_ip
from foundation import set_huawei_ibmc_ip
from foundation import set_intel_bmc_ip
from foundation.ndp_client import discover_all_nodes as discover_all_nodes_single_interface
from foundation.shared_functions import ipv4_to_int, int_to_ipv4
from foundation.tinyrpc import call_genesis_method, RpcError
from foundation import nic
logger = logging.getLogger('console')
is_in_factory = factory_mode.factory_mode()

class Vendor(object):
    NX = 'nutanix_nx'
    XC = 'dell_xc'
    HX = 'lenovo_hx'
    UCS = 'cisco_ucs'
    HPE = 'hpe_proliant'
    PPC = 'ibm_powerpc'
    IRONWOOD = 'ironwood'
    INSPUR = 'inspur'
    IBMC = 'huawei'
    INTEL = 'intel'
    ALL = [NX, XC, HX, UCS, HPE, PPC, IRONWOOD, INSPUR, IBMC, INTEL]
    SET_IP_FUNC = {NX: set_smc_ipmi_ip.set_ipmi_ip, 
       XC: set_dell_idrac_ip.set_idrac_ip, 
       HX: set_lenovo_imm_ip.set_imm_ip, 
       UCS: set_cisco_cimc_ip.set_cimc_ip, 
       HPE: set_hp_ilo_ip.set_ilo_ip, 
       PPC: set_smc_ipmi_ip.set_ipmi_ip, 
       IRONWOOD: set_ironwood_irmc_ip.set_irmc_ip, 
       INSPUR: set_inspur_bmc_ip.set_inspur_ip, 
       IBMC: set_huawei_ibmc_ip.set_ibmc_ip, 
       INTEL: set_intel_bmc_ip.set_intel_bmc_ip}


def discover_nodes():
    context = imaging_context.get_context()
    if context != imaging_context.FIELD_VM:
        try:
            result = discover_all_nodes(interface_filter_list=[])
        except socket.gaierror:
            raise StandardError('CVM discovery needs to use eth0. Please make sure that eth0 exists and is on the CVM network.')
        except:
            logger.exception('Discovery failed')
            raise StandardError('Discovery failed, please check foundation log')

    else:
        result = call_genesis_method('localhost', NodeManager.discover_all_nodes, interface_filter_list=[])
        if isinstance(result, RpcError):
            raise StandardError("Discovery failed because of a RpcError. Restart genesis via 'genesis restart' and retry")
    return filter(lambda block: bool(block.get('block_id')), result)


def generic_ping_multiple(targets):
    """
    Pings a list of targets by IP address. Returns list of tuple consisting
    of IP address and boolean. Boolean is true if ping was successful.
    """
    results = tools.tmap(tools.generic_ping, map(lambda ip: (ip,), targets))
    return zip(targets, results)


def config_from_file(path, first_ip, netmask=None, gateway=None):
    config = {'Discover Nodes': False, 
       'Subnet Mask': {'Controller': None, 
                       'Hypervisor': None, 
                       'IPMI': netmask}, 
       'Default Gateway': {'Controller': None, 
                           'Hypervisor': None, 
                           'IPMI': gateway}, 
       'IP Addresses': {}}
    next_ip = first_ip
    with open(path) as (node_file):
        for line in node_file.read().splitlines():
            block_id, model, node_position, ipv6, netif = line.split()
            json_key = '%s%%%s' % (ipv6, netif)
            config['IP Addresses'][json_key] = {'Controller': None, 
               'Hypervisor': None, 
               'IPMI': next_ip}
            int_ip = ipv4_to_int(next_ip)
            next_ip = int_to_ipv4(int_ip + 1)

    return config


def configure_node(config, node):
    if config.get('ucsm_managed_mode') or node.get('ucsm_managed_mode') or node.get('ipmi_mac'):
        return configure_node_via_ipmi(config, node)
    return configure_node_via_genesis(config, node)


def configure_node_via_genesis(config, node):
    ipv6_ip = node['ipv6_address']
    ipmi_ip_dict = {'address': node['ipmi_ip'], 
       'netmask': config['ipmi_netmask'], 
       'gateway': config['ipmi_gateway']}
    config_tuple = (
     None, None, ipmi_ip_dict)
    ret = network_validation.configure_ip_via_genesis(node['node_position'], ipv6_ip, config_tuple, log_on_error=True, logger=logger)
    return ret


def validate_mac_address(mac):
    """
    Ping link local address obtained from ipmi mac address to check whether
    ipmi mac address is valid and in same subnet as foundation.
    Args:
      mac : ipmi mac address of given node.
    Return:
      If given ipmi mac address is valid and we can sucessfully ping link local
      address return True else in all other cases return False.
    """
    ipv6_iface = foundation_settings.get_settings()['ipv6_interface']
    try:
        ipv6 = tools.get_ipv6_link_local_from_mac(mac)
    except ValueError as err:
        logger.error("This mac address '%s' is invalid. Stderr : %s" % (mac, err))
        return False
    else:
        ping = [
         'ping6', '-c', '3']
        if os.name == 'nt':
            ping = [
             'ping', '-6', '-n', '3']
        out, err, ret = tools.system(None, ping + ['%s%%%s' % (ipv6, ipv6_iface)], throw_on_error=False, log_on_error=False, timeout=6)
        if ret:
            return False

    return True


def configure_node_via_ipmi(config, node):
    ipmi_configured = False
    ipv6_iface = foundation_settings.get_settings()['ipv6_interface']
    if config.get('ucsm_managed_mode') or node.get('ucsm_managed_mode'):
        try:
            logger.info('Attempting to configure BMC ip %s using management server', node['ipmi_ip'])
            remote_boot_ucsm.set_cimc_ip_via_ucsm(config['ucsm_ip'], config['ucsm_user'], config['ucsm_password'], node['ipmi_ip'], config['ipmi_netmask'], config['ipmi_gateway'], node['ucsm_node_serial'])
            ipmi_configured = True
        except Exception as e:
            exp_err = "Server with serial '%s' is not available" % node['ucsm_node_serial']
            if exp_err in str(e):
                logger.error(str(e))
                node['valid_node_serial'] = False
                node['ipmi_message'] = str(e)
            else:
                node['valid_node_serial'] = True
                node['ipmi_message'] = ''
                logger.error('Failed to configure BMC ip with error: %s\nPlease ensure that the data provided is valid and try again. For successfully imaging UCS managed node, BMC must have a valid ip' % str(e))

    else:
        if not validate_mac_address(node['ipmi_mac']):
            logger.warn('Given ipmi mac address %s is not reachable. Either ipmi mac address is invalid or not in same subnet as foundation.' % node['ipmi_mac'])
            return ipmi_configured
        ipmi_password = node.get('ipmi_password') or config['ipmi_password']
        ipmi_user = node.get('ipmi_user') or config['ipmi_user']
        set_ip_functions = list(set(Vendor.SET_IP_FUNC.values()))
        try:
            tools.tmap(lambda func, args: func(*args), map(lambda func: (
             func,
             (
              node['ipmi_mac'], ipv6_iface, ipmi_user,
              ipmi_password, node['ipmi_ip'], config['ipmi_netmask'],
              config['ipmi_gateway'])), set_ip_functions))
        except StandardError as e:
            if len(e.args) != 3:
                raise
            _, exceptions, results = e.args
            if any(map(lambda ee: ee is None, exceptions)):
                logger.info('Configured BMC at %s to %s', node['ipmi_mac'], node['ipmi_ip'])
                ipmi_configured = True
            else:
                for error, func in zip(exceptions, set_ip_functions):
                    logger.warn('failed to configure BMC using %s: %s', func.func_name, error)

                logger.error('Failed to configure BMC at %s using any method', node['ipmi_mac'])

    if is_in_factory:
        logger.debug('Verifying BMC IP settings in factory environment')
        verify_ipmi_ip(config, node)
    return ipmi_configured


def verify_ipmi_ip(config, node):
    """
    Verify IPMI IP by reading back them from IPMI and compare with config
    
    Args:
      config: config in _configure_node_via_ipmi
      node: node in _configure_node_via_ipmi
    
    Raises:
      StandardError if failed to read IP from BMC or IP info doesn't match.
    
    NOTE: plz consider moving all these non-http-server
          helper to somewhere else and delete this note.
    """
    node_config = lambda : None
    for field in ['ipmi_user', 'ipmi_password']:
        setattr(node_config, field, node.get(field) or config[field])

    node_config.ipmi_ip = node['ipmi_ip']
    net_info = ipmi_util.get_net_configuration(node_config)
    logger.info('IPMI %s is configured to %s', node['ipmi_ip'], net_info)
    if net_info.get('ipv4_configuration', '') != 'Static':
        raise StandardError('IPMI %s is not configured to use Static IP' % node['ipmi_ip'])
    cidr = sum([ bin(int(x)).count('1') for x in config['ipmi_netmask'].split('.') ])
    ip_cidr = net_info.get('ipv4_address', '')
    if ip_cidr != '%s/%s' % (node['ipmi_ip'], cidr):
        raise StandardError('IPMI %s is not configured to use the desired IP/netmask' % node['ipmi_ip'])
    if net_info.get('ipv4_gateway', '') != config['ipmi_gateway']:
        raise StandardError('IPMI %s is not configured to use the desired gateway' % config['ipmi_gateway'])


def discover_all_nodes(address_type='IPv6', ip_filter_list=None, uuid_filter_list=None, interface_filter_list=None):
    """
    Wrapper on top of ndp_client.discover_all_nodes.
    Get interface_list configured on the node by calling list_nics and call
    ndp_client.discover_all_nodes
    API aggregates the nodes discovered on a particular NIC, deduplicate if same
    nodes are discovered again and return merged list.
    """
    interface_list = nic.get_interface_list_for_discovery()
    results = tools.tmap(discover_all_nodes_single_interface, map(lambda interface: (
     address_type, ip_filter_list,
     uuid_filter_list, interface_filter_list), interface_list), map(lambda interface: {'interface': interface}, interface_list))

    def deduplicate(discovered_blocks):

        def get_block(block_id, result):
            return filter(lambda x: x.get('block_id') == block_id, result)[0]

        nodes_seen = set()
        blocks_seen = set()
        result = []
        for block in discovered_blocks:
            current_block, visited = (block, False) if block['block_id'] not in blocks_seen else (
             get_block(block.get('block_id'), result), True)
            blocks_seen.add(block['block_id'])
            dedup_nodes = [ node for node in block.get('nodes') if node['node_uuid'] not in nodes_seen and not nodes_seen.add(node['node_uuid'])
                          ]
            if len(dedup_nodes) > 0:
                if not visited:
                    del current_block['nodes']
                    current_block['nodes'] = dedup_nodes
                    result.append(current_block)
                else:
                    for node in dedup_nodes:
                        current_block.get('nodes').append(node)

        return result

    discovered_blocks = [ block for entry in results for block in entry ]
    return deduplicate(discovered_blocks)