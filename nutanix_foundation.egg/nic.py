# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/nic.py
# Compiled at: 2019-02-15 12:42:10
import logging, platform, netifaces
from foundation import foundation_settings
from foundation import ndp_client
from foundation.portable import is_mac, is_win, is_portable
from foundation import virtual_interfaces
from foundation import nic_linux, nic_windows, nic_mac
from foundation.nic_linux import NetworkInterfaceLinux
from foundation.nic_mac import NetworkInterfaceMac
from foundation.nic_windows import NetworkInterfaceWindows
from foundation_tools import generic_ping
logger = logging.getLogger(__name__)
primary_nic = None

def list_nics():
    """
    enumerate local network interfaces with both ipv4 unicast and ipv6ll
    
    Return:
      a dict of interface as key, ip information dict as value
      eg.
        {"2": {"ipv4": "10.1.243.231", "ipv6": "fe80::8d93%en0"}, ...}
    Note: set_primary_nic("2") or set_primary_nic("en3")
    """
    if is_win():
        return nic_windows.list_nics()
    return list_nics_common()


def list_nics_common():
    """
    Common API for Linux & MAC and branch out to OS specific module to extract
    sub adapter fields
    
    Returns:
       a dict of interface as key, ip information dict as value
      eg.
        {"2": {"ipv4": "10.1.243.231", "ipv6": "fe80::8d93%en0"}, ...}
    """
    nics = {}
    adapters = netifaces.interfaces()
    for adapter in adapters:
        if adapter.startswith('lo'):
            continue
        addrs = netifaces.ifaddresses(adapter)
        if not addrs.get(netifaces.AF_INET):
            continue
        if not addrs.get(netifaces.AF_INET6):
            continue
        ipv4 = addrs[netifaces.AF_INET][0]['addr']
        netmask = addrs[netifaces.AF_INET][0].get('netmask')
        for addr in addrs[netifaces.AF_INET6]:
            if '%' in addr.get('broadcast', ''):
                ipv6 = addr['broadcast']
                key = addr['broadcast'].split('%')[-1]
            else:
                if '%' in addr.get('addr', ''):
                    ipv6 = addr['addr']
                    key = addr['addr'].split('%')[-1]
                else:
                    continue
            netgroup = (
             ipv4, ipv6, netmask, key)
            if is_mac():
                nics.update(nic_mac.extract_fields_and_get_nics(adapter, netgroup))
            else:
                nics.update(nic_linux.extract_fields_and_get_nics(adapter, netgroup))
            break

    if is_mac():
        nic_mac.set_friendly_names_mac(nics)
    return nics


def set_primary_nic(nic):
    """
    Sets the primary nic for discovery.
    Args:
      nic: Index of nic
    """
    global primary_nic
    primary_nic = nic
    ndp_client.INTERFACE = nic
    if platform.system() == 'Linux':
        ndp_client.INTERFACE = nic_linux.get_interface_name(nic)
    foundation_settings.settings['ipv6_interface'] = nic


def get_interface_list_for_discovery():
    nics = list_nics()
    if is_portable():
        return [ key for key in nics ]
    return [ nics[key]['name'] for key in nics ]


def extended_list_nics():
    """
    It is extended version of lists_nics that packs more data
      {
        "ifindex" : <ifindex>,
        "interface_details" : {
          "name" : "<name>",
          "primary_interfacef" : <boolean>,
          "netmask": "<netmask>",
          "ipv4": "<ipv4>",
          "vlan" : "<vlan>"
        }
      }
      'default_gateway': <>,
      'routes': <>} ---> Could be futuristic additions
    
    Args:
      None
    Returns:
      enics formed as above
    """
    enics = {}
    gws = netifaces.gateways()
    if gws.get('default'):
        enics['default_gateway'] = gws['default'][netifaces.AF_INET][0]
    primary_list = list_nics()
    nlist = []
    for key in primary_list.keys():
        nlist.append({'interface_index': key, 'interface_details': primary_list[key]})

    enics['nics'] = nlist
    return enics


def setup_foundation_networking(configure_nics):
    """
    Sets up Foundation Networking & Handle these exceptions
      - Creates Virtual interfaces with VLAN ID
      - If VLAN ID is 0, then assume it is multihoming scenario
      - If delete flag is set, then delete the passed vlan interface
      - If VLAN adapter(interface) exists, delete and re-create with new params
    
    Args:
      configure_nics: nics info that need to be configured
    Returns:
      returns dictionary of configured nics in the format
       [
        {
          "ifindex" : "<ifindex>",
          "config" :
          [
            {
              "netmask" : "string",
              "vlan" : <int>,
              "ipv4" : "string"
            }
          ]
        }
      ]
    Raises:
      StandardError on following cases
      - if portable foundation
      - input json has invalid config
    """
    configured_nics = []
    if is_portable():
        for entry in configure_nics:
            for config in entry['config']:
                if config['vlan']:
                    raise StandardError('Foundation cannot configure VLAN on %s' % platform.system())

    adapters = netifaces.interfaces()
    for entry in configure_nics:
        ifname = netifaces_name(entry['interface_index'])
        if ifname.split('.')[0] != ifname:
            raise StandardError('Cannot configure virtual interfaces on %s, set /primary_nic first' % ifname)
        nic_config = entry['config']
        network_groups = []
        for config in nic_config:
            vlan = config['vlan']
            if not int(vlan):
                network_groups.append((config['ipv4_address'], config['netmask']))
                continue
            subintf = ifname + '.' + str(vlan)
            if config['delete'] and subintf in adapters:
                virtual_interfaces.delete_vlan_interface(subintf, vlan)
                continue
            if subintf in adapters:
                virtual_interfaces.delete_vlan_interface(subintf, vlan)
            virtual_interfaces.create_vlan_interface(subintf, vlan, config['netmask'], config['ipv4_address'])
            if not generic_ping(config['ipv4_address'], retries=5, sleep_time=1):
                raise StandardError('Foundation failed to create Virtual interface %s', subintf)

        if not is_win():
            entire_nics = list_nics()
            configured_nics = [ {'interface_index': x, 'interface_details': entire_nics[x]} for x in entire_nics if entire_nics[x]['parent_interface_index'] != -1
                              ]
        if len(network_groups) > 0:
            configure_simple_multihoming(ifname, network_groups)

    return configured_nics


def delete_foundation_networking():
    """
    Delete all the Virtual interfaces configured on the node.
    Types of virtual interfaces
      - eth0.100, eth0.2146, eth0:0, eth0:1
    
    Returns:
      None
    """
    adapters = netifaces.interfaces()
    for adapter in adapters:
        if adapter.startswith('lo'):
            continue
        if '.' in adapter:
            virtual_interfaces.delete_vlan_interface(adapter, adapter.split('.')[1])
        else:
            nic = NetworkInterfaceFactory(adapter)
            nic.config_ips([])


def netifaces_name(ifindex):
    """
    translate ifindex or ifname to an adapter name works with netifaces,
    
    We usually need to translate
     - linux, 2 to eth0,
     - mac, en5 to en5
     - windows, 11 to a VERY_LONG_UUID
    """
    ifname = str(ifindex)
    adapters = netifaces.interfaces()
    if ifname in adapters:
        return ifname
    if is_win():
        ifname = nic_windows.get_interface_name(ifname)
    else:
        if is_mac():
            ifname = nic_mac.get_interface_name(ifname)
        else:
            ifname = nic_linux.get_interface_name(ifname)
    return ifname


def configure_simple_multihoming(ifindex, network_groups):
    """
    wrapper for configuring multiple IPs on single interface w/o VLAN
    
    Args:
      ifindex: the `key` in list_nic, "en5", "2", or "11"
      network_groups: list of tuple of (ip, netmask)
    """
    ifname = netifaces_name(ifindex)
    nic = NetworkInterfaceFactory(ifname)
    nic.config_ips(network_groups)


class NetworkInterfaceFactory(object):
    """ build a NetworkInterface object based on CURRENT running platform """

    def __new__(cls, *args, **kargs):
        if is_mac():
            return NetworkInterfaceMac(*args, **kargs)
        if is_win():
            return NetworkInterfaceWindows(*args, **kargs)
        return NetworkInterfaceLinux(*args, **kargs)