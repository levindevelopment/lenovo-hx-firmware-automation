# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/nic_linux.py
# Compiled at: 2019-02-15 12:42:10
import re, glob, os
from foundation import foundation_tools as tools
from foundation.nic_base import NetworkInterface

def extract_fields_and_get_nics(adapter, netgroup):
    """
    Enumerate local network interfaces on linux node with ipv4 unicast and ipv6ll
    
    Return:
      a dict of interface as key, ip information dict as value
      eg.
        {"2": {"ipv4": "10.15.6.3",
               "ipv6": "fe80::526b:8dff:fe01:f49d%eth0"
               name: "eth0",
               netmask: "255.255.252.0",
               parent_interface_index: -1,
               primary_interface: true,
               vlan: null},
        ...}
    """
    ipv4, ipv6, netmask, key = netgroup
    key = open('/sys/class/net/%s/ifindex' % key).read().strip()
    vlan_id = extract_vlan_linux(adapter)
    primary_intf = True if not vlan_id else False
    parent_ifindex = extract_parent_ifindex(adapter, primary_intf)
    return {key: {'ipv4': ipv4, 'ipv6': ipv6, 'netmask': netmask, 'vlan': vlan_id, 
             'primary_interface': primary_intf, 'parent_interface_index': parent_ifindex, 
             'name': get_interface_name(key)}}


def get_interface_name(nic_index):
    """
    Returns the name of the nic with given index.
    
    Args:
      nic_index: Index of a nic in linux sysfs.
    
    Raises:
      StandardError if the given nic index is invalid.
    
    Returns:
      Name of the nic with given nic index.
    """
    nics = glob.glob('/sys/class/net/*')
    interface_name = None
    for nic in nics:
        nic_name = os.path.basename(nic)
        index = open('/sys/class/net/%s/ifindex' % nic_name).read().strip()
        if int(nic_index) == int(index):
            interface_name = nic_name
            break

    if not interface_name:
        raise StandardError('Invalid nic index provided: %s' % nic_index)
    return interface_name


def extract_vlan_linux(adapter):
    """
    Extracts the vlan id (if set) on the adapter, could be
      [u'eth0', u'eth0.2146', u'eth0.100']
    Returns:
      vlan id
    """
    filter_txt = re.compile('VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD(.*)$')
    vlan_pattern = re.compile('\\s*(.*?)\n                                \\s*\\|\\s*(.*?)\n                                \\s*\\|\\s*(.*?)\n                                \\s+|\\s+\\b', re.VERBOSE | re.DOTALL)
    cmd_list = [
     'sudo', 'cat', '/proc/net/vlan/config']
    out, err, ret = tools.system(None, cmd_list, throw_on_error=False, log_on_error=True)
    if ret and 'No such file' in err:
        return
    out = out.replace('\n', ' ')
    out = out.replace('\t', ' ')
    out = filter_txt.search(out).group(1)
    vlan_id_out = None
    for intf, vlan_id, _ in vlan_pattern.findall(out):
        if adapter != intf:
            continue
        vlan_id_out = vlan_id

    return vlan_id_out


def extract_parent_ifindex(adapter, primary_intf):
    """
    Extracts the ifindex of the parent interface
    Returns:
      For primary inteface(like eth0/eth1), will return -1. For Virtual interfaces
      like (eth0.2146), returns ifindex of eth0
    """
    if primary_intf:
        return -1
    base_adapter = adapter.split('.')[0]
    key = open('/sys/class/net/%s/ifindex' % base_adapter).read().strip()
    return key


class NetworkInterfaceLinux(NetworkInterface):

    def add_ip(self, ip, mask, gateway=None):
        cmd = ['ip', 'addr', 'add',
         '%s/%s' % (ip, mask), 'dev', self.name]
        return cmd

    def remove_ip(self, ip, mask=None):
        cmd = ['ip', 'addr', 'del',
         '%s/%s' % (ip, mask), 'dev', self.name]
        return cmd

    def sudo_execute(self, script_path):
        return tools.system(None, ['sudo', 'bash', '-e', script_path])