# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/nic_mac.py
# Compiled at: 2019-02-15 12:42:10
import re, netifaces
from foundation import foundation_tools as tools
from foundation.nic_base import NetworkInterface

def extract_fields_and_get_nics(adapter, netgroup):
    """
    Enumerate local network interfaces on mac
    
    Return:
      a dict of interface as key, ip information dict as value
      eg.
        {"en0": {"ipv4": "10.15.6.3",
               "ipv6": "fe80::526b:8dff:fe01:f49d%en0"
               name: "Wi-Fi",
               netmask: "255.255.252.0",
               parent_interface_index: -1,
               primary_interface: true,
               vlan: null},
        ...}
    """
    vlan_id = None
    primary_intf = True
    parent_ifindex = -1
    ipv4, ipv6, netmask, key = netgroup
    if adapter.startswith('vlan'):
        primary_intf = False
        _, parent_ifindex, _, vlan_id = extract_vlan_mac(adapter)
    return {key: {'ipv4': ipv4, 'ipv6': ipv6, 'netmask': netmask, 'vlan': vlan_id, 
             'primary_interface': primary_intf, 'parent_interface_index': parent_ifindex}}


def set_friendly_names_mac(nics):
    """
    Set friendly names for all ifindices in nics
    
    Returns:
      nics after setting "name" field
    """
    names = {}
    names = get_friendly_names_mac()
    for key in nics:
        if key in names:
            nics[key]['name'] = names[key]


def get_interface_name(nic_index):
    """ Returns the name of the nic with given index. """
    adapters = netifaces.interfaces()
    if nic_index in adapters:
        return nic_index


def get_friendly_names_mac():
    """
    Get the mapping of interface names and user friendly names
    
    Return:
      eg. {"en5": "USB 10/100/1000 LAN"}
    """
    re_port_dev = 'Hardware Port: (.*)\nDevice: (.*)\n'
    out, _, _ = tools.system(None, ['networksetup', '-listallhardwareports'], throw_on_error=False, log_on_error=False)
    port_devs = re.findall(re_port_dev, out)
    return dict(map(reversed, port_devs))


def extract_vlan_mac(adapter):
    """
    Extracts the vlan id (if set) on MAC platform, adapter could be
      [u'en0', u'en9', u'vlan2146']
    Returns:
      vlan id
    """
    vlan_pattern = re.compile('\\s*VLAN User Defined Name:\\s*(.*?)\\s*Parent Device:\\s*(.*?)\\s*Device \\(Hardware Port\\):\\s*(.*?)\\s*Tag:\\s*(.*?)\\s+')
    cmd_list = [
     'networksetup', '-listVLANs']
    out, _, _ = tools.system(None, cmd_list, throw_on_error=False, log_on_error=False)
    out = out.replace('\n', ' ')
    out = out.replace('"', '')
    return [ i for i in vlan_pattern.findall(out) if i[2] == adapter ][0]


class NetworkInterfaceMac(NetworkInterface):

    def add_ip(self, ip, mask, gateway=None):
        cmd = ['ifconfig', self.name, 'alias', ip, 'netmask', mask]
        return cmd

    def remove_ip(self, ip, mask, gateway=None):
        cmd = ['ifconfig', self.name, '-alias', ip]
        return cmd

    def sudo_execute(self, script_path):
        return tools.system(None, [
         'osascript', '-e',
         'do shell script "bash -e %s" with administrator privileges' % script_path])