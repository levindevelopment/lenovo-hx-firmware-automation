# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/nic_windows.py
# Compiled at: 2019-02-15 12:42:10
import csv, features, os, re, tempfile, netifaces
from foundation import foundation_tools as tools
from foundation.nic_base import NetworkInterface
from foundation import features
KEY_IPv4 = 'IPv4 Address'
KEY_IPv6LL = 'Link-local IPv6 Address'
KEY_NETMASK = 'Subnet Mask'

def ipconfig():
    """
    the `ipconfig /all`
    
    Returns:
      {'Ethernet':
        {'IPv4 Address': '192.168.2.186',
         'Link-local IPv6 Address': 'fe80::70ad:e81e:54fd:d244%12',
        }
      }
    """
    r = re.compile('^(?:Ethernet|Wireless LAN) adapter (.*?):\n\n(.*?)\n(?:\n|\\Z)', re.DOTALL | re.MULTILINE)
    out, _, _ = tools.system(None, ['ipconfig', '/all'], throw_on_error=False, log_on_error=False)
    out = out.replace('\r\n', '\n')
    adapters = {}
    for adapter, kv in r.findall(out):
        adapters[adapter] = {}
        for line in kv.splitlines():
            if ':' not in line:
                continue
            k, v = line.split(':', 1)
            k = k.replace('.', '').strip()
            v = v.strip()
            v = v.replace('(Preferred)', '')
            adapters[adapter][k] = v

    return adapters


def has_admin():
    """
    Checks for admin access
    
    Returns:
      True if admin access else False
    """
    import ctypes
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    except AttributeError:
        return False


def extract_all_vlan_configured():
    """
    Extracts all vlan configured on the NIC by asking user for admin access.
    On Windows,
      - need to have hyper-v role installed to be able create vlan
      - user may need to create external hyper-v switch and add physical NIC
      - create virtual NIC and add to hyper-v switch
    
    Returns:
      - If user gives admin access, returns Dict in the format
        {"access": True,
        "vlan_info": [{"AccessVlanid": "",
                       "ParentAdapter": ""},
                       ...]
        }
      - If user does not give access, return Dict in the format
        {"access": False,
         "vlan_info": None}
    """
    is_admin = has_admin()
    all_vlan = {}
    output = os.path.join(tempfile.gettempdir(), 'vlan.csv')
    if not features.is_enabled(features.MULTIHOMING_VLAN) and not is_admin:
        return {'access': False, 'vlan_info': None}
    additional_params = ['-Verb', 'runAs'] if not is_admin else []
    cmdlist = [
     'powershell', 'Start-Process', 'powershell', '-WindowStyle', 'Hidden'] + additional_params + ['-ArgumentList',
     '"Get-VMNetworkAdapterVlan', '-ManagementOS', '|',
     'Select-Object', 'AccessVlanId,ParentAdapter', '|', 'export-csv',
     '-Path', output, '-Encoding', 'ascii', '-NoTypeInformation"']
    out, err, _ = tools.system(None, cmdlist, throw_on_error=False)
    if err:
        return {'access': False, 'vlan_info': None}
    all_vlan['access'] = True
    info = []
    f = None
    try:
        with open(output, 'rb') as (f):
            reader = csv.DictReader(f)
            for row in reader:
                info.append(row)

    except IOError as e:
        raise StandardError('Exception in foundation while extracting vlan info %s', str(e))

    all_vlan['vlan_info'] = info
    return all_vlan


def extract_vlan_sub_fields(all_vlan, adapter):
    """
    Extracts vlan id if configured on the adapter from all_vlan
    
    Returns:
      tuple of (vlan, parent_interface_index, primary_interface) with
        - vlan configured on virtual NIC
          - If user did not give access, return "uncomputable"
          - If user gave access, then return vlan id
        - parent_interface_index
          - If user does not give access, return "uncomputable"
          - If user does give access (what to return? - TBD
            Since virtual NIC is added to hyper-v switch, return switch ifindex?)
        - primary_interface
          - If user does not give access, return "uncomputable"
          - If user does give access, return True or False depending on whether it
            it is primary interface or not
    """
    vlan = None
    if not all_vlan['access']:
        return ('Uncomputable', 'Uncomputable', 'Uncomputable')
    r = re.compile('^vEthernet \\((.*?)\\)')
    vlan_ifname = r.search(adapter).group(1)
    info = all_vlan['vlan_info']
    if 'Default Switch' not in vlan_ifname:
        for entry in info:
            parent_adapter = entry['ParentAdapter']
            ifname = parent_adapter.split('=')[1].strip().strip("'")
            if ifname in vlan_ifname:
                vlan = entry['AccessVlanId']
                break

    if not vlan:
        return (
         None, -1, False)
    if vlan == '0':
        return (
         None, -1, True)
    return (
     vlan, 'Uncomputable', False)
    return


def get_interface_name(nic_index):
    """ Returns the name of the nic with given index.  """
    adapters = netifaces.interfaces()
    ipv6ll_suffix = '%%%s' % nic_index
    for adapter in adapters:
        addrs = netifaces.ifaddresses(adapter)
        for addr in addrs.get(netifaces.AF_INET6, []):
            for attr in ['broadcast', 'addr']:
                if addr.get(attr, '').endswith(ipv6ll_suffix):
                    return adapter


def list_nics():
    """
    Windows has it's own IPv6LL and many friendly names, let's pick the
    most common one
    
    Returns:
      same format as list_nics()
    """
    adapters = ipconfig()
    result = {}
    vlan_enabled = features.is_enabled(features.MULTIHOMING_VLAN)
    if vlan_enabled:
        all_vlan = extract_all_vlan_configured()
    for adapter, attrs in adapters.items():
        if not all(map(lambda key: key in attrs, [
         KEY_IPv4, KEY_IPv6LL, KEY_NETMASK])):
            continue
        ipv4 = attrs[KEY_IPv4]
        ipv6 = attrs[KEY_IPv6LL]
        netmask = attrs[KEY_NETMASK]
        intf_index = ipv6.split('%')[-1]
        vlan = None
        primary_interface = True
        parent_interface_index = -1
        if vlan_enabled and 'vEthernet' in adapter:
            vlan, parent_interface_index, primary_interface = extract_vlan_sub_fields(all_vlan, adapter)
        result[intf_index] = {'ipv4': ipv4, 
           'ipv6': ipv6, 
           'name': adapter, 
           'netmask': netmask, 
           'vlan': vlan, 
           'primary_interface': primary_interface, 
           'parent_interface_index': parent_interface_index}

    return result


class NetworkInterfaceWindows(NetworkInterface):
    script_ext = '.bat'
    _netsh_index = None

    @property
    def netsh_index(self):
        if not self._netsh_index:
            addrs = netifaces.ifaddresses(self.name)
            for addr in addrs.get(netifaces.AF_INET6, []):
                if '%' in addr.get('addr', ''):
                    self._netsh_index = addr['addr'].split('%')[-1]

        assert self._netsh_index, 'failed to figure out interface index for %s' % self.name
        return self._netsh_index

    def add_ip(self, ip, mask, gateway=None):
        cmd = ['netsh', 'int', 'ipv4', 'add', 'address',
         self.netsh_index, ip, mask]
        if gateway:
            cmd.append(gateway)
        return cmd

    def remove_ip(self, ip, mask, gateway=None):
        return [
         'netsh', 'int', 'ipv4', 'del', 'address',
         self.netsh_index, ip, mask]

    def sudo_execute(self, script_path):
        return tools.system(None, ['powershell', 'Start-Process',
         '-Verb', 'runAs', '-WindowStyle', 'Hidden',
         'cmd', '-ArgumentList', '/c,%s' % script_path])

    def config_ips(self, *args, **kwargs):
        return super(NetworkInterfaceWindows, self).config_ips(keep_dhcp_ip=True, *args, **kwargs)