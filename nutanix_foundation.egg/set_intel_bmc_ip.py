# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/set_intel_bmc_ip.py
# Compiled at: 2019-02-15 12:42:10
from foundation import remote_boot_intel
from foundation.foundation_tools import get_ipv6_link_local_from_mac

def set_intel_bmc_ip(mac, interface, username, password, ipv4, netmask, gateway):
    """
    Sets Intel BMC IP
    
    Args:
      mac: MAC address of Management interface in aa:bb:cc:dd:ee:ff format.
      interface: Interface number of link to use. An integer.
      ipmi_username: User name to use for authentication.
      ipmi_password: Password to use for authentication.
      ipmi_ip: IPv4 address to be configured.
      ipmi_netmask: Netmask to be configured.
      ipmi_gateway: Gateway to be configured.
    """
    ipv6_ip = '[%s%%%s]' % (get_ipv6_link_local_from_mac(mac), interface)
    intel = remote_boot_intel.IntelBMC(ipv6_ip, username, password, None)
    intel.set_ipv4_address(mac, ipv4, netmask, gateway)
    intel.power_control('off')
    intel.power_control('on')
    return