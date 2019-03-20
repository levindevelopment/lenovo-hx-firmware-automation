# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/set_huawei_ibmc_ip.py
# Compiled at: 2019-02-15 12:42:10
from foundation import remote_boot_ibmc
from foundation.foundation_tools import get_ipv6_link_local_from_mac

def set_ibmc_ip(mac, interface, username, password, ipv4, netmask, gateway):
    """
    Sets IBMC ip on Huawei node.
    
    Args:
      mac: MAC address of IBMC interface in aa:bb:cc:dd:ee:ff format.
      interface: Interface number of link to use. An integer.
      ipmi_username: User name to use for authentication.
      ipmi_password: Password to use for authentication.
      ipmi_ip: IPv4 address to be configured.
      ipmi_netmask: Netmask to be configured.
      ipmi_gateway: Gateway to be configured.
    """
    ipv6_ip = '[%s%%%s]' % (get_ipv6_link_local_from_mac(mac), interface)
    ibmc = remote_boot_ibmc.Huawei(ipv6_ip, username, password, None)
    ibmc.set_ipv4_address(mac, ipv4, netmask, gateway)
    ibmc.power_control('off')
    ibmc.power_control('on')
    return