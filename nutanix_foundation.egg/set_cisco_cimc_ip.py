# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/set_cisco_cimc_ip.py
# Compiled at: 2019-02-15 12:42:10
import logging
from foundation_tools import get_ipv6_link_local_from_mac
from remote_boot_cimc import CiscoCIMC
default_logger = logging.getLogger(__file__)

def set_cimc_ip(mac, interface, ipmi_username, ipmi_password, ipmi_ip, ipmi_netmask, ipmi_gateway, dhcp=False):
    """
    Sets CIMC ip on Cisco node.
    
    Args:
      mac: MAC address of IPMI interface in aa:bb:cc:dd:ee:ff format.
      interface: Interface number of link to use. An integer.
      ipmi_username: User name to use for authentication.
      ipmi_password: Password to use for authentication.
      ipmi_ip: IPv4 address to configure CIMC to.
      ipmi_netmask: Netmask to configure CIMC to.
      ipmi_gateway: Gateway to configure CIMC to.
    """
    ipv6_ip = '[%s%%%s]' % (get_ipv6_link_local_from_mac(mac), interface)
    cimc = CiscoCIMC(ipv6_ip, ipmi_username, ipmi_password)
    try:
        try:
            cimc.login()
        except:
            default_logger.exception('Unable to log in to BMC')
            raise StandardError('Unable to log in to BMC. Ensure that the authentication details provided are correct and the targetnode is Cisco itself.')

        xml = '<mgmtIf extGw="%s" extIp="%s" extMask="%s" dhcpEnable="%s" />' % (
         ipmi_gateway, ipmi_ip, ipmi_netmask, 'yes' if dhcp else 'no')
        cimc.set_object('sys/rack-unit-1/mgmt/if-1', xml)
    except:
        raise StandardError('Failed to configure cimc ip for: %s' % mac)
    finally:
        cimc.logout()