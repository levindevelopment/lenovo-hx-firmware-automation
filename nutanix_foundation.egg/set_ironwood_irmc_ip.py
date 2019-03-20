# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/set_ironwood_irmc_ip.py
# Compiled at: 2019-02-15 12:42:10
from foundation.foundation_tools import get_ipv6_link_local_from_mac
from foundation.ironwood import FujitsuIRMC

def set_irmc_ip(mac, interface, username, password, ip, netmask, gateway):
    """
    See documentation for 'set_smc_ipmi_ip.set_ipmi_ip'.
    
    Raises:
      StandardError on failure.
    """
    ipv6_ip = '%s%%%s' % (get_ipv6_link_local_from_mac(mac), interface)
    irmc_client = FujitsuIRMC(ipv6_ip, username, password)
    irmc_client.configure_bmc_ipv4(ip, netmask, gateway)