# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/set_lenovo_imm_ip.py
# Compiled at: 2019-02-15 12:42:10
from lenovo_util import LenovoUtil
from foundation_tools import get_ipv6_link_local_from_mac

def set_imm_ip(mac, interface, username, password, ipv4_addr, netmask, gateway):
    ipv6_addr = '%s%%%s' % (get_ipv6_link_local_from_mac(mac), interface)
    util = LenovoUtil(ipv4_addr, username, password, ipv6_addr=ipv6_addr)
    util.set_ipv4_config(gateway, netmask, use_ipv6=True)