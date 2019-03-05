# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/set_dell_idrac_ip.py
# Compiled at: 2019-02-15 12:42:10
import logging
from foundation import folder_central
from foundation.foundation_tools import get_ipv6_link_local_from_mac
from foundation.foundation_tools import system
IDRAC_TIMEMAX_S = 20
default_logger = logging.getLogger(__file__)

def set_idrac_ip(mac, interface, username, password, ip, netmask, gateway):
    """
    Arguments to this function are similar to set_smc_ipmi_ip.set_ipmi_ip().
    """
    ipv6_ip = '%s%%%s' % (get_ipv6_link_local_from_mac(mac), interface)
    out, err, ret = system(None, cmd_list=[
     folder_central.get_dell_racadm_path(),
     '-r', ipv6_ip,
     '-u', username,
     '-p', password,
     'setniccfg', '-s', ip, netmask, gateway], log_on_error=False, throw_on_error=False, timeout=IDRAC_TIMEMAX_S)
    if ret:
        default_logger.debug('idrac returned out:%s\n error:%s', out, err)
        raise StandardError('Failed to configure idrac ip for %s' % mac)
    return