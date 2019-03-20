# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/nic_base.py
# Compiled at: 2019-02-15 12:42:10
import logging, os, tempfile, netifaces
from foundation.shared_functions import in_same_subnet
logger = logging.getLogger(__name__)

class NetworkInterface(object):
    """
    Abstraction class for foundation host's interface
    
    Current will only do fetch and set IPv4 addresses.
    
    Usage:
      nic = NetworkInterfaceMac("en5")
      nic.config_ips([
          ("10.2.58.182", "255.255.252.0"),
          ("10.3.58.183", "255.255.252.0"),
          ("10.4.58.184", "255.255.252.0"),
      ])  # will show a popup asking for root permission
    """
    script_ext = '.sh'

    def __init__(self, if_name):
        self.name = if_name

    @property
    def current_ips(self):
        """
        Return a list of IPv4 address such as
          [{'netmask': u'255.255.252.0', 'addr': u'10.1.58.178'},
           {'netmask': u'255.255.252.0', 'addr': u'10.1.58.180'},]
          [{'netmask': '255.255.252.0', 'addr': '10.1.53.10'},
           {'addr': '10.1.53.11'}]
        
        NOTE: on Mac, the netmask may not available for all addresses
        """
        return netifaces.ifaddresses(self.name).get(netifaces.AF_INET, [])

    @property
    def default_gateway_ip(self):
        gateways = netifaces.gateways()
        for gateway in gateways.get(netifaces.AF_INET, []):
            if gateway and gateway[1] == self.name:
                return gateway[0]

    def add_ip(self, ip, mask, gateway=None):
        raise NotImplementedError

    def remove_ip(self, ip, mask=None):
        raise NotImplementedError

    def sudo_execute(self, script_path):
        raise NotImplementedError

    def sudo(self, cmds, script_name='netcfg'):
        """ Create a temporary file then execute it over sudo """
        script_path = None
        if not cmds:
            return
        logger.info('About to execute with sudo:')
        script_path = os.path.join(tempfile.gettempdir(), script_name + self.script_ext)
        with open(script_path, 'w') as (tf):
            for cmd in cmds:
                logger.debug(' %s', self.cmd_format(cmd).strip())
                tf.write(self.cmd_format(cmd))

        return self.sudo_execute(script_path)

    def cmd_format(self, cmd):
        return (' ').join(cmd) + os.linesep

    def config_ips(self, ip_masks, keep_gateway=True, keep_dhcp_ip=False):
        """
        Config IPs for a NIC
        
        This method will config the NIC with static IP from ip_masks, when the NIC
        has more than one IPs, extra IPs will be removed, unless keep_gateway is
        True and the IP is associated with the default gateway.
        
        Args:
          ip_masks: a list of (ip, netmask)
          keep_gateway: when foundation is running on a remote system, removing the
                        IP associated with default gateway will make the system
                        inaccessible, this option will keep that IP configured.
          keep_dhcp_ip: on some systems (HyperV), setting a static IP will
                        disable DHCP and remove the DHCPed IP, this option
                        will configure the DHCP IP as static IP.
        """
        current_ip_masks = [ (ip['addr'], ip.get('netmask', None)) for ip in self.current_ips
                           ]
        gateway_ip = None
        if keep_gateway:
            gateway_ip = self.default_gateway_ip
        cmds = []
        if len(current_ip_masks) > 1:
            for ip, mask in current_ip_masks:
                if (
                 ip, mask) not in ip_masks:
                    if keep_gateway and gateway_ip and mask:
                        if in_same_subnet(ip, gateway_ip, mask):
                            keep_gateway = False
                            continue
                    cmds.append(self.remove_ip(ip, mask))

        if keep_dhcp_ip and current_ip_masks:
            current_ip, current_mask = current_ip_masks[0]
            cmds.append(self.add_ip(current_ip, current_mask, gateway_ip))
        for ip, mask in set(ip_masks) - set(current_ip_masks):
            cmds.append(self.add_ip(ip, mask))

        return self.sudo(cmds)