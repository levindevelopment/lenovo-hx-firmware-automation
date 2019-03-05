# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/virtual_interfaces.py
# Compiled at: 2019-02-15 12:42:10
import logging, os, re
from subprocess import Popen, PIPE
from foundation_tools import system
import netifaces
from foundation.shared_functions import validate_and_correct_ip, validate_and_correct_netmask
logger = logging.getLogger(__file__)

def create_multihoming_interfaces(config):
    """
    Configure virtual interfaces if multihoming is selected.
    """
    foundation_ipmi_ip = config['foundation_ipmi_ip']
    ipmi_mask = config['ipmi_netmask']
    foundation_hyp_ip = config['foundation_hyp_ip']
    hyp_mask = config['hypervisor_netmask']
    foundation_cvm_ip = config.get('foundation_cvm_ip', None)
    cvm_mask = config.get('cvm_netmask', None)
    network_groups = [
     (
      foundation_ipmi_ip, ipmi_mask),
     (
      foundation_hyp_ip, hyp_mask)]
    if foundation_cvm_ip and cvm_mask and foundation_hyp_ip != foundation_cvm_ip:
        network_groups.append((foundation_cvm_ip, cvm_mask))
    create_all_interfaces(network_groups)
    return


def create_interface(iface, address, netmask):
    """
    Creates a virtual interface with the specified name, address and netmask.
    """
    validate_interface(iface, address, netmask)
    if ping_test(address):
        raise StandardError('Address %s is already in use. Cannot create virtual interface %s with ip %s.' % (
         address, iface, address))
    proc = Popen([
     'sudo ifconfig %s %s netmask %s up' % (
      iface, address, netmask)], shell=True, stdout=PIPE, stderr=PIPE)
    out, err = proc.communicate()
    ret = proc.returncode
    if ret:
        raise StandardError("Failed to create virtual interface '%s': %s" % (
         iface, out + err))
    else:
        logging.info('Created %s with ip %s and netmask %s successfully' % (
         iface, address, netmask))


def ping_test(address):
    logger.debug("Pinging %s to see if it's in use" % address)
    proc = Popen(['ping', '-w', '6', address], stdout=PIPE, stderr=PIPE)
    proc.communicate()
    ret = proc.returncode
    return not ret


def delete_interface(iface):
    """
    Deletes a virtual interface with the specified name.
    """
    validate_interface(iface)
    proc = Popen(['sudo ifconfig %s down' % iface], shell=True)
    proc.communicate()


def validate_interface(iface, address=None, netmask=None):
    if ':' not in iface:
        raise StandardError("Invalid virtual interface '%s' specified" % iface)
    base_adapter = iface.split(':')[0]
    if not os.path.exists('/sys/class/net/%s' % base_adapter):
        raise StandardError("Base adapter '%s' does not exist" % base_adapter)
    if address:
        validate_and_correct_ip(address)
    if netmask:
        validate_and_correct_netmask(netmask)


def delete_multihoming_interfaces():
    """
    Helper API to delete multihoming interfaces
    
    Args: None
    Returns: None
    """
    for iface in range(3):
        delete_interface('eth0:%d' % iface)


def create_all_interfaces(network_groups):
    """
    Creates all virtual interfaces (IPMI, Hypervisor, CVM).
    """
    delete_multihoming_interfaces()
    out, err, ret = system(None, ['/sbin/ifconfig', 'eth0'], log_on_error=False)
    inet_addr = re.findall('inet addr:(\\d+\\.\\d+\\.\\d+\\.\\d+).*', out)
    if inet_addr:
        eth0_ip = inet_addr[0]
    else:
        eth0_ip = None
    for index, net_group in enumerate(network_groups):
        vif_ip, netmask = net_group
        if vif_ip != eth0_ip:
            create_interface('eth0:%d' % index, vif_ip, netmask)
        else:
            logging.debug('Skipped creation of eth0:%d with ip %s and netmask %s, because eth0 already has this ip assigned. ' % (
             index, vif_ip, netmask))

    return


def validate_vlan_interface(iface, vlan_id, address=None, netmask=None):
    """
    Validates if sub-inteface can be created
    
    Args:
      iface: Sub-interface to be validated
      vlan_id: Vlan id to be validated
      address: IPv4 address
      netmask: netmask to be used
    Returns:
      None
    Raises:
      StandardError if validation fails
    """
    if '.' not in iface:
        raise StandardError("Invalid vlan interface '%s' specified" % iface)
    base_adapter = iface.split('.')[0]
    if not os.path.exists('/sys/class/net/%s' % base_adapter):
        raise StandardError("Base adapter '%s' does not exist" % base_adapter)
    if int(vlan_id) not in range(1, 4095):
        raise StandardError('Vlan id %s is incorrect' % vlan_id)
    if address:
        validate_and_correct_ip(address)
    if netmask:
        validate_and_correct_netmask(netmask)


def delete_vlan_interface(iface, vlan_id):
    """
    Deletes a VLAN Sub-interface with the specified name.
    
    Args:
      iface: Sub-interface to be deleted (could be "eth0.2146", "eth0.100" etc)
      vlan_id: Vlan to be deleted
    Returns:
      True or False if operations succeeds or fails
    Raises:
      StandardError if unable to delete the sub-interface
    """
    validate_vlan_interface(iface, vlan_id)
    cmd_list = ['sudo', 'vconfig', 'rem', '%s' % iface]
    out, err, ret = system(None, cmd_list, throw_on_error=False, log_on_error=False)
    if ret:
        raise StandardError('Failed to delete vlan interface %s ' % iface)
    return True


def create_vlan_interface(iface, vlan_id, netmask, address):
    """
    Creates a virtual interface with the specified name, address and netmask.
    
    Args:
      iface: Sub-interface to be created (could be "eth0.2146", "eth0.100" etc)
      vlan_id: Vlan to be set on the subinterface
      netmask: netmask to be used
      address: IPv4 address to be set
    Returns:
      True or False if operation succeeds or fails
    Raises:
      StandaradError if unable to create the sub-interface
    """
    base_adapter = iface.split('.')[0]
    validate_vlan_interface(iface, vlan_id, address, netmask)
    if ping_test(address):
        raise StandardError('Address %s is already in use. Cannot create virtual interface %s with ip %s.' % (
         address, iface, address))
    nics = netifaces.interfaces()
    for nic in nics:
        if nic.startswith('lo'):
            continue
        addrs = netifaces.ifaddresses(nic)
        if not addrs.get(netifaces.AF_INET):
            continue
        if not addrs.get(netifaces.AF_INET6):
            continue
        ipv4 = addrs[netifaces.AF_INET][0]['addr']
        if address == ipv4:
            msg = 'Skipped creation of %s with ip %s and netmask %s, because %s already has this ip assigned.' % (
             iface, address, nic)
            logger.debug(msg)
            raise StandardError(msg)

    cmd = ['sudo', 'ip', 'link', 'add', 'link', base_adapter, 'name',
     iface, 'type', 'vlan', 'id', vlan_id]
    out, err, ret = system(None, cmd, throw_on_error=False, log_on_error=False)
    if ret:
        raise StandardError("Failed to create virtual interface '%s': %s" % (
         iface, out + err))
    cmd = [
     'sudo', 'ifconfig', iface, address, 'netmask', netmask, 'up']
    out, err, ret = system(None, cmd, throw_on_error=False, log_on_error=False)
    if ret:
        raise StandardError("Failed to create virtual interface '%s': %s" % (
         iface, out + err))
    else:
        logger.info('Created %s with ip %s and netmask %s successfully' % (
         iface, address, netmask))
    return True