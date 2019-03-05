# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/dhcp_options.py
# Compiled at: 2019-02-15 12:42:10
import glob, logging, os, sys, time
from foundation import folder_central
from foundation import foundation_tools as tools
DEFAULT_LOGGER = logging.getLogger(__file__)
FOUNDATION_CENTRAL_IP_ADDRESS = 'fc_ip'
API_KEY = 'api_key'
OPTION_MAP = {200: FOUNDATION_CENTRAL_IP_ADDRESS, 201: API_KEY}
CONF_FILE = '/etc/dhcp/dhclient-eth0.conf'
UUID_FILE_NAME = '/etc/sysconfig/network-scripts/ifcfg-eth0'
PRIMARY_LEASE_FILE_NAME = '/var/lib/dhclient/dhclient-eth0.leases'

def read_vendor_options(option_class):
    """
    This method reads the vendor-specific DHCP option sent by the
    DHCP server and returns the value of vendor-specific DHCP option.
    DHCP Client sends the vendor-class-identifier to the server and
    the  DHCP server responds with the option values of the specific
    vendor-class requested by DHCP client.
    
    DHCP server sends vendor-specific-option in the following format:
    option space Nutanix;
    option Nutanix.fc_ip code 200 = string;
    option Nutanix.api_key code 201 = string;
    class "NutanixFC" {
      match if option vendor-class-identifier = "NutanixFC";
      vendor-option-space Nutanix;
      option Nutanix.fc_ip "1.1.1.1";
      option Nutanix.api_key "xxxx-xxxx"
    }
    
    NOTE: 1. This method creates a dhclient-eth0.conf file in /etc/dhcp/
             folder and adds code to read the custom option to the
             dhclient-eth0.conf file.
          2. The network is restarted to renew the DHCP lease and get the
             custom option from dhcp server.
    Args:
      option_class: Class in which the vendor specific option is defined.
                    This class is uniquely identified by the vendor-class-identifier.
    
    Raises:
      StandardError if:
        1. There is no vendor-class in the server corresponding to the
           vendor-class-identifier sent by the client.
        2. The option is garbled or partially received.
    
    Returns:
      Returns a dictionary of option_name and option_value pairs of the vendor-specific
      option/s for the option class requested by the user.
    """
    tmp_file = os.path.join(folder_central.get_tmp_folder(), 'temp.conf')
    cmd = 'also request vendor-encapsulated-options;\nsend vendor-class-identifier "%s";' % option_class
    with open(tmp_file, 'w') as (fd):
        fd.write(cmd)
    cmd = [
     'sudo', 'mv', tmp_file, CONF_FILE]
    tools.system(None, cmd, throw_on_error=True)
    cmd = [
     'sudo', 'chcon', '-t', 'dhcp_etc_t', CONF_FILE]
    tools.system(None, cmd, throw_on_error=False)
    with open(UUID_FILE_NAME) as (uuid_file):
        uuid = None
        for line in uuid_file:
            if 'UUID' in line:
                line = line.split('=')
                uuid = line[1]
                uuid = uuid.strip(';"')
                secondary_lease_file_name = '/var/lib/dhclient/dhclient-%s-eth0.lease' % uuid
                break

        if uuid is None:
            secondary_lease_file_name = '/var/lib/dhclient/dhclient--eth0.lease'
    if os.path.exists(PRIMARY_LEASE_FILE_NAME):
        lease_file_name_list = [
         PRIMARY_LEASE_FILE_NAME]
    else:
        if os.path.exists(secondary_lease_file_name):
            lease_file_name_list = [
             secondary_lease_file_name]
        else:
            lease_file_name_list = glob.glob('/var/lib/dhclient/*.lease*')
    if not lease_file_name_list:
        return
    for lease_file_name in lease_file_name_list:
        DEFAULT_LOGGER.info('Processing dhcp lease file: %s' % lease_file_name)
        option_value = get_option_value(lease_file_name)
        if option_value:
            break

    if not option_value:
        return
    option_value = option_value.strip(';}')
    option_value = option_value.split(':')
    option_dict = {}
    while len(option_value) > 0:
        option_total_length = len(option_value)
        current_option_length = int(option_value[1], 16)
        actual_option_length = 2 + current_option_length
        if len(option_value) < actual_option_length:
            raise StandardError('Complete option is not received')
        option_code_received = int(option_value[0], 16)
        s = ('').join(option_value[2:actual_option_length])
        option_decoded_value = s.decode('hex')
        if option_code_received in OPTION_MAP:
            option_dict[OPTION_MAP[option_code_received]] = option_decoded_value
        option_value = option_value[actual_option_length:option_total_length]

    return option_dict


def get_option_value(lease_file_name):
    """
    This method restarts network and returns the option value of
    vendor-encapsulated-options.
    Args:
      lease_file_name: Name of the file from which dhcp lease should be read.
    Returns:
      option_value: Value of vendor-encapsulated-options in hexadecimal format,
                    if found.
      None, otherwise.
    """
    cmd = [
     'sudo', 'service', 'network', 'restart']
    out, err, ret = tools.system(None, cmd, throw_on_error=False)
    if ret:
        DEFAULT_LOGGER.error('Error while restarting network: %s' % err)
        return
    cmd = [
     'sudo', 'cat', lease_file_name]
    try:
        lease, stderr, rc = tools.system(None, cmd, throw_on_error=True)
    except Exception:
        DEFAULT_LOGGER.exception('Encountered exception while reading the lease_file %s' % lease_file_name)
        return
    else:
        if not lease:
            return
        lease = lease.split()
        if 'vendor-encapsulated-options' in lease and lease.index('vendor-encapsulated-options') + 1 < len(lease):
            option_value = lease[lease.index('vendor-encapsulated-options') + 1]
            return option_value

    DEFAULT_LOGGER.error('No vendor specific options matching the vendor-class-identifier sent.')
    return
    return