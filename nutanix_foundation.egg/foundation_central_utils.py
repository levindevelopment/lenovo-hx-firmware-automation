# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/foundation_central_utils.py
# Compiled at: 2019-02-15 12:42:10
import os, logging, json, re, time
from cluster.genesis.node_manager import NodeManager
from foundation import folder_central
from foundation import foundation_settings
from foundation import foundation_tools as tools
from foundation import new_threading_model as ntm
from foundation import session_manager
from foundation.cvm_utilities import detect_local_hypervisor_type
from foundation.fc_rest_client import FCRestClient
from foundation.shared_functions import MASTER_VERSION, NOS_VERSION_RE
from foundation.tinyrpc import call_genesis_method, RpcError
DEFAULT_LOGGER = logging.getLogger(__file__)
FACTORY_CONFIG_FILE = '/etc/nutanix/factory_config.json'
IPV6_INTERFACE = 'eth0'
MAX_RETRIES = 5
TIME_INTERVAL = 10
PROGRESS_INTERVAL = 30
RPC_INTERVAL = 30
RPC_RETRIES = 20
PUT_TIME_INTERVAL = 2

def update_fc_metadata_file(new_dict):
    """
    If fc_metadata_file exists, this method updates the file.
    Else, it creates a new file and writes to the file.
    Args:
    new_dict: Dictionary to be appended or to be written to fc_metadata_file.
    """
    fc_dict = {}
    fc_metadata_file = folder_central.get_fc_metadata_path()
    if os.path.exists(fc_metadata_file):
        fc_dict = json.load(open(fc_metadata_file))
    fc_dict.update(new_dict)
    tmp_file = os.path.join(folder_central.get_tmp_folder(), 'temp.json')
    with open(tmp_file, 'w') as (outfile):
        outfile.write(json.dumps(fc_dict, indent=2))
    cmd = [
     'sudo', 'mv', tmp_file, fc_metadata_file]
    tools.system(None, cmd, throw_on_error=True)
    return


def get_registration_data():
    """
    This method is used to get the details of the node by calling various
    genesis rpcs.
    Returns:
      Node details required by /imaged_nodes/POST in dictionary format.
    """
    req_keys = [
     'node_type', 'cvm_uuid', 'node_serial', 'node_position', 'model',
     'block_serial', 'hardware_attributes', 'cvm_ip', 'cvm_netmask',
     'cvm_gateway', 'hypervisor_ip', 'hypervisor_netmask',
     'hypervisor_gateway', 'aos_version', 'hypervisor_type',
     'hypervisor_version', 'hypervisor_hostname']
    post_data = {key:None for key in req_keys}
    factory_config_dict = json.load(open(FACTORY_CONFIG_FILE))
    hardware_config_dict = json.load(open(folder_central.get_cvm_hardware_config_path()))
    post_data['node_type'] = 'on-prem'
    if factory_config_dict:
        post_data['cvm_uuid'] = factory_config_dict.get('node_uuid', None)
        post_data['node_serial'] = factory_config_dict.get('node_serial', None)
        post_data['node_position'] = factory_config_dict.get('node_position', None)
        post_data['block_serial'] = factory_config_dict.get('rackable_unit_serial', None)
    if hardware_config_dict and 'node' in hardware_config_dict and 'model_string' in hardware_config_dict['node']:
        post_data['model'] = hardware_config_dict['node']['model_string']
    if hardware_config_dict and 'node' in hardware_config_dict and 'hardware_attributes' in hardware_config_dict['node']:
        post_data['hardware_attributes'] = hardware_config_dict['node']['hardware_attributes']
    fc_settings_dict = foundation_settings.get_settings().get('fc_settings', {})
    ipv6_interface = fc_settings_dict.get('ipv6_interface', IPV6_INTERFACE)
    post_data['ipv6_interface'] = ipv6_interface
    post_data['cvm_ipv6'] = _get_cvm_link_local_ipv6_address(ipv6_interface)
    node_data = get_common_node_details()
    post_data.update(node_data)
    missing_keys = []
    for name in req_keys:
        if not post_data[name]:
            missing_keys.append(name)

    if not missing_keys:
        return post_data
    raise KeyError("Couldn't get the values of the following required keys %s" % missing_keys)
    return


def _get_cvm_link_local_ipv6_address(interface='eth0'):
    """
    Returns ipv6 address of the interface. None, if an error occurs.
    """
    cmd_list = [
     'ip', 'address', 'show', interface]
    out, err, ret = tools.system(config=None, cmd_list=cmd_list, log_on_error=False, throw_on_error=False)
    if ret:
        DEFAULT_LOGGER.info('Error while executing cmd %r on CVM; ret %d, stdout %s, stderr %s' % (
         cmd_list, ret, out, err))
        return
    ipv6 = None
    link_local_pattern = 'inet6\\s(fe80(:[0-9a-fA-F]{0,4}){1,7})'
    match = re.search(link_local_pattern, out)
    if match and match.group(1):
        ipv6 = match.group(1)
        DEFAULT_LOGGER.info('CVM ipv6 addr: %s' % ipv6)
    else:
        DEFAULT_LOGGER.error('Failed in getting link local ipv6 address of the CVM')
    return ipv6


def _get_network_settings():
    """
    Returns discovered IP config of CVM, hypervisor and IPMI for this node.
    """
    cvm_ip_config = hypervisor_ip_config = ipmi_ip_config = None
    ret = call_genesis_method('localhost', NodeManager.get_ip)
    if isinstance(ret, RpcError) or not ret:
        error = 'Failed to get ip config of local node - Error: %s' % ret
        DEFAULT_LOGGER.error(error)
        return (
         cvm_ip_config, hypervisor_ip_config, ipmi_ip_config)
    cvm_ip_config, hypervisor_ip_config, ipmi_ip_config = ret
    if cvm_ip_config is None:
        error = 'CVM IP config of local node is None'
        DEFAULT_LOGGER.error(error)
    if hypervisor_ip_config is None:
        error = 'Hypervisor IP config of local node is None'
        DEFAULT_LOGGER.error(error)
    if ipmi_ip_config is None:
        error = 'IPMI IP config of local node is None'
        DEFAULT_LOGGER.error(error)
    return (cvm_ip_config, hypervisor_ip_config, ipmi_ip_config)


def _get_software_version():
    """
    Returns the software version installed on the node.
    """
    ret = call_genesis_method('localhost', NodeManager.software_version)
    if isinstance(ret, RpcError) or not ret:
        error = 'Failed to get software version installed on local node - Error: %s' % ret
        DEFAULT_LOGGER.error(error)
        return
    nos_version = ret.get('nutanix_release_version', None)
    if nos_version:
        nos_version_match = NOS_VERSION_RE.match(nos_version)
        if not nos_version_match:
            message = "Couldn't parse nutanix version %s" % nos_version
            DEFAULT_LOGGER.info(message)
            DEFAULT_LOGGER.info('Foundation will assume this is a dev build')
            return MASTER_VERSION
        return nos_version_match.group(1)
    return nos_version


def get_hypervisor_version(hypervisor_ip, hypervisor_type):
    """
    Returns the hypervisor version installed on the node.
    Sample versions returned for each hypervisor:
    AHV - 20170830.171
    ESX - 6.5.0
    Hyperv - 2016
    """
    if hypervisor_type == 'kvm':
        cmd_list = [
         'ssh', '-i', '/home/nutanix/.ssh/id_rsa', 'root@192.168.5.1',
         'cat /etc/nutanix-release']
        out, err, ret = tools.system(config=None, cmd_list=cmd_list, log_on_error=False, throw_on_error=False)
        if ret:
            DEFAULT_LOGGER.info('Error while executing cmd %r on %s; ret %d, stdout %s, stderr %s' % (
             cmd_list, hypervisor_ip, ret, out, err))
            return
        out = out.split('.')
        version = '%s.%s' % (out[2], out[3])
    else:
        if hypervisor_type == 'esx':
            cmd_list = [
             'ssh', '-i', '/home/nutanix/.ssh/id_rsa', 'root@192.168.5.1',
             'vmware -v']
            version, err, ret = tools.system(config=None, cmd_list=cmd_list, log_on_error=False, throw_on_error=False)
            if ret:
                DEFAULT_LOGGER.info('Error while executing cmd %r on %s; ret %d, stdout %s, stderr %s' % (
                 cmd_list, hypervisor_ip, ret, version, err))
                return
            version = version.split(' ')[2]
        else:
            if hypervisor_type == 'hyperv':
                cmd_list = [
                 '/usr/local/nutanix/bin/winsh',
                 '"(Get-CimInstance Win32_OperatingSystem).caption"']
                version, err, ret = tools.system(config=None, cmd_list=cmd_list, log_on_error=False, throw_on_error=False)
                if ret:
                    DEFAULT_LOGGER.info('Error while executing cmd %r on cvm; ret %d, stdout %s, stderr %s' % (
                     cmd_list, ret, version, err))
                    return
                version = version.split(' ')[3]
    return version


def get_hypervisor_hostname(hypervisor_ip, hypervisor_type):
    """
    Returns the hypervisor hostname on success or None, otherwise.
    """
    if hypervisor_type == 'kvm':
        cmd_list = [
         'ssh', '-i', '/home/nutanix/.ssh/id_rsa', 'root@192.168.5.1',
         'cat /etc/hostname']
        out, err, ret = tools.system(config=None, cmd_list=cmd_list, log_on_error=False, throw_on_error=False)
        if ret:
            DEFAULT_LOGGER.info('Error while executing cmd %r on %s; ret %d, stdout %s, stderr %s' % (
             cmd_list, hypervisor_ip, ret, out, err))
            return
        hostname = out.strip('\n')
    else:
        if hypervisor_type == 'esx':
            cmd_list = [
             'ssh', '-i', '/home/nutanix/.ssh/id_rsa', 'root@192.168.5.1',
             'hostname -s']
            out, err, ret = tools.system(config=None, cmd_list=cmd_list, log_on_error=False, throw_on_error=False)
            if ret:
                DEFAULT_LOGGER.info('Error while executing cmd %r on %s; ret %d, stdout %s, stderr %s' % (
                 cmd_list, hypervisor_ip, ret, out, err))
                return
            hostname = out.strip('\n')
        else:
            if hypervisor_type == 'hyperv':
                cmd_list = [
                 '/usr/local/nutanix/bin/winsh', 'hostname']
                out, err, ret = tools.system(config=None, cmd_list=cmd_list, log_on_error=False, throw_on_error=False)
                if ret:
                    DEFAULT_LOGGER.info('Error while executing cmd %r on cvm; ret %d, stdout %s, stderr %s' % (
                     cmd_list, ret, out, err))
                    return
                hostname = out.strip('\n')
    return hostname


def update_fc():
    """
    Updates Foundation Central that the node is available for cluster creation.
    """
    fc_metadata_file = folder_central.get_fc_metadata_path()
    if os.path.exists(fc_metadata_file):
        fc_dict = json.load(open(fc_metadata_file))
    else:
        return
    req_keys = [
     'fc_ip', 'api_key', 'imaged_node_uuid']
    if not all((key in fc_dict for key in req_keys)):
        return
    if is_node_configured():
        return
    fc_rest_client = FCRestClient(fc_dict['fc_ip'], fc_dict['api_key'])
    resource = 'imaged_nodes/%s/heartbeat' % fc_dict['imaged_node_uuid']
    ret, response = fc_rest_client.rest_call(resource=resource, method='POST')
    if ret != 200:
        DEFAULT_LOGGER.error('Failed to update the node status in Foundation Central with error %s' % response)
    else:
        DEFAULT_LOGGER.info('Successfully updated FC about node status')


def is_node_configured():
    """
    Makes a genesis RPC and checks if the node is configured or not.
    Returns:
      False, if the node is configured or if an RPC Error occurs.
      True, otherwise.
    """
    retry_count = RPC_RETRIES
    while retry_count:
        response = call_genesis_method('localhost', NodeManager.configured)
        if isinstance(response, RpcError):
            error = 'Failed to get status of the node from genesis - Error: %s. Retrying in %s seconds' % (
             response, RPC_INTERVAL)
            DEFAULT_LOGGER.error(error)
            retry_count -= 1
            time.sleep(RPC_INTERVAL)
            if not retry_count:
                return True
        else:
            return response


def is_interface_in_dhcp(interface_name):
    """
    This function reads the configuration file for the specified interface_name
    and returns the status of the interface.
    Returns:
      True, if the interface is in dhcp mode.
      False, otherwise.
    """
    configuration_file_name = '/etc/sysconfig/network-scripts/ifcfg-%s' % interface_name
    cmd = ['sudo', 'cat', configuration_file_name]
    try:
        config, stderr, rc = tools.system(None, cmd, throw_on_error=True)
    except Exception:
        DEFAULT_LOGGER.exception('Encountered exception while reading theconfiguration_file %s' % configuration_file_name)
        return False
    else:
        if not (config and 'dhcp' in config.lower()):
            return False

    return True
    return


def get_imaged_node_uuid(cvm_ip, session_id=None):
    """
    Returns the imaged_node_uuid corresponding to the cvm_ip.
    """
    global_config = session_manager.get_global_config(session_id)
    for node in global_config.nodes:
        if getattr(node, 'cvm_ip', None) == cvm_ip:
            return getattr(node, 'fc_imaged_node_uuid', None)

    return


def _parse_progress_output(result):
    """
    This method takes the foundation progress json as input and parses it to be
    in-line with the input of /imaged_clusters/<imaged_cluster_uuid>/status/PUT.
    Args:
      result: Dictionary containing imaging session progress details.
    Returns:
      progress: Dictionary as expected by
                /imaged_clusters/<imaged_cluster_uuid>/status/PUT on success.
      None, otherwise.
    """
    if not (result and result['clusters'] and result['nodes']):
        DEFAULT_LOGGER.info('No data to be updated')
        return {}
    progress = {}
    progress['cluster_status'] = {}
    progress['nodes_status'] = []
    progress['current_foundation_ip'] = tools.get_interface_ip()
    progress['foundation_session_id'] = result['session_id']
    progress['imaging_stopped'] = result['imaging_stopped']
    progress['aggregate_percent_complete'] = result['aggregate_percent_complete']
    if 'clusters' in result:
        if len(result['clusters']) != 1:
            DEFAULT_LOGGER.error('Submitted cluster creation intent only for onecluster, but multiple clusters appear in progress output')
            return
        for cluster in result['clusters']:
            progress['cluster_status']['cluster_name'] = cluster.get('cluster_name', None)
            progress['cluster_status']['status'] = cluster.get('status', '')
            progress['cluster_status']['percent_complete'] = cluster.get('percent_complete', 0)
            progress['cluster_status']['message_list'] = cluster.get('messages', [])

    if 'nodes' in result:
        for node in result['nodes']:
            new_dict = {}
            new_dict['imaged_node_uuid'] = get_imaged_node_uuid(node['cvm_ip'], result['session_id'])
            new_dict['status'] = node.get('status', '')
            new_dict['percent_complete'] = node.get('percent_complete', 0)
            new_dict['message_list'] = node.get('messages', [])
            progress['nodes_status'].append(new_dict)

    return progress


def update_progress(session_id=None):
    """
    This method updates Foundation Central about the cluster creation progress
    once in every 10 seconds.
    Returns:
      True, if progress is updated successfully in FC.
      False, otherwise.
    """
    fc_metadata_file = folder_central.get_fc_metadata_path()
    if os.path.exists(fc_metadata_file):
        fc_dict = json.load(open(fc_metadata_file))
    else:
        raise OSError("Couldn't find %s" % fc_metadata_file)
    sm = session_manager.get_session_manager()
    session_ids = sm.get_all_session_ids()
    if not session_id:
        last_active_session_id = session_manager.get_last_active_session_id()
        if not session_ids or not last_active_session_id:
            result = {}
            result['session_id'] = None
            result['imaging_stopped'] = True
            result['action'] = ''
            result['aggregate_percent_complete'] = 0
            result['nodes'] = []
            result['clusters'] = []
            result['results'] = None
            return False
        session_id = last_active_session_id
    else:
        if session_id not in session_ids:
            raise StandardError("Invalid session id '%s' provided" % session_id)
        fc_rest_client = FCRestClient(fc_dict['fc_ip'], fc_dict['api_key'])
        resource = 'imaged_nodes/%s' % fc_dict['imaged_node_uuid']
        retry_count = MAX_RETRIES
        while retry_count:
            ret, response = fc_rest_client.rest_call(resource=resource, method='GET')
            if ret == 200 and response.get('imaged_cluster_uuid', None):
                imaged_cluster_uuid = response['imaged_cluster_uuid']
                break
            else:
                DEFAULT_LOGGER.error('Failed to get imaged_cluster_uuid')
                retry_count -= 1
            if not retry_count:
                DEFAULT_LOGGER.error("Couldn't get imaged_cluster_uuid for node:%s" % fc_dict['imaged_node_uuid'])
                return False
            time.sleep(TIME_INTERVAL)

        while True:
            result = ntm.get_progress(session_id)
            progress = _parse_progress_output(result)
            resource = 'imaged_clusters/%s/status' % imaged_cluster_uuid
            if progress:
                ret, response = fc_rest_client.rest_call(resource=resource, method='PUT', body=progress)
                if ret != 200:
                    DEFAULT_LOGGER.error('Error in updating cluster creation status with Foundation Central')
                else:
                    if result['aggregate_percent_complete'] == 100 and result['imaging_stopped']:
                        DEFAULT_LOGGER.info('Cluster creation completed. Updated progress in Foundation Central')
                        return True
                    if result['aggregate_percent_complete'] not in (0, 100) and result['imaging_stopped']:
                        DEFAULT_LOGGER.error("Couldn't complete cluster creation request")
                        return False
            time.sleep(PROGRESS_INTERVAL)

    return


def notify_fc_with_progress(status, imaged_cluster_uuid, imaging_stopped=True):
    """
    This method updates Foundation Central by calling
    /imaged_clusters/<imaged_cluster_uuid>/status/PUT in the event of failures
    in initializing cluster creation.
    Args:
      status: Status message to be updated in FC.
    Returns:
      True, if progress is updated successfully in FC.
      False, otherwise.
    """
    if not imaged_cluster_uuid:
        DEFAULT_LOGGER.error("No imaged_cluster_uuid provided. Can't update Foundation Central")
        return False
    fc_metadata_file = folder_central.get_fc_metadata_path()
    if os.path.exists(fc_metadata_file):
        fc_dict = json.load(open(fc_metadata_file))
    else:
        return False
    progress = {'current_foundation_ip': tools.get_interface_ip(), 
       'foundation_session_id': '', 
       'imaging_stopped': imaging_stopped, 
       'aggregate_percent_complete': 0, 
       'cluster_status': {'cluster_name': '', 
                          'status': str(status), 
                          'percent_complete': 0, 
                          'message_list': []}, 
       'nodes_status': []}
    fc_rest_client = FCRestClient(fc_dict['fc_ip'], fc_dict['api_key'])
    resource = 'imaged_clusters/%s/status' % imaged_cluster_uuid
    retry_count = MAX_RETRIES
    while retry_count:
        ret, response = fc_rest_client.rest_call(resource=resource, method='PUT', body=progress)
        if ret == 404:
            DEFAULT_LOGGER.error('Cluster with imaged_cluster_uuid: %s no longer exists. Failed updating cluster creation progress in Foundation Central' % imaged_cluster_uuid)
            return False
        if ret != 200:
            retry_count -= 1
            DEFAULT_LOGGER.error('Error in updating cluster creation status with Foundation Central. Retrying in %s seconds. Retries left: %s' % (
             TIME_INTERVAL, retry_count))
        else:
            DEFAULT_LOGGER.info('Updated cluster progress in Foundation Central')
            return True
        time.sleep(TIME_INTERVAL)

    DEFAULT_LOGGER.error('Failed to update progress in Foundation Central')
    return False


def update_imaged_node_network_details(ip_config, imaged_node_uuid):
    """
    This method updates Foundation Central about the node's current network
    configuration by calling /imaged_nodes/<imaged_node_uuid>/PUT.
    Args:
      ip_config: Node IP configuration as tuple
                (cvm_ip, hypervisor_ip, ipmi_ip), where each element is a dict
                with keys:
                  'address', 'netmask', 'gateway'
      imaged_node_uuid: imaged_node_uuid of the node entity in Foundation Central.
    Returns:
      True, if it succeeds updating Foundation Central.
      False, otherwise.
    """
    put_data = {}
    cvm_ip_config, hypervisor_ip_config, ipmi_ip_config = ip_config
    if cvm_ip_config:
        put_data['cvm_ip'] = cvm_ip_config.get('address', None)
        put_data['cvm_netmask'] = cvm_ip_config.get('netmask', None)
        put_data['cvm_gateway'] = cvm_ip_config.get('gateway', None)
    if hypervisor_ip_config:
        put_data['hypervisor_ip'] = hypervisor_ip_config.get('address', None)
        put_data['hypervisor_netmask'] = hypervisor_ip_config.get('netmask', None)
        put_data['hypervisor_gateway'] = hypervisor_ip_config.get('gateway', None)
    if ipmi_ip_config:
        put_data['ipmi_ip'] = ipmi_ip_config.get('address', None)
        put_data['ipmi_netmask'] = ipmi_ip_config.get('netmask', None)
        put_data['ipmi_gateway'] = ipmi_ip_config.get('gateway', None)
    return update_imaged_node_details(imaged_node_uuid, put_data)


def update_registered_node_in_fc(imaged_node_uuid):
    """
    This method updates the details of the imaged node in Foundation Central.
    Args:
      imaged_node_uuid: imaged_node_uuid of the node entity in Foundation Central.
    Returns:
      True, if it succeeds updating Foundation Central.
      False, otherwise.
    """
    if not imaged_node_uuid:
        DEFAULT_LOGGER.error('imaged_node_uuid is not provided')
        return False
    put_data = {}
    factory_config_dict = json.load(open(FACTORY_CONFIG_FILE))
    hardware_config_dict = json.load(open(folder_central.get_cvm_hardware_config_path()))
    if factory_config_dict:
        put_data['cvm_uuid'] = factory_config_dict.get('node_uuid', None)
        put_data['node_position'] = factory_config_dict.get('node_position', None)
    if hardware_config_dict and 'node' in hardware_config_dict and 'hardware_attributes' in hardware_config_dict['node']:
        put_data['hardware_attributes'] = hardware_config_dict['node']['hardware_attributes']
    node_data = get_common_node_details()
    put_data.update(node_data)
    return update_imaged_node_details(imaged_node_uuid, put_data)


def get_common_node_details():
    """
    This method gets the details of the node that are common for making
    /imaged_nodes/POST and /imaged_nodes/<imaged_node_uuid>/PUT calls to
    Foundation Central.
    Returns:
      Dictionary with the following keys.
      ["cvm_ip", "cvm_netmask", "cvm_gateway", "hypervisor_ip",
       "hypervisor_netmask", "hypervisor_gateway", "ipmi_ip", "ipmi_netmask",
       "ipmi_gateway", "aos_version", "hypervisor_type", "hypervisor_version",
       "hypervisor_hostname", "foundation_version"]
    """
    node_data = {}
    cvm_ip_config, hypervisor_ip_config, ipmi_ip_config = _get_network_settings()
    if cvm_ip_config:
        node_data['cvm_ip'] = cvm_ip_config.get('address', None)
        node_data['cvm_netmask'] = cvm_ip_config.get('netmask', None)
        node_data['cvm_gateway'] = cvm_ip_config.get('gateway', None)
    if hypervisor_ip_config:
        node_data['hypervisor_ip'] = hypervisor_ip_config.get('address', None)
        node_data['hypervisor_netmask'] = hypervisor_ip_config.get('netmask', None)
        node_data['hypervisor_gateway'] = hypervisor_ip_config.get('gateway', None)
    if ipmi_ip_config:
        node_data['ipmi_ip'] = ipmi_ip_config.get('address', None)
        node_data['ipmi_netmask'] = ipmi_ip_config.get('netmask', None)
        node_data['ipmi_gateway'] = ipmi_ip_config.get('gateway', None)
    node_data['aos_version'] = _get_software_version()
    try:
        node_data['hypervisor_type'] = detect_local_hypervisor_type()
    except Exception:
        DEFAULT_LOGGER.exception("Couldn't detect the local hypervisor type.")

    node_data['hypervisor_version'] = get_hypervisor_version(node_data['hypervisor_ip'], node_data['hypervisor_type'])
    node_data['hypervisor_hostname'] = get_hypervisor_hostname(node_data['hypervisor_ip'], node_data['hypervisor_type'])
    node_data['foundation_version'] = tools.get_current_foundation_version()
    return node_data


def update_imaged_node_details(imaged_node_uuid, put_data):
    """
    This method updates the details of imaged_node in Foundation Central.
    Args:
      imaged_node_uuid: imaged_node_uuid of the node entity in Foundation Central.
      put_data: Node details required by /imaged_nodes/<imaged_node_uuid>/PUT
                in dictionary format.
    Returns:
      True, if it succeeds updating Foundation Central.
      False, otherwise.
    """
    fc_metadata_file = folder_central.get_fc_metadata_path()
    if os.path.exists(fc_metadata_file):
        fc_dict = json.load(open(fc_metadata_file))
    else:
        return False
    fc_rest_client = FCRestClient(fc_dict['fc_ip'], fc_dict['api_key'])
    resource = 'imaged_nodes/%s' % imaged_node_uuid
    retry_count = MAX_RETRIES
    while retry_count:
        ret, response = fc_rest_client.rest_call(resource=resource, method='GET')
        if ret == 200 and response.get('object_version', None):
            put_data['object_version'] = response['object_version']
            ret, response = fc_rest_client.rest_call(resource=resource, method='PUT', body=put_data)
            if ret == 200:
                return True
            if ret == 400:
                retry_count -= 1
                DEFAULT_LOGGER.info('Object version has changed in Foundation central. Retrying in %s seconds. Retries left: %s' % (
                 PUT_TIME_INTERVAL, retry_count))
            else:
                return False
        else:
            retry_count -= 1
            DEFAULT_LOGGER.error('Failed to find object_version on the node.Retrying in %s seconds. Retries left: %s' % (
             resource, PUT_TIME_INTERVAL, retry_count))
        time.sleep(PUT_TIME_INTERVAL)

    return False