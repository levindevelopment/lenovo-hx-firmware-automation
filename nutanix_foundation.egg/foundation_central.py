# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/foundation_central.py
# Compiled at: 2019-02-15 12:42:10
import json, logging, os, time, threading
from foundation import config_validator as cv
from foundation import config_parser
from foundation import config_persistence
from foundation import dhcp_options
from foundation import folder_central
from foundation import foundation_central_utils as fc_utils
from foundation import foundation_settings
from foundation import foundation_tools
from foundation import ipmi_config
from foundation import session_manager
from foundation.fc_rest_client import FCRestClient
DEFAULT_LOGGER = logging.getLogger(__file__)
HEARTBEAT_INTERVAL_MINS = 10
INTENT_POLL_INTERVAL_MINS = 15
MAX_RETRIES = 5
VENDOR_CLASS = 'NutanixFC'
REGISTER_INTERVAL_MINS = 15
RETRY_INTERVAL = 300

def initiate_fc():
    DEFAULT_LOGGER.info('Starting Foundation Central workflow')
    fc_thread = threading.Thread(target=fc_workflow)
    fc_thread.daemon = True
    fc_thread.start()
    DEFAULT_LOGGER.info('Starting Foundation Central heartbeat thread')
    hb_thread = threading.Thread(target=hb_workflow)
    hb_thread.daemon = True
    hb_thread.start()


def hb_workflow():
    fc_settings_dict = foundation_settings.get_settings().get('fc_settings', {})
    heartbeat_interval_mins = fc_settings_dict.get('heartbeat_interval_mins', HEARTBEAT_INTERVAL_MINS)
    sm = session_manager.get_session_manager()
    while True:
        while sm.get_active_session_ids():
            DEFAULT_LOGGER.info('An imaging session is currently active. Will try to send heartbeats after %s minutes.' % heartbeat_interval_mins)
            time.sleep(heartbeat_interval_mins * 60)

        fc_utils.update_fc()
        time.sleep(heartbeat_interval_mins * 60)


def progress_workflow(session_id=None):
    try:
        if fc_utils.update_progress(session_id):
            DEFAULT_LOGGER.info('Cluster creation phase completed')
        else:
            DEFAULT_LOGGER.error('Error in completing cluster creation request')
    except OSError:
        DEFAULT_LOGGER.exception("Couldn't find fc_metadata_file")
    except Exception:
        DEFAULT_LOGGER.exception('Invalid session_id: %s provided' % session_id)


def fc_workflow():
    if fc_utils.is_node_configured():
        DEFAULT_LOGGER.info('Node is configured. Not starting FC workflow')
        return
    fc_settings_dict = foundation_settings.get_settings().get('fc_settings', {})
    option_class = fc_settings_dict.get('vendor_class', VENDOR_CLASS)
    intent_poll_interval_mins = fc_settings_dict.get('intent_poll_interval_mins', INTENT_POLL_INTERVAL_MINS)
    registered = False
    fc_dict = {}
    fc_metadata_file = folder_central.get_fc_metadata_path()
    sm = session_manager.get_session_manager()
    if os.path.exists(fc_metadata_file):
        fc_dict = json.load(open(fc_metadata_file))
        if 'imaged_node_uuid' in fc_dict:
            DEFAULT_LOGGER.info('Node is already registered with Foundation Central')
            registered = True
    if not registered:
        DEFAULT_LOGGER.info('Registering the node with Foundation Central')
        register_node_with_fc(option_class)
    else:
        if fc_utils.update_registered_node_in_fc(fc_dict['imaged_node_uuid']):
            DEFAULT_LOGGER.info('Successfully updated the imaged node information in Foundation Central')
        else:
            DEFAULT_LOGGER.error("Couldn't update imaged node information inFoundation Central")
    if os.path.exists(fc_metadata_file):
        fc_dict = json.load(open(fc_metadata_file))
    else:
        DEFAULT_LOGGER.error("Couldn't find %s" % fc_metadata_file)
        return
    while True:
        imaged_cluster_uuid = get_cluster_creation_intent()
        if not imaged_cluster_uuid:
            DEFAULT_LOGGER.info('No cluster creation intent found. Trying again in %s minutes' % intent_poll_interval_mins)
        else:
            fc_rest_client = FCRestClient(fc_dict['fc_ip'], fc_dict['api_key'])
            resource = 'imaged_clusters/%s' % imaged_cluster_uuid
            ret, response = fc_rest_client.rest_call(resource=resource, method='GET')
            if ret == 200 and response.get('foundation_init_node_uuid', None) == fc_dict['imaged_node_uuid']:
                if not response['cluster_status']['intent_picked_up']:
                    DEFAULT_LOGGER.info('Attempting to create a cluster')
                    if fc_utils.notify_fc_with_progress('Picked up cluster creation intent', imaged_cluster_uuid, imaging_stopped=False):
                        DEFAULT_LOGGER.info('Starting cluster creation thread')
                        cc_thread = threading.Thread(target=create_cluster, args=(
                         imaged_cluster_uuid,))
                        cc_thread.daemon = True
                        cc_thread.start()
                        cc_thread.join()
                        while sm.get_active_session_ids():
                            time.sleep(intent_poll_interval_mins * 60)

                    else:
                        DEFAULT_LOGGER.error('Failed to notify Foundation that the cluster creation intent was picked up. Skipping cluster creation...')
                else:
                    DEFAULT_LOGGER.info('Existing cluster creation intent has been addressed. Checking for a new cluster creation intent in %s minutes' % intent_poll_interval_mins)
            else:
                DEFAULT_LOGGER.info('Current node is not the foundation_init_node. Not initiating cluster creation process. Checking for a new intent in %s minutes' % intent_poll_interval_mins)
        time.sleep(intent_poll_interval_mins * 60)

    return


def create_cluster(imaged_cluster_uuid):
    """
    This method acts as a wrapper around _create_cluster by handling the
    exceptions raised by _create_cluster.
    """
    try:
        _create_cluster(imaged_cluster_uuid)
    except Exception as error:
        fc_utils.notify_fc_with_progress(error, imaged_cluster_uuid, imaging_stopped=True)
        DEFAULT_LOGGER.exception('Cluster creation failed with error %s' % str(error))


def register_node_with_fc(option_class):
    """
    This method reads the Foundation Central's IP from DHCP vendor-specific
    options and writes them to /etc/nutanix/foundation_central.json.
    It also sends the node information to Foundation Central by
    calling /imaged_nodes/POST which will return a imaged_node_uuid
    which will be stored in foundation_central.json.
    
    Args:
      option_class: Class in which the vendor specific option is
                    defined. This class is uniquely identified by
                    the vendor-class-identifier.
    """
    fc_settings_dict = foundation_settings.get_settings().get('fc_settings', {})
    register_interval_mins = fc_settings_dict.get('register_interval_mins', REGISTER_INTERVAL_MINS)
    fc_metadata_file = folder_central.get_fc_metadata_path()
    sm = session_manager.get_session_manager()
    while True:
        if os.path.exists(fc_metadata_file):
            option_dict = json.load(open(fc_metadata_file))
            if 'fc_ip' in option_dict and 'api_key' in option_dict:
                DEFAULT_LOGGER.info('fc_ip and api_key exist in %s. Skipping reading vendor options' % fc_metadata_file)
                break
        while sm.get_active_session_ids() or fc_utils.is_node_configured() or not fc_utils.is_interface_in_dhcp('eth0'):
            DEFAULT_LOGGER.info('Node is not in a state to read DHCP options. Will try to read dhcp options after %s minutes.' % (RETRY_INTERVAL / 60))
            time.sleep(RETRY_INTERVAL)

        option_dict = dhcp_options.read_vendor_options(option_class)
        if not option_dict:
            DEFAULT_LOGGER.info('Required vendor-encapsulated options not found. Trying again in %s minutes.' % register_interval_mins)
            time.sleep(register_interval_mins * 60)
            continue
        if 'fc_ip' in option_dict and 'api_key' in option_dict:
            break
        else:
            DEFAULT_LOGGER.info('Required vendor-encapsulated options not found. Trying again in %s minutes.' % register_interval_mins)
            time.sleep(register_interval_mins * 60)

    if option_dict:
        fc_utils.update_fc_metadata_file(option_dict)
        DEFAULT_LOGGER.info('Received vendor-encapsulated-options from DHCP server')
    retry_count = MAX_RETRIES
    while retry_count:
        try:
            post_data = fc_utils.get_registration_data()
            break
        except KeyError:
            DEFAULT_LOGGER.exception("Couldn't get the values of required keys. Retrying in %s minutes" % (RETRY_INTERVAL / 60))
            post_data = None
            time.sleep(RETRY_INTERVAL)
        else:
            retry_count -= 1

    if post_data is None:
        raise StandardError('Required keys are not found')
    fc_rest_client = FCRestClient(option_dict['fc_ip'], option_dict['api_key'])
    while True:
        ret, response = fc_rest_client.rest_call(resource='imaged_nodes', method='POST', body=post_data)
        if ret != 200:
            DEFAULT_LOGGER.error('Failed to register node with Foundation Central. Retrying in %s minutes' % (RETRY_INTERVAL / 60))
            time.sleep(RETRY_INTERVAL)
        else:
            break

    if 'imaged_node_uuid' in response:
        fc_utils.update_fc_metadata_file({'imaged_node_uuid': response['imaged_node_uuid']})
        DEFAULT_LOGGER.info('Node with uuid %s is registered with Foundation Central' % response['imaged_node_uuid'])
    else:
        raise StandardError("Response from the server doesn't have imaged_node_uuid though the API returned status code 200")
    return


def get_cluster_creation_intent():
    """
    This method makes an /imaged_nodes/<imaged_node_uuid>/GET call to check for
    cluster creation intent,
    Returns:
     imaged_cluster_uuid, if cluster creation intent has been submitted.
     None, otherwise.
    """
    fc_metadata_file = folder_central.get_fc_metadata_path()
    if os.path.exists(fc_metadata_file):
        fc_dict = json.load(open(fc_metadata_file))
    else:
        DEFAULT_LOGGER.error("Couldn't find %s" % fc_metadata_file)
        return
    fc_rest_client = FCRestClient(fc_dict['fc_ip'], fc_dict['api_key'])
    resource = 'imaged_nodes/%s' % fc_dict['imaged_node_uuid']
    ret, response = fc_rest_client.rest_call(resource=resource, method='GET')
    if ret == 200 and response.get('imaged_cluster_uuid', None):
        return response['imaged_cluster_uuid']
    return
    return


def _create_cluster(imaged_cluster_uuid):
    """
    This method reads foundation_json_config and starts imaging using the
    CVM workflow.
    """
    from foundation import installer
    fc_metadata_file = folder_central.get_fc_metadata_path()
    if os.path.exists(fc_metadata_file):
        fc_dict = json.load(open(fc_metadata_file))
    else:
        raise StandardError("Couldn't find %s" % fc_metadata_file)
    fc_rest_client = FCRestClient(fc_dict['fc_ip'], fc_dict['api_key'])
    resource = 'imaged_clusters/%s' % imaged_cluster_uuid
    ret, response = fc_rest_client.rest_call(resource=resource, method='GET')
    foundation_init_config = response.get('foundation_init_config', None)
    if not foundation_init_config:
        raise StandardError('Foundation imaging config is not present in the cluster details')
    DEFAULT_LOGGER.info('Config for cluster creation is %s' % foundation_init_config)
    sm = session_manager.get_session_manager()
    active_sessions = sm.get_active_session_ids()
    if active_sessions:
        raise StandardError("Active imaging sessions %s exist, can't trigger imaging using Foundation Central" % active_sessions)
    session_id = session_manager.get_new_session_id()
    config_persistence.persist_config(foundation_init_config)
    foundation_init_config['fc_workflow'] = True
    try:
        global_config = config_parser.parse_json_config_network_validation(foundation_init_config)
    except StandardError as exc:
        session_manager.mark_idle_session_failure(session_id)
        raise StandardError('Exception in parsing cluster creation configuration: %s' % str(exc))
    else:
        try:
            global_config = config_parser.parse_json_config_imaging(foundation_init_config)
        except StandardError as exc:
            session_manager.mark_idle_session_failure(session_id)
            raise StandardError('Exception in parsing cluster creation configuration: %s' % str(exc))
        else:
            foundation_init_config.pop('fc_workflow', None)
            global_config.nv_recover_on_fail = True
            status, err_msg = session_manager.is_session_possible(global_config)
            if not status:
                session_manager.mark_idle_session_failure(session_id)
                raise StandardError(err_msg)
            try:
                cv.common_validations(global_config, quick=True)
            except StandardError as exc:
                session_manager.mark_session_failure(session_id)
                raise StandardError('Exception in performing quick validations: %s' % str(exc))

            fc_progress_thread = threading.Thread(target=progress_workflow, args=(
             session_id,))
            fc_progress_thread.daemon = True
            fc_progress_thread.start()
            try:
                installer.generate_imaging_graph(global_config)
            except StandardError as exc:
                session_manager.mark_session_failure(session_id)
                raise StandardError('Exception in generating imaging graph: %s' % str(exc))

        foundation_init_config['foundation_central'] = True
        foundation_init_config['session_id'] = session_id
        config_persistence.persist_config(foundation_init_config)
        foundation_tools.update_metadata({'persisted_config': foundation_init_config}, session_id)
        foundation_tools.update_metadata({'environ': dict(os.environ)}, session_id)
        foundation_tools.update_metadata({'platform': foundation_tools.platform_info()}, session_id)
        discovered_nodes = None
        try:
            discovered_nodes = ipmi_config.discover_nodes()
        except StandardError:
            DEFAULT_LOGGER.exception('Ignoring exception from discover_nodes()')

    if discovered_nodes:
        cvm_ip_list = []
        for node in global_config.nodes:
            cvm_ip_list.append(node.cvm_ip)

        for d_node_top in discovered_nodes:
            for d_node in d_node_top['nodes']:
                if d_node['svm_ip'] not in cvm_ip_list:
                    d_node_top['nodes'].remove(d_node)

    config_persistence.persist_discovery_info(discovered_nodes, session_id)
    installer.do_imaging_threaded(global_config)
    DEFAULT_LOGGER.info('Started cluster creation')
    return