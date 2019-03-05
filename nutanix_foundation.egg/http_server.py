# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/http_server.py
# Compiled at: 2019-02-15 12:42:10
import glob, json, logging, mimetypes, os, re, shutil, socket, sys, tarfile, threading, time, traceback, urllib, warnings, cherrypy
from cherrypy.lib.static import serve_file
from cherrypy.process import wspbus
from cluster.genesis.node_manager import NodeManager
from cluster.genesis.cluster_manager import ClusterManager
from util.net.rpc import RpcError
from foundation import archive_log
from foundation import config_manager
from foundation import config_parser
from foundation import config_persistence
from foundation import config_validator as cv
from foundation import configure_network_remote
from foundation import cvm_utilities
from foundation import factory_mode
from foundation import features
from foundation import folder_central
from foundation import foundation_settings
from foundation import foundation_tools
from foundation import generate_phoenix
from foundation import imaging_context
from foundation import installer
from foundation import ipmi_config
from foundation import iso_checksums
from foundation import iso_whitelist
from foundation import network_validation
from foundation import new_threading_model as ntm
from foundation import nic as nic_module
from foundation import portable
from foundation import remote_boot
from foundation import remote_boot_ucsm
from foundation import parameter_validation as pv
from foundation import session_manager
from foundation import shared_functions
from foundation import update_manager
from foundation import virtual_console
from foundation import virtual_interfaces
from foundation import imaging_step_handoff
from foundation.decorators import save_post_params, fail_session_on_error
from foundation.tinyrpc import call_genesis_method, call_genesis_method_over_tunnel
HTTP_PORT = foundation_settings.settings['http_port']
HTTP_SERVER_THREADS = 10
TIMEZONE_INFO_FILE = '/usr/share/zoneinfo/zone.tab'
foundation_api = None
UNIT_TEST_MODE = False
MAXIMUM_TRANSFER_TIMEOUT = 3600
MAXIMUM_MONITOR_TIMEOUT = 20
cherrypy_patched = {}
KICKOFF_DELAY = 5.0
PHOENIX_RETRIES = 3
api_logger = logging.getLogger('foundation.api')

def handle_500_error():
    """
    This function is the handler of unexcepted exceptions and format them in to
    proper 500 with optional embeded structured details.
    
    usage:
      raise StandardError("some error message")
        => {"error": {"message": "some error message", "details": {}}}
      raise StandardError("another error message", {"wrong fields": ["cvm_ip"]})
        => {"error": {"message": "some error message",
                                 "details": {"wrong fields": ["cvm_ip"]}}}
    """

    def _is_json_serializable(obj):
        try:
            json.dumps(obj)
            return True
        except TypeError:
            return False

    cherrypy.response.status = 500
    cherrypy.response.headers['Content-Type'] = 'application/json'
    exception_type, exception, tb = sys.exc_info()
    args = getattr(exception, 'args', ())
    details = {}
    session_id = session_manager.get_session_id()
    if exception_type is StandardError and len(args) < 2:
        error = str(exception)
        details = {}
    else:
        if exception_type is StandardError and len(args) == 2:
            error = exception.args[0]
            details = exception.args[1]
        else:
            error = repr(exception)
    if not _is_json_serializable(error):
        api_logger.warn('%s is not json serializable, formatting as str', repr(error))
        error = repr(error)
    if not _is_json_serializable(details):
        api_logger.warn('%s is not json serializable, formatting as str', repr(details))
        details = repr(details)
    result_json = {'error': {'message': error, 
                 'details': details, 
                 'session_id': None}}
    if session_id:
        result_json['error']['session_id'] = session_id
    cherrypy.response.body = json.dumps(result_json, indent=2)
    api_logger.error('Unexpected error in handling:\nURL: %s\nBody: %s', cherrypy.request.request_line, getattr(cherrypy.request, 'json', {}))
    api_logger.exception('Exception handling %s', cherrypy.request.request_line)
    return


def hook_drop_garbage_args():
    """
    This is the hook to drop _=TS and __=TS for API requests from $.ajax
    """
    cherrypy.request.params.pop('_', None)
    cherrypy.request.params.pop('__', None)
    return


class FoundationApi(object):
    """
    This class is mounted at /foundation.
    """
    _cp_config = {'request.error_response': handle_500_error, 
       'hooks.before_handler': hook_drop_garbage_args}

    def __init__(self):
        self.node_hooks = {}
        self.global_hooks = set([])
        self.hook_lock = threading.Lock()

    @cherrypy.expose
    def index(self):
        return 'Nutanix Foundation API - for automation use only.'

    @cherrypy.expose
    def log(self, session_id=None, node_id=None, step=None, offset=None, level=logging.INFO):
        """
        The logging and callback API.
        
        Parameters:
          session_id: ID of the imaging session to which this log entry
              corresponds to.
          node_id: The foundation node id of the node that used the log URL.
          step: The step the node is reporting. This can be a simple string
                indicating a particular phase of the installation or
                one of the following special strings (without colon):
                      fatal: Installation failed.
                      info: log informational message.
                      error: log non-fatal error message.
          message: The human readable message that was the body of the http
                     request.
        
          eg.
            http://<ip>:<port>/foundation/log?node_id=<node_id>&
              step=<step>
          The body of the request contains the human readable message.
        """
        if not session_id:
            raise StandardError('Must specify session_id')
        if not node_id:
            raise StandardError('Must specify node_id')
        if not step:
            raise StandardError('Must specify step')
        log_level_mapping = dict(info=logging.INFO, error=logging.ERROR, fatal=logging.CRITICAL, warning=logging.WARNING, debug=logging.DEBUG)
        if cherrypy.request.body.length:
            payload = cherrypy.request.body.read().strip()
        else:
            payload = step
        gc = session_manager.get_global_config(session_id)
        gc._events.handle_event(node_id, step, payload)
        session_manager.set_session_id(session_id)
        if step not in ('info', 'error', 'warning', 'fatal'):
            for nc in gc.nodes:
                if nc.node_id == node_id:
                    nc.set_status_via_callback(step)
                    break

        log_name = 'foundation.session.%s.node_%s' % (session_id, node_id)
        logger = logging.getLogger(log_name)
        if step in log_level_mapping:
            logger.log(log_level_mapping[step], payload)
        else:
            logger.log(level, '%s: %s', step, payload)

    @cherrypy.expose
    def detect_local_hypervisor_type(self):
        """
        Detect the type of hypervisor for this CVM.
        """
        from cvm_utilities import detect_local_hypervisor_type
        try:
            hyp = detect_local_hypervisor_type()
        except:
            api_logger.exception('Exception in detect_local_hypervisor_type')
            message = 'Failed to detect local hypervisor type, please check api log for more information'
            raise StandardError(message)

        return hyp

    @cherrypy.expose
    def detect_workload(self):
        """
        We formerly stored some factory-installed data, like La Jolla, on data
        disks. We no longer support La Jolla, and in fact never sold it, so this is
        now a dummy.
        
        Output: JSON structure as follows
        If any payload detected, return
        {
         "/path/to/some/disk/workload.json" : {... content of the workload manifest ...}
        }.
        Else return empty {}.
        """
        return json.dumps({}, indent=2)

    @cherrypy.expose
    def discover_nodes(self):
        """
        Discover Nutanix nodes in the network. This requires IPv6 connectivity.
        """
        discovered_nodes = ipmi_config.discover_nodes()
        return json.dumps(discovered_nodes)

    @cherrypy.expose
    def discover_ucsm_nodes(self, ucsm_ip, ucsm_user, ucsm_password):
        """
        Discover UCS managed nodes connected to a given UCS manager.
        """
        discovered_nodes = remote_boot_ucsm.discover_ucsm_nodes(ucsm_ip, ucsm_user, ucsm_password)
        return json.dumps(discovered_nodes)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @save_post_params
    def configure_foundation_networking(self):
        """
        Provides network configuration support for foundation. This API currently
        supports configuring virtual interfaces when multihoming is selected.
        Functionalities like configuring vlans will later be added to this API.
        """
        config = cherrypy.request.json
        config_persistence.persist_config(config.copy())
        if 'use_foundation_ips' in config and config['use_foundation_ips']:
            virtual_interfaces.create_multihoming_interfaces(config)
        else:
            raise StandardError('API called with incorrect parameters')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @save_post_params
    def ipmi_config(self):
        """
        Configure IPMI IP on BMC of nodes.
        
        The server will return the same data structure it received with the per-node
        parameter ipmi_configure_successful set - True if configuration succeeded or
        False if it did not. ipmi_configure_now will be set to False for all nodes.
        If any node that the user wanted configured was not successful, the response
        will have a 500 code. The ipmi_config call will do  a ping test on the
        configured IPs if all the configuration succeeds. If the ping test for an
        interface fails, the call will set ipmi_configured to false. In the case of
        failure, ipmi_config will guarantee the existence of key "ipmi_message" in
        every node for which ipmi_configure_now was true when the method was called
        and ipmi_configured is now false, and that its value will be a
        human-readable string.
        
        """
        config = cherrypy.request.json
        config_persistence.persist_config(config.copy())
        config_keys = [
         'ucsm_ip', 'ipmi_netmask', 'ipmi_gateway',
         'foundation_ipmi_ip', 'foundation_hyp_ip',
         'hypervisor_netmask', 'foundation_cvm_ip', 'cvm_netmask']
        node_keys = ['ipmi_ip']
        invalid_addrs = []

        def sanitize(keys, json_obj):
            validation_error = False
            for key in keys:
                if json_obj.get(key, None):
                    try:
                        if key.endswith('mask'):
                            json_obj[key] = cv.validate_and_correct_netmask(json_obj[key])
                        else:
                            json_obj[key] = cv.validate_and_correct_ip(json_obj[key])
                    except StandardError as e:
                        validation_error = True
                        api_logger.error(str(e))
                        invalid_addrs.append(json_obj[key])

            return validation_error

        err = False
        err |= sanitize(config_keys, config)
        for block in config['blocks']:
            for node in block['nodes']:
                err |= sanitize(node_keys, node)

        if err:
            raise StandardError('Invalid ipmi network info: %s' % invalid_addrs)
        if 'use_foundation_ips' in config and config['use_foundation_ips']:
            warnings.warn('Using /ipmi_config to configure virtual interfaces for multihomingis deprecated. Please use /foundation_networking API formultihoming support.', DeprecationWarning)
            virtual_interfaces.create_multihoming_interfaces(config)
        nodes_to_configure = []
        for block in config['blocks']:
            for node in block['nodes']:
                if node.get('ipmi_mac'):
                    node['ipmi_mac'] = foundation_tools.normalize_mac(node['ipmi_mac'])
                if node['ipmi_configure_now']:
                    nodes_to_configure.append(node)

        details = {}
        results = foundation_tools.tmap(func=ipmi_config.configure_node, args_list=map(lambda node: (
         config, node), nodes_to_configure))
        for node, ipmi_configured in zip(nodes_to_configure, results):
            node['ipmi_configure_successful'] = ipmi_configured
            if ipmi_configured:
                if factory_mode.factory_mode():
                    api_logger.debug('FACTORY: Skip toggling ipmi_configure_now')
                else:
                    node['ipmi_configure_now'] = False
                node['ipmi_message'] = 'Configuring node to use IPMI IP %s succeeded' % node['ipmi_ip']
                api_logger.info('IPMI IP %s has been configured successfully via foundation', node['ipmi_ip'])
            else:
                node['ipmi_message'] = "Couldn't configure IPMI IP %s" % node['ipmi_ip']
                details[node['ipmi_ip']] = node['ipmi_message']

        failed_config = not all(results)
        if not failed_config:
            targets = map(lambda node: node['ipmi_ip'], nodes_to_configure)
            ping_results = ipmi_config.generic_ping_multiple(targets)
            for node, ping_result in zip(nodes_to_configure, ping_results):
                if not ping_result:
                    node['ipmi_configure_successful'] = False
                    node['ipmi_message'] = "Correctly configured IPMI IP %s, but the IP isn't pingable. Check that you have plugged in the IPMI or first 1G port." % node['ipmi_ip']
                    details[node['ipmi_ip']] = node['ipmi_message']

        config_persistence.persist_config(config.copy())
        if details:
            message = 'Foundation failed to configure IPMI IPs. Please check api.log for more details'
            raise StandardError(message, details)
        return json.dumps(config, indent=2)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @save_post_params
    def ping_multiple(self):
        """
        Ping multiple nodes concurrently.
        
        Input is a JSON list containing a set of IPv4 IP addresses. Example:
        ["10.1.61.95", "10.2.61.96", "10.1.60.237", "10.1.61.237"]
        
        Result is a JSON list containing a set of JSON lists containing
        an IP address and a boolean. Example:
        [['10.1.61.95', True], ['10.2.61.96', False], ['10.1.60.237', True],
         ['10.1.61.237', False]]
        
        The result list will be in the same order as the input list.
        
        """
        ips = cherrypy.request.json
        result = ipmi_config.generic_ping_multiple(ips)
        return json.dumps(result, indent=2)

    @cherrypy.expose
    def get_timezones(self):
        """
        Get list of timezones which can be passed in the /image_nodes call.
        Returns:
          List of strings, each element being a valid timezone.
        Raises:
          StandardError if Foundation is unable to read file.
        """
        TIMEZONE_RE = re.compile('[A-Z]{2}\t[-+\\d]+\t(\\S+)')
        tzs = []
        tz_map = folder_central.get_foundation_windows_timezone_map_path()
        if os.path.exists(TIMEZONE_INFO_FILE):
            with open(TIMEZONE_INFO_FILE) as (fd):
                for line in fd:
                    if line.startswith('#'):
                        continue
                    m = TIMEZONE_RE.match(line)
                    if m:
                        tzs.append(m.group(1))

        else:
            if os.path.exists(tz_map):
                tzs = foundation_tools.get_default_timezones().keys()
            else:
                api_logger.warn('Timezone file is missing, returning []')
        return json.dumps(sorted(tzs), indent=2)

    @cherrypy.expose
    def abort_session(self, session_id=None):
        """
        Abort a running session. This will mark the session as aborted so that
        user can start imaging the same nodes immediately. This API is available
        only in standalone foundation. The actual imaging process will run for
        some more time in the backend until it reaches a state where it can be
        stopped safely. Then it will report imaging_stopped=True in progress API.
        Trying to abort a session which is not active, will result in error.
        
        Args:
          session_id: Id of the session which needs to be aborted.
        
        Raises:
          StandardError if the api is called on CVM foundation or if the session
          id provided is invalid.
        """
        if not session_id:
            raise StandardError('Provide a session_id')
        if imaging_context.get_context() == imaging_context.FIELD_VM:
            raise StandardError('Aborting an imaging session is allowed only on standalone foundation')
        sm = session_manager.get_session_manager()
        session_ids = sm.get_all_session_ids()
        if session_id not in session_ids:
            raise StandardError("Invalid imaging session id '%s'" % session_id)
        api_logger.info("Received a request to abort imaging session with id '%s'" % session_id)
        session_manager.set_session_id(session_id)
        sm.abort_session(session_id)
        gc = session_manager.get_global_config(session_id)
        for node in gc.nodes:
            gc._events.handle_event(node.node_id, 'fatal', 'Aborted from API')

        foundation_tools.update_metadata({'session_aborted': True}, session_manager.get_session_id())

    @cherrypy.expose
    def get_progress_sessions(self):
        """
        Report imaging progress of all active, failed and succeeded sessions.
        This API can be used as an alternative to check whether any session
        is currently active in Foundation.
        
        Returns the progress output json for all sessions grouped under
        "active sessions", "succeeded_sessions" and "failed_sessions".
        """
        type_sid_map = session_manager.get_all_session_ids_by_category()
        global_progress = {}
        global_progress['active_sessions'] = {}
        global_progress['succeeded_sessions'] = {}
        global_progress['failed_sessions'] = {}
        for _type in ['active_sessions', 'succeeded_sessions', 'failed_sessions']:
            for sid in type_sid_map[_type]:
                global_progress[_type][sid] = ntm.get_progress(sid)

        cherrypy.response.headers['Content-Type'] = 'application/json'
        return json.dumps(global_progress, indent=2)

    @cherrypy.expose
    def progress(self, session_id=None):
        """
        Get progress of current session.
        """
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
                return json.dumps(result, indent=2)
            session_id = last_active_session_id
        else:
            if session_id not in session_ids:
                raise StandardError("Invalid session id '%s' provided" % session_id)
        result = ntm.get_progress(session_id)
        cherrypy.response.headers['Content-Type'] = 'application/json'
        return json.dumps(result, indent=2)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @save_post_params
    @fail_session_on_error
    def validate_network_configuration(self):
        """
        This call is used to check the IP configuration of Hypervisor,
        CVM and IPMI including:
          - Detecting IP conflicts
          - CVM-CVM connection
          - CVM-Hypervisor connection (optional)
        """
        config = cherrypy.request.json
        foundation_tools.update_metadata({'network_configuration': config}, session_manager.get_session_id())
        session_id = session_manager.get_new_session_id()
        config_persistence.persist_config(config)
        try:
            global_config = config_parser.parse_json_config_network_validation(config)
        except StandardError:
            api_logger.exception('Exception in parsing config')
            raise
        else:
            status, err_msg = session_manager.is_session_possible(global_config)
            if not status:
                raise StandardError(err_msg)
            try:
                network_validation.generate_validation_graph(global_config)
            except StandardError:
                api_logger.exception('Exception in generating graph')
                raise

        network_validation.do_validation_threaded(global_config)
        result = {'session_id': session_id}
        return json.dumps(result, indent=2)

    @cherrypy.expose
    def get_network_validation_result(self, session_id=None):
        warnings.warn('get_network_validation_result API is deprecated, please swtich to progress API for the result.', DeprecationWarning)
        session_id = self.validate_and_get_session_id(session_id)
        result = network_validation.get_result(session_id=session_id)
        return json.dumps(result)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @save_post_params
    @fail_session_on_error
    def boot_phoenix(self):
        """
        API to boot multiple nodes to phoenix asynchronously
        """
        json_config = cherrypy.request.json
        session_manager.get_new_session_id()
        json_config['blocks'] = [{'nodes': json_config.pop('nodes')}]
        global_config = config_parser.parse_boot_phoenix_config(json_config)
        try:
            installer.generate_imaging_graph(global_config, action=installer.Action.BOOT_PHOENIX)
        except StandardError:
            api_logger.exception('Exception in generating graph')
            raise

        installer.do_imaging_threaded(global_config)
        result = {'session_id': global_config._session_id}
        return json.dumps(result, indent=2)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @save_post_params
    @fail_session_on_error
    def image_nodes(self):
        """
        API to image multiple nodes and optionally create clusters.
        """
        json_config = cherrypy.request.json
        if factory_mode.factory_mode():
            api_logger.debug('Adapting config for factory')
            json_config = factory_mode.adapt_stage_2(json_config)
        session_id = session_manager.get_new_session_id()
        try:
            global_config = config_parser.parse_json_config_imaging(json_config)
        except StandardError:
            api_logger.exception('Exception in parsing config')
            raise
        else:
            status, err_msg = session_manager.is_session_possible(global_config)
            if not status:
                raise StandardError(err_msg)
            is_unittest = getattr(global_config, 'is_unittest', False)
            try:
                if not is_unittest:
                    cv.common_validations(global_config, quick=True)
            except StandardError:
                api_logger.exception('Exception in quick validation')
                raise
            else:
                try:
                    installer.generate_imaging_graph(global_config)
                except StandardError:
                    api_logger.exception('Exception in generating graph')
                    raise

                json_config['session_id'] = session_id
                config_persistence.persist_config(json_config)
                foundation_tools.update_metadata({'persisted_config': config_persistence.get_persisted_config()}, session_id)
                try:
                    user_agent = cherrypy.request.headers.get('User-Agent')
                    foundation_tools.update_metadata({'browser_user_agent': user_agent}, session_id)
                except (AttributeError, KeyError, cherrypy.CherryPyException):
                    api_logger.warning('Could not log user agent: %s' % traceback.format_exc())

            foundation_tools.update_metadata({'environ': dict(os.environ)}, session_id)
            foundation_tools.update_metadata({'platform': foundation_tools.platform_info()}, session_id)
            discovered_nodes = None
            try:
                discovered_nodes = ipmi_config.discover_nodes()
            except StandardError:
                api_logger.exception('Ignoring exception from discover_nodes()')

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
        result = {'session_id': session_id}
        return json.dumps(result, indent=2)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @save_post_params
    @fail_session_on_error
    def pre_check(self):
        """
        This call is to check all the parameters and configurations that will be
        used to call image_nodes.
        """
        api_logger.info('Precheck starting')
        json_config = cherrypy.request.json
        session_id = session_manager.get_new_session_id()
        config_persistence.persist_config(json_config)
        try:
            global_config = config_parser.parse_json_config_imaging(json_config)
            global_config.action = 'pre_check'
            cv.common_validations(global_config)
        except StandardError:
            api_logger.exception('Exception in validating config')
            raise

        status, err_msg = session_manager.is_session_possible(global_config, set_active=False)
        if not status:
            raise StandardError(err_msg)
        api_logger.info('Precheck completed successfully')
        session_config = session_manager.get_session_by_id(session_id)
        session_config.delete_session_files()
        session_config.set_archive_status(session_manager.SessionConfig.ARCH_DONE_FILES_DELETED)
        result = {'session_id': session_id}
        return json.dumps(result, indent=2)

    @cherrypy.expose
    def must_redirect(self):
        """
        Checks if a Foundation GUI monitoring imaging progress needs to redirect
        to another node because Foundation is about to reboot the node.
        """
        result = {}
        redirect_now, new_cvm_ip, new_cvm_ipv6 = imaging_step_handoff.get_redirect_status()
        result['redirect_now'] = redirect_now
        result['new_cvm_ipv4_ip'] = new_cvm_ip
        result['new_cvm_ipv6_link_local_ip'] = new_cvm_ipv6
        cherrypy.response.headers['Content-Type'] = 'application/json'
        return json.dumps(result, indent=2)

    @cherrypy.expose
    def get_factory_config(self):
        """
        This call is used to retrieve the parts of the image_nodes dict
        that we don't want to rely on factory users for.
        """
        config = factory_mode.get_config()
        cherrypy.response.headers['Content-Type'] = 'application/json'
        return json.dumps(config, indent=2)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @save_post_params
    def populate_factory_config(self):
        """
        This call fills in the remaining parts of the factory config template
        once we've gathered user input. The UI should use this after filling in
        the template from get_last_config, but before running IPMI configuration
        and imaging.
        """
        config = cherrypy.request.json
        if factory_mode.factory_mode():
            factory_mode.adapt(config)
        cherrypy.response.headers['Content-Type'] = 'application/json'
        return json.dumps(config, indent=2)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    def launch_virtual_console(self):
        """
        Launches the ipmi virtual console
        Args:
          ipmi_ip: IPMI IP address.
          ipmi_user: IPMI user name.
          ipmi_password: IPMI password.
        Returns:
          url to access the ipmi console.
        """
        node_config = cherrypy.request.json
        session_id = session_manager.IGNORED_SESSION_ID
        session_manager.set_session_id(session_id)
        url = virtual_console.launch(node_config)
        result = {'url': url}
        cherrypy.response.headers['Content-Type'] = 'application/json'
        return json.dumps(result, indent=2)

    @cherrypy.expose
    def get_last_config(self):
        """
        This call is used to populate the GUI with the previous imaging
        configuration on crash and to populate the GUI after imaging completes.
        """
        last_active_session_id = session_manager.get_last_active_session_id()
        config = config_persistence.get_persisted_config(session_id=last_active_session_id)
        cherrypy.response.headers['Content-Type'] = 'application/json'
        return json.dumps(config, indent=2)

    @cherrypy.expose
    def get_all_session_ids(self):
        """
        Gets session IDs of all imaging sessions.
        """
        sm = session_manager.get_session_manager()
        last_active_session_id = session_manager.get_last_active_session_id()
        result = {'last_active_session_id': str(last_active_session_id), 
           'session_ids': sm.get_all_session_ids()}
        return json.dumps(result, indent=2)

    def _get_log(self, path, offset):
        offset = int(offset)
        if not os.path.exists(path):
            return 'Log is empty'
        cherrypy.response.headers['Content-Type'] = 'text/plain'
        log_fh = open(path)
        log_fh.seek(offset)
        return log_fh

    def validate_and_get_session_id(self, session_id=None):
        """
        Validates a session id, if provided. If session id is not provided, it will
        return the session id of the last active session. This will be used when
        session-unaware GUI calls Foundation rest apis without providing a session
        id.
        Args:
          session_id: Id of the session which needs to be validated. If not
              provided, function will use the last active session id.
        
        Raises:
          StandardError if session id is not provided and there are no imaging
          sessions available.
          StandardError if the session id provided is invalid.
        
        Returns:
          Session id which the caller can use.
        """
        sm = session_manager.get_session_manager()
        session_ids = sm.get_all_session_ids()
        if not session_id:
            if not session_ids:
                raise StandardError('No imaging session found')
            last_active_session_id = session_manager.get_last_active_session_id()
            assert last_active_session_id is not None
            session_id = last_active_session_id
        else:
            if session_id not in session_ids:
                raise StandardError("Invalid session id '%s' provided" % session_id)
        return session_id

    @cherrypy.expose
    def node_log(self, hypervisor_ip=None, session_id=None):
        """
        Installation log for an individual node.
        
        Provide hypervisor_ip as a GET param.
        Can also get the logs corresponding to a particular session by
        providing a session id.
        """
        session_id = self.validate_and_get_session_id(session_id=session_id)
        config = session_manager.get_global_config(session_id)
        for node in config.nodes:
            if node.hypervisor_ip == hypervisor_ip:
                log_path = folder_central.get_node_log_path(node.node_id, session_id)
                return serve_file(log_path, content_type='text/plain')

        return ''

    @cherrypy.expose
    def cluster_log(self, cvm_ip=None, session_id=None):
        """
        Installation log for operations at cluster level.
        
        Provide CVM IP of any any cvm belonging to the cluster.
        Can also get the logs corresponding to a particular session by
        providing a session id.
        """
        session_id = self.validate_and_get_session_id(session_id=session_id)
        config = session_manager.get_global_config(session_id)
        for cluster in config.clusters:
            for node in cluster.cluster_members:
                if node.cvm_ip == cvm_ip:
                    log_path = folder_central.get_cluster_log_path(cluster.cluster_name, session_id)
                    return serve_file(log_path, content_type='text/plain')

        return ''

    @cherrypy.expose
    def service_log(self):
        """
        The logs of the Foundation service.
        """
        log_name = folder_central.get_service_log_path()
        return serve_file(log_name, content_type='text/plain')

    @cherrypy.expose
    def get_update_log(self):
        """
        The last log of the Foundation update.
        """
        log_name = update_manager.get_last_update_log_path()
        return serve_file(log_name, content_type='text/plain')

    def _list_and_delete_broken_links(self, folder):
        """
        Lists the directory and cleans any broken symlinks found.
        """
        files = []
        for fl in os.listdir(folder):
            if fl.startswith('.'):
                continue
            filepath = os.path.join(folder, fl)
            if not os.path.exists(filepath):
                try:
                    os.unlink(filepath)
                except Exception:
                    pass

                continue
            files.append(fl)

        return files

    @cherrypy.expose
    def enumerate_hypervisor_isos(self):
        """
        This call is used to list the available hypervisor ISOs.
        
        Result:
        {
          "esx": [ {"filename": <filename 1>}, ... ],
          "xen": [ {"filename": <filename 1>}, ... ],
          "kvm": [ {"filename": <filename 1>}, {"filename": <filename>}, ... ],
          "hyperv": [ {"filename": <filename 1>, "SKUs": [...]}, ... ]
        }
        
        Where
          1. "filename" is a user readable string identifying a hypervisor iso.
          2. "SKUs" is a list of Windows Server SKUs available in the given
             installation image. Each element is one of "free", "standard",
             "datacenter".
          3. This api returns "AHV bundled with AOS (version 4.6+)" for any
             AHV tarball bundled in AOS. Post this string as filename to ask
             the Foundation to use AHV from AOS.
        
        """

        def make_iso_objects(folder, hyp):
            iso_names = self._list_and_delete_broken_links(folder)
            kvm_dict = None
            hyp_filters = ['.iso']
            if hyp == 'kvm':
                hyp_filters.append('.tar.gz')
            iso_names = filter(lambda s: any(map(lambda f: s.lower().endswith(f), hyp_filters)), iso_names)
            hyp_list = []
            if hyp == 'kvm':
                nos_names = self._list_and_delete_broken_links(folder_central.get_nos_folder())
                nos_names = filter(lambda s: s.lower().endswith('.tar.gz') or s.lower().endswith('.tar'), nos_names)
                api_logger.debug('Available NOS packages: %s' % str(nos_names))
                if nos_names:
                    kvm_dict = {'filename': foundation_tools.NOS_AHV_BUNDLE_MAGIC, 
                       'supported': True}
            for iso in iso_names:
                if hyp == 'kvm':
                    supported = True
                else:
                    md5sum = iso_checksums.get_checksum(os.path.join(folder, iso))
                    if md5sum is None:
                        supported = True
                    else:
                        supported = iso_whitelist.md5_in_whitelist(md5sum)
                hyp_list.append({'filename': iso, 'supported': supported})

            if kvm_dict:
                hyp_list.append(kvm_dict)
            return hyp_list

        kvm_folder = folder_central.get_kvm_isos_folder()
        esx_folder = folder_central.get_esx_isos_folder()
        hyperv_folder = folder_central.get_hyperv_isos_folder()
        xen_folder = folder_central.get_xen_isos_folder()
        isos = {'kvm': make_iso_objects(kvm_folder, 'kvm'), 
           'esx': make_iso_objects(esx_folder, 'esx'), 
           'hyperv': make_iso_objects(hyperv_folder, 'hyperv'), 
           'xen': make_iso_objects(xen_folder, 'xen')}
        if features.is_enabled(features.LINUX_INSTALLATION):
            linux_folder = folder_central.get_linux_isos_folder()
            isos['linux'] = make_iso_objects(linux_folder, 'linux')
        return json.dumps(isos, indent=2)

    @cherrypy.expose
    def enumerate_nos_packages(self):
        """
        This call is used to list the available AOS packages.
        
        Result:
        [
          <aos tarball file name 1>,
          <aos tarball file name 2>,
          . . . more tarballs
        ]
        
        """
        folder = folder_central.get_nos_folder()
        entries = self._list_and_delete_broken_links(folder)
        names = filter(lambda s: s.lower().endswith('.tar.gz') or s.lower().endswith('.tar'), entries)
        return json.dumps(names, indent=2)

    @cherrypy.expose
    def reset_state(self):
        """
        Restores foundation to its original state, deleting persisted_config.json
        and clearing out last active session.
        
        Returns 500 if any session is currently active.
        """
        last_active_session_id = session_manager.get_last_active_session_id()
        if last_active_session_id:
            if ntm.is_running(session_id=last_active_session_id):
                raise StandardError('Cannot reset in middle of session')
        session_manager.clear_last_active_session_id()
        cfg_file = folder_central.get_persisted_config_path()
        if os.path.exists(cfg_file):
            try:
                os.remove(cfg_file)
            except OSError:
                raise StandardError("Could't remove persisted config file")

        factory_mode.load_config()

    @cherrypy.expose
    def log_archive_tar(self):
        """
        This call is used to download the log archive which is a tar file
        containing one or more tgz with archived logs.
        """
        tar_file = archive_log.collect_log_archives()
        return serve_file(tar_file, disposition='attachment', name='log_archive.tar')

    @cherrypy.expose
    def kvm_in_nos(self, nos_pkg_name=None):
        """
        Checks whether KVM RPM tarball is present in the provided NOS package and
        if yes, provides the KVM version as well.
        
        Args:
          nos_pkg_path: File name of NOS tarball in foundation/nos.
        
        Returns:
          dict{
              kvm_in_nos: True if KVM bits are present, False otherwise.
              kvm_version: Version of the KVM present in NOS. Valid only if
                  kvm_in_nos field is True.
          }
        
        Raises:
          Internal server error if the provided NOS tarball is not in
          tar or tar.gz format.
        """
        if not nos_pkg_name:
            raise StandardError('Provide a NOS package name')
        nos_pkg_path = os.path.join(folder_central.get_nos_folder(), nos_pkg_name)
        if not os.path.exists(nos_pkg_path):
            raise StandardError("Provided NOS package doesn't exist")
        if not nos_pkg_path.endswith('tar.gz') and not nos_pkg_path.endswith('.tar'):
            raise StandardError('Invalid NOS package format')
        try:
            tf = tarfile.open(nos_pkg_path)
        except:
            message = 'Unable to open NOS tarball. Ensure that the NOS tarball is a valid tar or tar.gz file'
            raise StandardError(message)

        kvm_in_nos = False
        kvm_version = None
        kvm_version = foundation_tools.get_kvm_version_in_nos(nos_tf=tf)
        if kvm_version:
            kvm_in_nos = True
        tf.close()
        return json.dumps({'kvm_in_nos': kvm_in_nos, 
           'kvm_version': kvm_version}, indent=2)

    @cherrypy.expose
    def is_update_available(self):
        """
        Checks if a foundation update is available.
        """
        update = update_manager.is_update_available()
        if update:
            output_dict = {'update': update, 'update_available': True}
            return json.dumps(output_dict, indent=2)
        output_dict = {'update_available': False}
        return json.dumps(output_dict, indent=2)

    @cherrypy.expose
    def last_update_status(self):
        """
        Returns the last Foundation update status.
        """
        update = update_manager.get_last_update_status()
        output_dict = {'status': update}
        return json.dumps(output_dict, indent=2)

    @cherrypy.expose
    def auto_update_foundation(self, tar_file=None):
        """
        If kicked off without tar_file param it fetches updates from the
        official foundation update url, which can be found in update_manager.
        If not you can specify the tarfile present in the default foundation_update
        folder, which is ~/foundation_updates.
        """
        if not tar_file:
            update = update_manager.is_update_available()
            if not update:
                raise StandardError('No foundation updates available!')
            target_tar = update_manager.download_update(update.get('download_url'), update.get('md5sum', None))
        else:
            target_tar = os.path.join(folder_central.get_update_foundation_dir(), tar_file)
        if target_tar:
            update_manager.kick_off_foundation_update(target_tar, delay=KICKOFF_DELAY)
        else:
            raise StandardError('Foundation auto-update failed. Could not download the update.')
        return

    @cherrypy.expose
    def restart_foundation(self):
        """
        Restarts foundation. No guarantees on return
        """
        update_manager.kick_off_restart_foundation()

    @cherrypy.expose
    def upload(self, installer_type=None, filename=None, cleanup=False):
        """
        This api is used to upload hypervisor or AOS images to foundation.
        Args:
          installer_type: One of "kvm", "esx", "hyperv", "xen", or "nos"
          filename: The filename to be uploaded(must end with iso when installer type is hyperv, esx)
        Return:
          {
            "name": name of file to be used in hypervisor_isos or
                    nos_package parameter.
            "md5sum": string md5 checksum of the file we read,
                      this will be null for nos.
            "in_whitelist":
               True if foundation allows you to image with this iso. Present only for hypervisor
               isos. Ignore this field if you specified installer_type=nos.
          }
        """
        installer_types = foundation_tools.HYP_TYPES + ['nos'] + ['update']
        if installer_type not in installer_types:
            raise StandardError('installer_type %s should be one of %s.' % (
             installer_type, installer_types))
        if installer_type == 'kvm' and not (filename.endswith('tar.gz') or filename.endswith('iso')):
            raise StandardError('AHV image must be in tar.gz or .iso format')
        if installer_type == 'nos':
            dest_dir = folder_central.get_nos_folder()
        else:
            if installer_type == 'update':
                dest_dir = folder_central.get_update_foundation_dir()
                if not os.path.exists(dest_dir):
                    os.makedirs(dest_dir)
            else:
                dest_dir = getattr(folder_central, 'get_%s_isos_folder' % installer_type)()
        dest_file = os.path.join(dest_dir, filename)
        try:
            with open(dest_file, 'wb') as (dest_fp):
                shutil.copyfileobj(cherrypy.request.body, dest_fp)
        except IOError as e:
            if os.path.exists(dest_file):
                os.unlink(dest_file)
            api_logger.exception('failed in upload %s', dest_file)
            raise StandardError('failed to upload file %s' % dest_file, e)

        filesize = os.path.getsize(dest_file)
        md5sum = None
        if installer_type in ('nos', ):
            in_whitelist = shared_functions.validate_aos_package(name=dest_file)
            if not in_whitelist:
                os.unlink(dest_file)
                raise StandardError("Failed to validate AOS package '%s'" % dest_file)
        else:
            if installer_type == 'update':
                in_whitelist = True
            else:
                in_whitelist = iso_whitelist.filesize_in_whitelist(str(filesize))
                if not in_whitelist:
                    md5sum = foundation_tools.get_md5sum(dest_file)
                    in_whitelist = iso_whitelist.md5_in_whitelist(md5sum)
                if cleanup:
                    for image in glob.glob(os.path.join(dest_dir, '*')):
                        if dest_file not in image:
                            os.unlink(image)

        output_dict = {'name': dest_file, 
           'md5sum': md5sum, 
           'in_whitelist': in_whitelist}
        iso_checksums.add_checksum(dest_file, md5sum)
        config_manager.CacheManager.reset()
        cherrypy.response.headers['Content-Type'] = 'application/json'
        return json.dumps(output_dict, indent=2)

    @cherrypy.expose
    def delete(self, installer_type, filename):
        """
        This call is used to delete the hypervisor or AOS images.
        """
        installer_types = foundation_tools.HYP_TYPES + ['nos']
        if installer_type not in installer_types:
            raise StandardError('installer_type %s should be one of %s.' % (
             installer_type, installer_types))
        if installer_type == 'nos':
            dest_dir = folder_central.get_nos_folder()
        else:
            dest_dir = getattr(folder_central, 'get_%s_isos_folder' % installer_type)()
        dest_file = os.path.join(dest_dir, filename)
        if not os.path.exists(dest_file):
            raise StandardError("File %s:%s doesn't exist" % (
             installer_type, filename))
        try:
            os.unlink(dest_file)
        except OSError:
            raise StandardError('Failed to delete %s:%s' % (
             installer_type, filename))

    @cherrypy.expose
    def get_foundation_tar(self, *args, **kw):
        """
        This call is used to get a tarball from currently running foundation.
        By default, no hypervisor iso is included and a minimal tarball is returned.
        
        Optional parameters:
        {kvm, esx, hyperv, xen, linux}=1: include this type of hypervisor iso
                                          in tarball
        nos=1: include nos in tarball
        
        """
        session_id = session_manager.IGNORED_SESSION_ID
        session_manager.set_session_id(session_id)
        dirs = foundation_tools.HYP_TYPES + ['nos']
        dirs_to_keep = filter(lambda x: x in cherrypy.request.params, dirs)
        tar_path = foundation_tools.get_foundation_tar(dirs_to_keep)
        url_path = FileServer.add_file(tar_path)
        raise cherrypy.HTTPRedirect('/' + url_path, 302)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @save_post_params
    def get_phoenix_iso(self):
        params = cherrypy.request.json
        iso = generate_phoenix.generate_phoenix_iso_http(params, logger=api_logger)
        url = FileServer.add_file(iso)
        raise cherrypy.HTTPRedirect('/' + url, 302)

    @cherrypy.expose
    def phoenix_network_status(self, phoenix_ip):
        """
        phoenix_ip : Phoenix ip
        This api is used to get the phoenix's network status for a given node.
        Returns True, if phoenix's network is stable, False, otherwise.
        """
        phoenix_ip = shared_functions.validate_and_correct_ip(phoenix_ip)
        result = {'stable': False}
        for retry in xrange(PHOENIX_RETRIES):
            try:
                _, _, ret = foundation_tools.ssh(None, phoenix_ip, [
                 'test', '-f', '/tmp/phoenix_stable'], throw_on_error=False, user='root', log_on_error=False)
            except:
                ret = 1
            else:
                if ret != 0:
                    return json.dumps(result, indent=2)
                time.sleep(0.5)

        result['stable'] = True
        return json.dumps(result, indent=2)

    @cherrypy.expose
    def version(self):
        """
        The version tag of the Foundation package.
        """
        cherrypy.response.headers['Content-Type'] = 'text/plain'
        return foundation_tools.get_current_foundation_version()

    @cherrypy.expose
    def get_all_features(self):
        """
        Get list of optional features and their status.
        """
        cherrypy.response.headers['Content-Type'] = 'application/json'
        return json.dumps(features.all(), indent=2)

    @cherrypy.tools.json_in()
    @cherrypy.expose
    @save_post_params
    def upload_local(self):
        """
        This creates a symlink in the installer_type directory in foundation to the
        given local path.
        """
        request = cherrypy.request.json
        installer_type = request.get('installer_type', None)
        localpath = request.get('localpath', None)
        cleanup = request.get('cleanup', True)
        installer_types = foundation_tools.HYP_TYPES + ['nos']
        if installer_type not in installer_types:
            raise StandardError('installer_type %s should be one of %s' % (
             installer_type, installer_types))
        if not localpath:
            raise StandardError('Need non-empty localpath')
        if not os.path.isfile(localpath):
            raise StandardError('Given localpath: %s is not a valid file' % localpath)
        if installer_type == 'nos':
            dest_dir = folder_central.get_nos_folder()
        else:
            dest_dir = getattr(folder_central, 'get_%s_isos_folder' % installer_type)()
        filename = os.path.split(localpath)[1]
        dest_file = os.path.join(dest_dir, filename)
        if localpath == dest_file:
            api_logger.info('/upload_local received request: %s' % json.dumps(request))
            api_logger.info('This file already exists. Will not proceed to create a symbolic link')
            return
        if cleanup:
            for image in glob.glob(os.path.join(dest_dir, '*')):
                os.unlink(image)

        try:
            os.symlink(localpath, dest_file)
        except OSError:
            message = 'Failed to create symbolic link: %s -> %s' % (dest_file, localpath)
            api_logger.exception(message)
            raise StandardError(message)

        return

    @cherrypy.expose
    def update_whitelist(self):
        global UNIT_TEST_MODE
        try:
            new_whitelist = json.load(cherrypy.request.body)
        except (AttributeError, ValueError):
            api_logger.exception('Exception in parsing whitelist json')
            raise StandardError('The whitelist you uploaded is not a valid json')

        iso_whitelist.update_whitelist(new_whitelist, update_on_disk=not UNIT_TEST_MODE)

    @cherrypy.expose
    def get_whitelist(self):
        """
        This api is used to download the is whitelist.
        """
        cherrypy.response.headers['Content-Type'] = 'application/json'
        return json.dumps(iso_whitelist.whitelist, indent=2)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @save_post_params
    @fail_session_on_error
    def reboot_to_phoenix(self):
        """
        Reboot a node into Phoenix livecd.
        
        This API comes with two flavors, CO or HCI.
        
        HCI:
          The input should contain the mandatory field: cvm_ip
          Optional fields are:
            cvm_vlan_id, cvm_gateway, cvm_netmask, hypervisor_ip
          If hypervisor_ip is specified, it is used first to reboot the host.
          If that fails, cvm_ip is used.
        
        CO:
          The input should have the following mandatory fields:
          (to reach out the AHV, and configure Phoenix network)
            compute_only=True
            hypervisor_ip, hypervisor_netmask
          Optional:
            cvm_vlan_id, hypervisor_gateway
        """
        network_config = cherrypy.request.json
        session_manager.get_new_session_id()
        global_config = config_parser.parse_reboot_config({'blocks': [{'nodes': [network_config]}]})
        assert len(global_config.nodes) == 1, 'This API takes exactly 1 node to reboot, the request is giving %s' % len(global_config.nodes)
        node_config = global_config.nodes[0]
        is_co = getattr(node_config, 'compute_only', False)
        if is_co:
            missing_fields = config_parser.required_fields(node_config, [
             'hypervisor_ip', 'hypervisor_netmask'])
            if missing_fields:
                raise StandardError('Missing mandatory fields: %s' % missing_fields)
        else:
            if not getattr(node_config, 'cvm_ip', None):
                raise StandardError('Missing mandatory fields: cvm_ip')
            if not hasattr(node_config, 'cvm_netmask'):
                cvm_ip = node_config.cvm_ip
                ret = call_genesis_method(cvm_ip, NodeManager.get_ip)
                if isinstance(ret, RpcError):
                    api_logger.warn('cvm_netmask is not provided and failed to fetch via NodeManager.get_ip RPC due to %s', ret)
                if ret[0] is None:
                    api_logger.warn("NodeManager.get_ip returned None for CVM's netmask and cvm_netmask not provided in config")
                else:
                    node_config.cvm_netmask = ret[0]['netmask']
            missing_fields = config_parser.required_fields(node_config, [
             'cvm_ip', 'cvm_netmask'])
            if missing_fields:
                raise StandardError('Missing mandatory fields: %s' % missing_fields)
            try:
                cvm_utilities.reboot_to_phoenix(node_config)
                session_manager.mark_session_success(global_config._session_id)
            except StandardError:
                api_logger.exception('Exception in reboot_to_phoenix')
                raise

        return json.dumps({'session_id': global_config._session_id}, indent=2)

    def _reboot_from_phoenix(self):
        network_config = cherrypy.request.json
        session_manager.get_new_session_id()
        global_config = config_parser.parse_reboot_config({'blocks': [{'nodes': [network_config]}]})
        assert len(global_config.nodes) == 1, 'This API takes exactly 1 node to reboot, the request is giving %s' % len(global_config.nodes)
        node_config = global_config.nodes[0]
        try:
            cvm_utilities.reboot_from_phoenix(node_config)
            session_manager.mark_session_success(global_config._session_id)
        except StandardError:
            api_logger.exception('Exception in reboot_to_cvm')
            raise

        return json.dumps({'session_id': global_config._session_id}, indent=2)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @save_post_params
    @fail_session_on_error
    def reboot_to_cvm(self):
        """
        Reboot the phoenix image back to the CVM.
        """
        return self._reboot_from_phoenix()

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @save_post_params
    @fail_session_on_error
    def reboot_from_phoenix(self):
        """
        Reboot back from the phoenix image.
        """
        return self._reboot_from_phoenix()

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @save_post_params
    def genesis_rpc(self, method, target, timeout=None):
        """
        A proxy to access genesis rpc via http api.
        
        Args:
          method: a genesis method, eg NodeManager.get_ip
          target: cvm IPv4 IP or IPv6 IP
          timeout: timeout for this operation, default is 6s from tinyrpc
        
        The the rpc args must be in a kwargs/json form in the POST body.
        """
        valid_classes = {'NodeManager': NodeManager, 
           'ClusterManager': ClusterManager}
        valid_methods = [
         'NodeManager.get_ip',
         'NodeManager.configure_ip',
         'NodeManager.get_backplane_ip',
         'NodeManager.configure_backplane_ip',
         'NodeManager.get_temporary_cvm_ip',
         'NodeManager.configure_temporary_cvm_ip',
         'NodeManager.get_current_cvm_backplane_vlan_tag',
         'ClusterManager.allocate_cluster_backplane_ips']
        if method not in valid_methods:
            raise StandardError('invalid method %s' % method)
        rpc_class, rpc_attr = method.split('.')
        rpc_method = getattr(valid_classes[rpc_class], rpc_attr)
        return self.genesis_rpc_helper(rpc_method, target, timeout, cherrypy.request.json)

    def genesis_rpc_helper(self, rpc_method, target, timeout=None, request_json=None):
        """
         Foundation Helper API that calls genesis RPC API, based on rpc_method
         being passed
        """
        if timeout:
            timeout = int(timeout)
        call_genesis_method_func = call_genesis_method
        try:
            socket.inet_aton(target)
            if target.count('.') == 3:
                call_genesis_method_func = call_genesis_method_over_tunnel
        except socket.error:
            pass
        else:
            api_logger.info('rpc method %s, target %s', rpc_method, target)
            api_logger.info('cherrypy %s', request_json)
            ret = call_genesis_method_func(cvm_ip=target, method=rpc_method, timeout_secs=timeout, **request_json)
            if not isinstance(ret, RpcError):
                return ret

        raise StandardError('rpc failed: %s' % str(ret.error))

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def list_nics(self, _=None, __=None):
        """
        List local networking.
        Get: Fetches the current networking configuration
        Post: sets up the foundation networking according to input config
        """
        return nic_module.list_nics()

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def primary_nic(self, nic=None):
        """
        Set primary nic for discovery.
        """
        if cherrypy.request.method == 'POST' and nic:
            nic_module.set_primary_nic(nic)
        return {'primary_nic': foundation_settings.get_settings()['ipv6_interface']}

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def foundation_networking(self):
        """
        API that functions as single Entry point in Foundation to configure
        networking.
          - GET displays the current networking configuration
          - POST sets networking to input JSON. POST also performs PUT operation
            when appropriate flags are passed in JSON
        """
        if cherrypy.request.method == 'POST':
            net_json_config = cherrypy.request.json
            configure_nics = []
            try:
                configure_nics = config_parser.parse_json_config_foundation_networking(net_json_config)
            except StandardError:
                api_logger.exception('Exception in parsing config')
                raise

            return nic_module.setup_foundation_networking(configure_nics)
        if cherrypy.request.method == 'DELETE':
            nic_module.delete_foundation_networking()
        return nic_module.extended_list_nics()

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def node_network_details(self):
        """
        API that fetches the configured CVM, Hypervisor & IPMI IP information on
        the node referenced by the IPv6 LinkLocal address passed in the json
        request.
        """
        json_config = cherrypy.request.json
        if 'nodes' not in json_config:
            raise StandardError('Not a valid json config, nodes need to be present')
        nodes = json_config['nodes']
        for node in nodes:
            if 'ipv6_address' not in node:
                raise StandardError('Missing ipv6_address in %s', node)

        rpc_method = getattr(NodeManager, 'get_ip')
        return configure_network_remote.node_network_details(self.genesis_rpc_helper, rpc_method, nodes)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def provision_network(self):
        """
        API that provisions CVM/Host ip based on json request. If request contains
        vlan id, it changes and put the nodes into a different subnet. Note that
        this operation should be attempted if standalone foundation is in trunk
        mode and can access the vlan network
        """
        json_config = cherrypy.request.json
        session_id = session_manager.get_new_session_id()
        json_config['blocks'] = [{'nodes': json_config.pop('nodes')}]
        global_config = config_parser.parse_genesis_rpc_config(json_config)
        rpc_method = getattr(NodeManager, 'configure_ip')
        get_ip_rpc_method = getattr(NodeManager, 'get_ip')
        configure_network_remote.provision_network(global_config, self.genesis_rpc_helper, rpc_method, get_ip_rpc_method, session_id)
        session_manager.mark_session_success(global_config._session_id)

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @save_post_params
    def is_iso_supported(self):
        """
        Checks if an iso is supported and returns iso metadata
        from iso_whitelist.json.
        Parameters:
          hypervisor_type: Hypervisor type.
          md5sum: md5sum of the hypervisor iso.
          nos_version: NOS version.
          node_model: Model name of the node.
        Returns:
          Dict consisting of following:
            supported: True if the iso is supported, False otherwise.
            metadata: Details from iso_whitelist.json.
            message: Reason why hypervisor iso is not supported.
        Raises:
          StandardError if required parameters are not given.
        """
        params = cherrypy.request.json
        req_params = ['hypervisor_type', 'md5sum', 'nos_version', 'node_model']
        req_params = filter(lambda p: not params.get(p), req_params)
        if req_params:
            raise StandardError('Provide values for the fields %s' % (', ').join(req_params))
        whitelist_check = pv.no_handoff_whitelist_check(params['md5sum'], params['hypervisor_type'].lower(), params['nos_version'])
        result = {}
        result['message'] = whitelist_check[1]
        result['metadata'] = whitelist_check[2]
        result['supported'] = whitelist_check[0]
        if result['metadata'] and result['metadata']['hypervisor'] != params['hypervisor_type'].lower():
            raise StandardError('Hypervisor with md5sum %s is of type %s but given as %s' % (
             params['md5sum'], result['metadata']['hypervisor'],
             params['hypervisor_type'].lower()))
        if not pv.does_hypervisor_support_nodemodel(params['md5sum'], params['node_model']):
            result['supported'] = False
            result['message'] = "%s iso with md5sum %s doesn't support hardware %s" % (
             params['hypervisor_type'], params['md5sum'],
             params['node_model'])
        cherrypy.response.headers['Content-Type'] = 'application/json'
        return json.dumps(result, indent=2)


class FileServer(object):
    """
    This the file registry for hosting static and dynamic files,
    including
     - /nos/xxx                      (static, in nos or out of tree)
       NOS package
     - /iso/xxx                      (static, in isos or out of tree)
       Hypervisor image
     - /phoenix/x86/livecd.tar       (static, in lib/phoenix)
       - Phoenix livecd.tar
     - /driver/esx/xxx               (static, in lib/driver)
       Drivers for esx, hyperv, xen
       anaconda for kvm
     - az_config.json for each node  (dynamic, in tmp)
    
    All files must be registered before usage, the
      `FileServer.make_url_and_hash` is the replacement for `make_url_and_hash`.
    """
    oot_mapping = {}
    static_mapping = {'nos': 'nos', 
       'isos': 'isos', 
       'lib/phoenix': 'phoenix', 
       'lib/driver': 'driver', 
       'tmp': 'tmp'}
    path_base = folder_central.get_foundation_dir()
    default_content_type = 'application/octet-stream'

    @staticmethod
    def add_file(path):
        """
        Add a file to registry
        
        Returns: the relative url for `path`
           eg. /path/to/foundation/nos/file -> nos/file
        """
        path = os.path.abspath(path)
        try:
            rel_path = os.path.relpath(path, FileServer.path_base)
            for prefix, uri in FileServer.static_mapping.items():
                if rel_path.startswith(prefix):
                    rel_rel_path = os.path.relpath(rel_path, prefix)
                    if portable.is_win():
                        rel_rel_path = rel_rel_path.replace('\\', '/')
                    return 'files/%s/%s' % (uri, rel_rel_path)

        except ValueError:
            rel_path = path

        key = os.path.basename(path)
        FileServer.oot_mapping[key] = path
        return 'files/other/%s' % key

    @staticmethod
    def make_url_and_hash(path, node_config, foundation_ip=None):
        """
        Add a file to the registry and returns the full url.
        
        This function expects the node_config has .foundation_ip attribute
        """
        if isinstance(path, dict):
            return path
        real_path = os.path.realpath(path)
        digest = config_manager.CacheManager.get(foundation_tools.get_md5sum, real_path)
        uri = FileServer.add_file(path)
        uri = urllib.quote(uri)
        return {'url': 'http://%s:%s/%s' % (foundation_ip or node_config.foundation_ip,
                 cherrypy.server.socket_port, uri), 
           'md5sum': digest}

    @staticmethod
    def reset():
        FileServer.oot_mapping = {}

    @cherrypy.expose
    def index(self):
        return 'Nutanix Foundation File Server - for automation use only.'

    @cherrypy.expose
    def other(self, key, *args, **kwargs):
        real_path = FileServer.oot_mapping.get(key, '/path/to/nowhere.txt')
        content_type = mimetypes.guess_type(key)[0] or FileServer.default_content_type
        return serve_file(real_path, content_type)

    nos = cherrypy.tools.staticdir.handler(section='/nos', dir=folder_central.get_nos_folder(), content_types={'': default_content_type})
    isos = cherrypy.tools.staticdir.handler(section='/isos', dir=folder_central._get_folder('isos'), content_types={'': default_content_type})
    phoenix = cherrypy.tools.staticdir.handler(section='/phoenix', dir=folder_central._get_folder('lib/phoenix'))
    driver = cherrypy.tools.staticdir.handler(section='/driver', dir=folder_central._get_folder('lib/driver'))
    tmp = cherrypy.tools.staticdir.handler(section='/tmp', dir=folder_central._get_folder('tmp'))


class GuiRoot(object):

    @cherrypy.expose
    def index(self):
        raise cherrypy.HTTPRedirect('index.html', 302)


class RedirectRoot(object):

    @cherrypy.expose
    def index(self):
        raise cherrypy.HTTPRedirect('/gui/index.html', 302)


def update_timeout():
    cherrypy.response.timeout = MAXIMUM_TRANSFER_TIMEOUT


def patch_mimetypes():
    """
    Patch mimetypes with some common binary formats missing from win/mac
    """
    mimetypes.add_type('application/x-iso9660-image', '.iso')
    mimetypes.add_type('application/x-tar-gz', '.tar.gz')
    mimetypes.add_type('application/octet-stream', '.vib')


def patch_cherrypy_report_channel_failure():
    """
    Patch ChannelFailures to print error message on binding failure
    """
    orig_handle_exception_fn = wspbus.ChannelFailures.handle_exception

    def handle_exception(self):
        print 'FATAL: Failed to start foundation on the following port'
        print sys.exc_info()[1]
        orig_handle_exception_fn(self)

    key = 'patch_cherrypy_report_channel_failure'
    if not cherrypy_patched.get(key, False):
        wspbus.ChannelFailures.handle_exception = handle_exception
        cherrypy_patched[key] = True


def load_docs():
    """
    Load documentation for REST APIs on /docs.
    """
    root_dir = folder_central.get_http_root_folder()
    docs_gui = folder_central.get_gui_for_docs()
    swagger_json_path = folder_central.get_swagger_json()
    try:
        foundation_ip = foundation_tools.get_interface_ip()
    except StandardError:
        foundation_ip = '127.0.0.1'

    if os.path.exists(swagger_json_path):
        swagger_json = json.load(open(swagger_json_path))
        swagger_json['info']['version'] = foundation_tools.get_current_foundation_version()
        swagger_json['host'] = '%s:%s' % (foundation_ip, HTTP_PORT)
        for path in swagger_json['paths']:
            api = getattr(FoundationApi, path[1:], None)
            desc = 'Not available, ask dev to write pydocs'
            if api and api.__doc__:
                desc = api.__doc__
            if 'get' in swagger_json['paths'][path]:
                swagger_json['paths'][path]['get']['description'] = desc
            elif 'post' in swagger_json['paths'][path]:
                swagger_json['paths'][path]['post']['description'] = desc

        json.dump(swagger_json, open(swagger_json_path, 'w'), indent=2)
        docs_root_config = {'/': {'tools.staticdir.root': root_dir, 
                 'tools.staticdir.on': True, 
                 'tools.staticdir.dir': docs_gui}}
        cherrypy.tree.mount(root=GuiRoot(), script_name='/docs', config=docs_root_config)
    else:
        api_logger.warning('Not loading documentation for REST APIs')
    return


def create(is_unit=False, http_port=HTTP_PORT):
    """
      Start HTTP server. Returns a reference to cherrypy's tree so that the
      caller can add additional apps.
    """
    global UNIT_TEST_MODE
    global foundation_api
    if is_unit:
        UNIT_TEST_MODE = True
    root_dir = folder_central.get_http_root_folder()
    cherrypy_error = folder_central.get_http_error_path()
    cherrypy_access = folder_central.get_http_access_path()
    patch_cherrypy_report_channel_failure()
    patch_mimetypes()
    cherrypy.config.update({'server.socket_host': '::', 
       'server.socket_port': http_port, 
       'server.thread_pool': HTTP_SERVER_THREADS, 
       'server.max_request_body_size': 8 * 1073741824, 
       'log.access_file': cherrypy_access, 
       'log.error_file': cherrypy_error, 
       'log.screen': False, 
       'environment': 'production', 
       'engine.autoreload.on': False})
    cherrypy.tree.mount(root=RedirectRoot(), script_name='/', config={})
    cherrypy.tree.mount(root=FileServer(), script_name='/files', config={})
    gui_root_config = {'/': {'tools.staticdir.root': root_dir, 
             'tools.staticdir.on': True, 
             'tools.staticdir.dir': folder_central.get_standalone_gui_path()}}
    cherrypy.tree.mount(root=GuiRoot(), script_name='/gui', config=gui_root_config)
    load_docs()
    foundation_api = FoundationApi()
    cherrypy.tree.mount(root=foundation_api, script_name='/foundation', config={'/': {'log.screen': False}})
    cherrypy.serving.request.hooks.attach('on_start_resource', update_timeout)
    cherrypy.log.access_log.propagate = False
    cherrypy.log.error_log.propagate = False
    return cherrypy.tree


def start():
    cherrypy.engine.start()


def block():
    cherrypy.engine.block()


def stop():
    cherrypy.engine.exit()