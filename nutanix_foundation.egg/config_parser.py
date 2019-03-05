# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/config_parser.py
# Compiled at: 2019-02-15 12:42:10
import errno, json, logging, os, socket, time, tokenize, uuid
from foundation import config_validator
from foundation import features
from foundation import foundation_aliases
from foundation import foundation_tools
from foundation import imaging_context
from foundation.session_manager import get_global_config, get_session_id, is_session_possible, mark_idle_session_failure
from foundation.config_manager import NodeConfig, ClusterConfig
from foundation.foundation_settings import settings as foundation_settings
from foundation.shared_functions import AUTOMATION_FRAMEWORK_KEY
logger = logging.getLogger('console')

def line_tokenizer(generator):
    tokens = []
    last_token = None
    indent = 0
    while True:
        if last_token:
            token_type, token, begin, end, line = last_token
            current_token = last_token
            last_token = None
        else:
            current_token = generator.next()
            token_type, token, begin, end, line = current_token
        if token_type == tokenize.COMMENT:
            pass
        elif token_type == tokenize.NL or token_type == tokenize.NEWLINE:
            if len(tokens):
                yield (
                 indent, tokens)
            tokens = []
        elif token_type == tokenize.STRING:
            tokens.append(eval(token))
        elif token_type == tokenize.OP:
            if token == '-':
                tokens[(-1)] += token
            else:
                tokens.append(token)
        elif token_type == tokenize.ENDMARKER:
            if len(tokens):
                yield (
                 indent, tokens)
            raise StopIteration()
        elif token_type == tokenize.NUMBER or token_type == tokenize.NAME:
            text = token
            while True:
                current_token = generator.next()
                token_type, token, begin, end, line = current_token
                if token_type == tokenize.NUMBER or token_type == tokenize.NAME or token_type == tokenize.OP and token != '=':
                    text += token
                    continue
                else:
                    break

            tokens.append(text)
            last_token = current_token
        elif token_type == tokenize.INDENT:
            indent += 1
        elif token_type == tokenize.DEDENT:
            indent -= 1
        else:
            raise StandardError('Unrecognized token %s at %s' % (token, begin))

    return


def process_params(config, text):
    parameters = text.split()
    for param in parameters:
        p = param.find('=')
        if p < 0:
            raise StandardError('Badly formatted node parameter %s' % param)
        key = param[:p]
        value = param[p + 1:]
        setattr(config, key, value)


def _parse_and_split_hypervisors(global_config):
    """
    Splits the hypervisor_iso dict in the global_config into two dicts:
      1) hypervisor_iso with entries [hypervisor type]: [iso name]
      2) hypervisor_checksum with entries [hypervisor type]: [checksum]
    Also sets the value of incoming_hypervisor_iso - needed for phoenix
    Defaults to empty dict {}
    Accepts both old and new dict entry formats:
      old) [hypervisor type]: [iso name]
      new) [hypervisor type]: {
             "filename": [iso name]
             "checksum": [checksum]
           }
    Returns:
      None - patches global_config
    """
    hypervisor_iso = {}
    hypervisor_checksum = {}
    global_config.hypervisor_iso = getattr(global_config, 'hypervisor_iso', {})
    if global_config.hypervisor_iso is None:
        global_config.hypervisor_iso = {}
    for hyp, hyp_obj in global_config.hypervisor_iso.items():
        if isinstance(hyp_obj, basestring):
            hypervisor_iso[hyp] = hyp_obj
            hypervisor_checksum[hyp] = None
        else:
            hypervisor_iso[hyp] = hyp_obj['filename']
            hypervisor_checksum[hyp] = hyp_obj['checksum']

    global_config.hypervisor_iso = hypervisor_iso
    global_config.incoming_hypervisor_iso = hypervisor_iso
    global_config.hypervisor_checksum = hypervisor_checksum
    return


def _parse_json_config(json_config):
    """
    Convert json config to config objects.
    
    Returns:
      object of class GlobalConfig
    """
    session_id = get_session_id()
    global_config = get_global_config(session_id)
    for key, value in json_config.items():
        if key not in ('clusters', 'blocks', 'tests'):
            setattr(global_config, key, value)

    if 'tests' in json_config:
        for key, value in json_config['tests'].items():
            setattr(global_config, key, value)

    _parse_and_split_hypervisors(global_config)
    clusters_jsons = json_config.get('clusters', [])
    cvm_ip_to_cluster_map = {}
    for cluster_json in clusters_jsons:
        cluster = ClusterConfig(parent=global_config)
        for key, value in cluster_json.items():
            if key not in ('cluster_members', ):
                setattr(cluster, key, value)
            if key == 'backplane_vlan':
                if not value:
                    setattr(cluster, key, 0)
                else:
                    try:
                        value = int(value)
                        setattr(cluster, key, value)
                    except ValueError:
                        raise StandardError('backplane_vlan must be an int, given value: %s' % value)

                    if value < 0 or value > 4095:
                        raise StandardError('backplane_vlan must be between 0 and 4095, given value: %s' % value)
            for cvm_ip in cluster_json['cluster_members']:
                cvm_ip_to_cluster_map[cvm_ip] = cluster

    blocks = json_config['blocks']
    for block in blocks:
        nodes = block['nodes']
        for node in nodes:
            if 'cvm_ip' in node and node['cvm_ip'] in cvm_ip_to_cluster_map:
                node_config = NodeConfig(parent=cvm_ip_to_cluster_map[node['cvm_ip']])
            else:
                node_config = NodeConfig(parent=global_config)
            for key, value in node.items():
                setattr(node_config, key, value)

            for key, value in block.items():
                if key != 'nodes':
                    setattr(node_config, key, value)

    return global_config


def _parse_cvm_vlan_id(node_config):
    """
    Parse cvm_vlan_id from current_network_interface and current_cvm_vlan_tag.
    
    Infer vlan tag from current_network_interface.
    If current_network_interface is a virtual interface then ignore
    current_cvm_vlan_tag but if interface is eth0 then use tag.
    """
    cvm_vlan_id = None
    intf = getattr(node_config, 'current_network_interface', '')
    if not intf:
        intf = ''
    parts = intf.split('.')
    if len(parts) > 1:
        cvm_vlan_id = parts[1]
    else:
        cvm_vlan_id = getattr(node_config, 'current_cvm_vlan_tag', None)
    return cvm_vlan_id


def _parse_json_config_network_validation(json_config):
    global_config = _parse_json_config(json_config)
    cluster_configs = global_config.clusters
    node_configs = global_config.nodes
    global_config.image_now = True
    global_config.enable_ns = False
    global_config.process_backplane_only = False
    global_config.nv_recover_on_fail = False
    for node_config in node_configs:
        foundation_aliases.fix_aliases(node_config)
        node_config.cvm_vlan_id = getattr(node_config, 'cvm_vlan_id', None)
        if node_config.cvm_vlan_id is None:
            node_config.cvm_vlan_id = _parse_cvm_vlan_id(node_config)
        node_config.ip_changed = False

    cvms_in_some_cluster = set([])
    for cluster in cluster_configs:
        cluster.enable_ns = getattr(cluster, 'enable_ns', False)
        cluster.process_backplane_only = getattr(cluster, 'process_backplane_only', False)
        for node in cluster.cluster_members:
            if node.cvm_ip in cvms_in_some_cluster:
                raise StandardError('CVM IP %s is in two clusters. CVMs may belong to only one cluster' % node.cvm_ip)
            cvms_in_some_cluster.add(node.cvm_ip)

    for node_config in node_configs:
        req_params = [
         'hypervisor_ip', 'hypervisor_netmask', 'hypervisor_gateway']
        if not getattr(node_config, 'compute_only', False):
            req_params.extend(['cvm_ip', 'cvm_netmask', 'cvm_gateway'])
        if not (node_config.enable_ns and node_config.process_backplane_only):
            req_params.extend(['ipv6_address'])
        for name in req_params:
            if not hasattr(node_config, name):
                raise StandardError('Missing required parameter: %s' % name)

    return global_config


def _set_foundation_details(global_config):
    phoenix_ip = global_config.nodes[0].phoenix_ip
    try:
        global_config.foundation_ip = foundation_tools.get_my_ip(phoenix_ip)
    except socket.error as value:
        error_code = value[0]
        if error_code == errno.ENETUNREACH:
            context = imaging_context.get_context()
            if context == imaging_context.FIELD_VM:
                raise StandardError('Interface IP needs to be in the CVM subnet. Use the network configuration view to set up the interface.')
            elif hasattr(global_config.nodes[0], 'ipmi_mac'):
                raise StandardError("Foundation IP or gateway IP not set. Try running the 'set_foundation_ip_address' script on the desktop.")
            else:
                raise StandardError("Foundation IP not set. Try running the 'set_foundation_ip_address' script on the desktop.")

    global_config.foundation_port = foundation_settings['http_port']


def _parse_json_config_imaging(json_config):
    """
    Parse json config for imaging.
    
    Returns:
      global_config
    """
    if features.is_enabled(features.FOUNDATION_CENTRAL) and json_config.get('fc_workflow', False):
        global_config = get_global_config()
    else:
        global_config = _parse_json_config(json_config)
    cluster_configs = global_config.clusters
    global_config.hypervisor_password = 'nutanix/4u'
    global_config.kvm_from_nos = False
    if not getattr(global_config, 'linux_kickstart', None):
        global_config.linux_kickstart = None
    global_default = []
    for item in global_default:
        if len(item) == 2:
            config_key, value = item
            json_key = config_key
        else:
            json_key, config_key, value = item
        setattr(global_config, config_key, json_config.get(json_key, value))

    global_config.cluster_destroy_now = False
    global_config.redundancy_factor = 2
    global_config.cluster_name = 'cluster'
    global_config.cluster_init_now = False
    _set_foundation_details(global_config)
    global_config.kvm_rpm = ''
    for node_config in global_config.nodes:
        if not getattr(node_config, 'block_id', None):
            node_config.block_id = time.strftime('%y') + 'NXSW' + str(uuid.uuid4()).upper().replace('-', '')[:6]
        if not hasattr(node_config, 'ucsm_managed_mode'):
            node_config.ucsm_managed_mode = False
        if node_config.image_now:
            node_config.image_successful = False
        if getattr(node_config, 'compute_only', False):
            node_config.svm_install_type = None
        else:
            node_config.svm_install_type = getattr(node_config, 'svm_install_type', 'clean')
        node_config.hyp_type = node_config.hypervisor
        node_config.image_delay = getattr(node_config, 'image_delay', 0)
        node_config.current_network_interface = getattr(node_config, 'current_network_interface', 'eth0')
        node_config.cvm_vlan_id = _parse_cvm_vlan_id(node_config)
        if getattr(node_config, 'ipmi_mac', None):
            node_config.ipmi_mac = foundation_tools.normalize_mac(node_config.ipmi_mac)
        foundation_aliases.fix_aliases(node_config)
        if not getattr(node_config, 'hypervisor_iso', None):
            node_config.hyp_iso = {}

    cluster_default_values = [('hypervisor_ntp_servers', None),
     ('cvm_ntp_servers', None),
     ('cvm_dns_servers', None)]
    for cluster in global_config.clusters:
        for key, value in cluster_default_values:
            if not hasattr(cluster, key):
                setattr(cluster, key, value)

    global_config.do_cluster_init = any([ cluster.cluster_init_now for cluster in cluster_configs ])
    global_config.do_cluster_destroy = any([ cluster.cluster_destroy_now for cluster in cluster_configs ])
    automation = getattr(global_config, AUTOMATION_FRAMEWORK_KEY, {})
    if automation:
        if getattr(global_config, 'nos_version', None):
            global_config.nos_package = foundation_tools.create_fake_nos_tarball(suffix=global_config._session_id, version=global_config.nos_version)
            global_config.fake_nos_package = global_config.nos_package
        if automation.get('svm_installer_url', None):
            if not (automation['svm_installer_url'].endswith('.tar') or automation['svm_installer_url'].endswith('.tar.gz')):
                raise StandardError('NOS package extension should either be .tar or .tar.gz')
    return global_config


class ConfigParserBase(object):
    """
    Base class for config parsing and validations.
    """

    def get_parse_config(self, session_id=None):
        self.session_id = session_id
        self._pre_parse_validation()
        self.global_config = self.parse()
        self._post_parse_validation()
        return self.global_config

    def parse(self):
        """
        The parsing function
        
        Returns:
          a GlobalConfig object
        """
        raise NotImplementedError

    def pre_parse_validation(self):
        """ Override to provide pre-parsing validation """
        pass

    def _pre_parse_validation(self):
        self.pre_parse_validation()

    def post_parse_validation(self):
        """ Override to provide post-parsing validation """
        pass

    def _post_parse_validation(self):
        global_config = self.global_config
        self.post_parse_validation()
        if hasattr(global_config, 'clusters'):
            for cluster in global_config.clusters:
                cluster.cluster_init_now = getattr(cluster, 'cluster_init_now', False)
                cluster.single_node_cluster = getattr(cluster, 'single_node_cluster', False)
                cluster.setup_replication = getattr(cluster, 'setup_replication', False)
                cluster.enable_ns = getattr(cluster, 'enable_ns', False)
                cluster_name = getattr(cluster, 'cluster_name', 'NTNX')
                try:
                    cluster_name.decode('ascii')
                except UnicodeError:
                    cluster.cluster_name_unicode = cluster_name
                    cluster.cluster_name = 'NTNX'
                    logger.debug('Using unicode in cluster name')

        hyp_ips = []
        cvm_ips = []
        UNSUPPORTED_NETWORK = '192.168.5.'
        for node in getattr(global_config, 'nodes', []):
            cvm_ip = getattr(node, 'cvm_ip', None)
            hyp_ip = getattr(node, 'hypervisor_ip', None)
            ipmi_ip = getattr(node, 'ipmi_ip', None)
            if cvm_ip and cvm_ip.startswith(UNSUPPORTED_NETWORK):
                raise StandardError('CVM IP (%s) belongs to unsupported network (%s)' % (
                 cvm_ip, UNSUPPORTED_NETWORK))
            if hyp_ip and hyp_ip.startswith(UNSUPPORTED_NETWORK):
                raise StandardError('Hypervisor IP (%s) belongs to unsupported network (%s)' % (
                 hyp_ip, UNSUPPORTED_NETWORK))
            if ipmi_ip and ipmi_ip.startswith(UNSUPPORTED_NETWORK):
                raise StandardError('IPMI IP (%s) belongs to unsupported network (%s)' % (
                 ipmi_ip, UNSUPPORTED_NETWORK))
            if cvm_ip in cvm_ips:
                raise StandardError('CVM IP %s specified for multiple nodes' % cvm_ip)
            if hyp_ip in hyp_ips:
                raise StandardError('Hypervisor IP %s specified for multiple nodes' % hyp_ip)
            if cvm_ip in hyp_ips or hyp_ip in cvm_ips:
                ip = cvm_ip if cvm_ip in hyp_ips else hyp_ip
                raise StandardError('IP %s specified as CVM IP for one node and as Hypervisor IP for another node. Please check your config' % ip)
            if cvm_ip:
                cvm_ips.append(cvm_ip)
            if hyp_ip:
                hyp_ips.append(hyp_ip)

        return


class ImagingJsonConfigParser(ConfigParserBase):

    def __init__(self, json_config):
        self.json_config = json_config

    def pre_parse_validation(self):
        config_validator.imaging_json_validation(self.json_config)

    def parse(self):
        return _parse_json_config_imaging(self.json_config)

    def post_parse_validation(self):
        global_config = self.global_config
        nodes = global_config.nodes
        for node in nodes:
            if node.hyp_type == 'linux':
                if not getattr(node, 'cvm_ip', None) and node.hyp_type == 'linux':
                    node.cvm_ip = node.hypervisor_ip
                    node.cvm_netmask = node.hypervisor_netmask
                    node.cvm_gateway = node.hypervisor_gateway

        need_handoff = False
        foundation_node = None
        first_node = None
        for node in nodes:
            if not hasattr(node, 'cvm_ip'):
                continue
            if node.image_now and node.cvm_ip == global_config.foundation_ip:
                need_handoff = True
                foundation_node = node

        if need_handoff:
            for node in nodes:
                if not hasattr(node, 'cvm_ip'):
                    continue
                if node.image_now and node is not foundation_node:
                    first_node = node

            if first_node:
                from foundation import imaging_step_handoff
                imaging_step_handoff.set_redirect_status(ready=False, cvm_ip=first_node.cvm_ip, cvm_ipv6=getattr(first_node, 'ipv6_address', ''))
            else:
                raise StandardError('Foundation at %s is going to image itself, but no extra node available.' % foundation_node.cvm_ip)
        global_config.need_handoff = need_handoff
        global_config.first_node_to_image = first_node
        return


class NetworkJsonConfigParser(ConfigParserBase):

    def __init__(self, json_config):
        self.json_config = json_config

    def parse(self):
        return _parse_json_config_network_validation(self.json_config)

    def post_parse_validation(self):
        global_config = self.global_config
        config_validator.validate_hypervisor_hostname_pattern(global_config)
        config_validator.validate_hostnames_are_not_duplicate(global_config)
        config_validator.check_min_segmentation_version(global_config)
        config_validator.validate_and_correct_network_addresses(global_config)


class CliConfigParser(ConfigParserBase):

    def __init__(self, config_fn, options):
        self.config_fn = config_fn
        self.options = options

    def parse(self):
        options = self.options
        global_config = get_global_config(self.session_id)
        node_configs = []
        cluster_config = None
        all_in_one_cluster = False
        global_config.image_now = True
        global_config.cvm_dns_servers = options.cvm_dns_servers
        global_config.cvm_ntp_servers = options.cvm_ntp_servers
        global_config.hypervisor_ntp_servers = options.hypervisor_ntp_servers
        if options.cluster_name:
            cluster_config = ClusterConfig(parent=global_config)
            cluster_config.cluster_init_now = True
            cluster_config.cluster_name = options.cluster_name
            all_in_one_cluster = True
        if options.cluster_destroy:
            if not cluster_config:
                cluster_config = ClusterConfig(parent=global_config)
            cluster_config.cluster_name = 'cluster_to_be_destroyed'
            all_in_one_cluster = True
            cluster_config.cluster_destroy_now = options.cluster_destroy
        if cluster_config:
            cluster_config.cluster_external_ip = options.cluster_external_ip
            cluster_config.redundancy_factor = options.redundancy_factor
            if getattr(options, 'enable_ns', False):
                cluster_config.enable_ns = True
                cluster_config.backplane_subnet = options.backplane_subnet
                cluster_config.backplane_netmask = options.backplane_netmask
                cluster_config.backplane_vlan = options.backplane_vlan
        last_node = None
        generator = line_tokenizer(tokenize.generate_tokens(open(self.config_fn).readline))

        def is_json_dict(value):
            try:
                result = json.loads(value)
                if isinstance(result, (dict, list)):
                    return True
                raise TypeError('Non-dict object is ignored')
            except (ValueError, TypeError):
                return False

        for indent, tokens in generator:
            if len(tokens) == 1:
                if all_in_one_cluster:
                    parent = cluster_config
                    node = NodeConfig(parent=parent)
                else:
                    node = NodeConfig(parent=global_config)
                last_node = node
                node.ipmi_ip, = tokens
                node_configs.append(node)
            elif len(tokens) == 3:
                key = tokens[0]
                value = tokens[2]
                if tokens[1] != '=':
                    raise StandardError("Unrecognized token: '%s'" % tokens[1])
                if value in ('False', 'false'):
                    value = False
                else:
                    if value in ('True', 'true'):
                        value = True
                    else:
                        if is_json_dict(value):
                            value = json.loads(value)
                if indent:
                    setattr(last_node, key, value)
                else:
                    setattr(global_config, key, value)

        for node in node_configs:
            node.hypervisor = node.hyp_type
            if hasattr(node, 'svm_ip'):
                node.cvm_ip = node.svm_ip
                node.cvm_gateway = node.svm_default_gw
                node.cvm_netmask = node.svm_subnet_mask
            if hasattr(node, 'ucsm_managed_mode') and node.ucsm_managed_mode.lower() == 'true':
                node.ucsm_managed_mode = True
            else:
                node.ucsm_managed_mode = False
            if getattr(node, 'compute_only', False):
                node.svm_install_type = None
            else:
                svm_install_type = getattr(node, 'svm_install_type', 'clean')
                node.svm_install_type = svm_install_type

        global_config.foundation_ip = foundation_tools.get_my_ip('8.8.8.8')
        if options.nos_package:
            nos_package_path = os.path.expanduser(options.nos_package)
            nos_package_path = os.path.abspath(nos_package_path)
            global_config.incoming_nos_package = nos_package_path
            global_config.nos_package = global_config.incoming_nos_package
        global_config.hypervisor_iso = {}
        for hyp in ['esx', 'kvm', 'hyperv', 'xen']:
            hyp_iso = getattr(options, '%s_iso' % hyp, None)
            if hyp_iso:
                hyp_iso_path = os.path.expanduser(hyp_iso)
                hyp_iso_path = os.path.abspath(hyp_iso_path)
                global_config.hypervisor_iso[hyp] = hyp_iso_path

        _parse_and_split_hypervisors(global_config)
        global_config.hyp_iso = global_config.hypervisor_iso
        if options.cluster_destroy:
            logger.warn('Foundation will destroy the cluster')
        global_config.run_ncc = options.run_ncc or any((getattr(c, 'run_ncc', False) for c in node_configs))
        global_config.run_syscheck = options.run_syscheck or any((getattr(c, 'run_syscheck', False) for c in node_configs))
        some_ip = getattr(node_configs[0], 'phoenix_ip', '8.8.8.8')
        global_config.foundation_ip = foundation_tools.get_my_ip(some_ip)
        global_config.foundation_port = foundation_settings['http_port']
        global_config.kvm_from_nos = False
        global_config.node_position = 'A'
        return global_config

    def pre_parse_validation(self):
        path = self.config_fn
        options = self.options
        if not os.path.isfile(path):
            raise StandardError('Config file %s not found' % path)
        for option in ['esx_iso', 'kvm_iso', 'hyperv_iso', 'nos_package']:
            fn = getattr(options, option, None)
            if option == 'kvm_iso':
                if fn and foundation_tools.NOS_AHV_BUNDLE_MAGIC in fn:
                    logger.debug('Using KVM from NOS bundle')
                    setattr(options, option, None)
                    continue
            if fn:
                fn = os.path.expanduser(fn)
                fn = os.path.abspath(fn)
                if not os.path.isfile(fn):
                    raise StandardError("Couldn't find file %s" % fn)

        return

    def post_parse_validation(self):
        pass

    @staticmethod
    def resolve_hostname(global_config):
        for node in global_config.nodes:
            for attr in ['ipmi', 'hypervisor', 'cvm']:
                attr = attr + '_ip'
                if hasattr(node, attr):
                    ip = socket.gethostbyname(getattr(node, attr))
                    setattr(node, attr, ip)


def parse_cli_config(path, options):
    """
    Returns global_config
    """
    parser = CliConfigParser(path, options)
    global_config = parser.get_parse_config()
    CliConfigParser.resolve_hostname(global_config)
    return global_config


def parse_json_config_imaging(json_config):
    """
    Parse and validate json config for imaging.
    
    Returns:
      global_config
    """
    parser = ImagingJsonConfigParser(json_config)
    result = parser.get_parse_config()
    return result


def parse_json_config_network_validation(json_config):
    """
    Parse and validate json config for network validation.
    
    Returns:
      global_config
    """
    parser = NetworkJsonConfigParser(json_config)
    return parser.get_parse_config()


def parse_json_config_foundation_networking(json_config):
    """
    Parse and validate json config for configuring foundation networking
    
    Args:
      json_config: Input json in the following format
    Returns:
      list of to be configured nics after validation. Example below
      [
        {
          "interface_index" : "2",
          "config" : [
          {
            "netmask" : "255.255.252.0",
            "vlan" : "2146",
            "ipv4" :  "10.5.213.254",
            "delete" : false
          },
          {
            "netmask" : "255.255.252.0",
            "vlan" : "100",
            "ipv4" : "10.5.213.250",
            "delete" : true
          }
        }
      ]
    Raises:
      StandardError on missing keys from json_config
    """
    configure_nics = []
    validate_keys = [
     'nics', 'default_gateway']
    validate_nic_config_keys = ['ipv4_address', 'vlan', 'netmask']
    validate_nic_keys = ['interface_index', 'config']
    missing_keys = []
    for key in validate_keys:
        if key not in json_config:
            missing_keys.append(key)

    nics = json_config['nics']
    for nic in nics:
        for key in validate_nic_keys:
            if key not in nic:
                missing_keys.append(key)

        nics_config = nic['config']
        for key in validate_nic_config_keys:
            for config in nics_config:
                if key not in config:
                    missing_keys.append(key)

        if missing_keys:
            raise StandardError('Missing keys %s in json_config' % missing_keys)
        configure_nics.append(nic)

    return configure_nics


def parse_reboot_config(network_config):
    session_id = get_session_id()
    global_config = _parse_json_config(network_config)
    status, msg = is_session_possible(global_config)
    if not status:
        mark_idle_session_failure(session_id)
        raise StandardError(msg + '. Wait for the current imaging session to complete')
    global_config.action = 'auxiliary_functions_running'
    return global_config


def parse_boot_phoenix_config(json_config):
    global_config = parse_reboot_config(json_config)
    _set_foundation_details(global_config)
    global_config.image_now = True
    return global_config


def required_fields(node_config, fields):
    missing_fields = []
    for field in fields:
        if getattr(node_config, field, None) is None:
            missing_fields.append(field)

    return missing_fields


def parse_genesis_rpc_config(json_config):
    session_id = get_session_id()
    global_config = parse_json_config_network_validation(json_config)
    status, msg = is_session_possible(global_config)
    if not status:
        mark_idle_session_failure(session_id)
        raise StandardError(msg + '. Wait for the current imaging session to complete')
    return global_config