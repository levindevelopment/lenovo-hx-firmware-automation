# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/config_validator.py
# Compiled at: 2019-02-15 12:42:10
import collections, dns.resolver, logging, os, re, socket
from distutils.version import LooseVersion
from urlparse import urlparse
from smb import smb_structs, SMBConnection
from foundation import config_manager
from foundation import cvm_utilities
from foundation import factory_mode
from foundation import features
from foundation import folder_central
from foundation import shared_functions
from foundation import foundation_tools
from foundation import imaging_context
from foundation import imaging_step_type_detection
from foundation import parameter_validation
from foundation.consts import ARCH_X86, ARCH_PPC
from foundation.foundation_tools import NOS_AHV_BUNDLE_MAGIC
from foundation.shared_functions import AUTOMATION_FRAMEWORK_KEY
from foundation.imaging_step_type_detection import CLASS_VM_INSTALLER
SMB_TCP_PORT = 445
DEFAULT_LOGGER = logging.getLogger(__file__)
MIN_NOS_VERSION_FOR_NS = '5.5'
ILLEGAL_HOSTNAME_RE = re.compile('[^a-zA-Z0-9-]')

def imaging_json_validation(json_config):
    """
    Validate the json config provided to image_nodes and make any
    necessary changes. This function is called *before* imaging process
    starts and is executed via /image_nodes API.
    
    This function must be extremely *short-lived* ! Any long running operation
    introduced here will hang UI and result in a bad user experience. Move any
    long running operations to common_validations.
    
    Args:
      json_config : A dict object as described in Foundation API for image_nodes.
    Returns:
      None
    Raises:
      StandardError upon any failure.
    """
    is_imaging = False
    blocks = json_config['blocks']
    for block in blocks:
        if factory_mode.factory_mode():
            if 'block_id' not in block:
                raise StandardError('Missing required parameter block_id')
        if 'model' in block.keys():
            del block['model']
        for node in block['nodes']:
            if factory_mode.factory_mode():
                for name in ['node_serial']:
                    if name not in node:
                        raise StandardError('Missing required parameter %s' % name)

            if 'model' in node.keys():
                del node['model']
            is_imaging |= node['image_now']

    incoming_nos_package = None
    if is_imaging and 'nos_package' in json_config:
        if not json_config['nos_package']:
            DEFAULT_LOGGER.debug('Imaging without nos_package provided')
        else:
            incoming_nos_package = os.path.join(folder_central.get_nos_folder(), json_config['nos_package'])
            if incoming_nos_package.endswith('.gz') and not os.path.exists(incoming_nos_package) and os.path.exists(incoming_nos_package[:-3]):
                incoming_nos_package = incoming_nos_package[:-3]
            if not os.path.isfile(incoming_nos_package):
                raise StandardError("Couldn't find nos_package at %s" % json_config['nos_package'])
            json_config['nos_package'] = incoming_nos_package

    def pathify(hypervisor, iso_name):
        hypervisors = foundation_tools.HYP_TYPES
        msg = 'You chose a hypervisor that was not one of %s' % hypervisors
        msg += 'Please use one of those'
        assert hypervisor in hypervisors, msg
        func = getattr(folder_central, 'get_%s_isos_folder' % hypervisor)
        return os.path.join(func(), iso_name)

    hyp_from_url = False
    if AUTOMATION_FRAMEWORK_KEY in json_config and 'nos_version' in json_config:
        hyp_from_url = True
        json_config['hyp_from_url'] = True
    if is_imaging and not hyp_from_url:
        for hyp, hyp_obj in json_config['hypervisor_iso'].items():
            if isinstance(hyp_obj, basestring):
                filename = hyp_obj
            else:
                filename = hyp_obj['filename']
            if os.path.isfile(filename):
                continue
            elif hyp == 'kvm' and (not filename or NOS_AHV_BUNDLE_MAGIC in filename):
                del json_config['hypervisor_iso']['kvm']
                continue
            elif os.path.isfile(pathify(hyp, filename)):
                if isinstance(hyp_obj, basestring):
                    json_config['hypervisor_iso'][hyp] = pathify(hyp, filename)
                else:
                    json_config['hypervisor_iso'][hyp]['filename'] = pathify(hyp, filename)
            else:
                raise StandardError('hypervisor_iso %s:%s does not exist' % (
                 hyp, filename))

    json_config['is_imaging'] = is_imaging
    return


def validate_and_correct_ip(ip):
    return shared_functions.validate_and_correct_ip(ip)


def validate_and_correct_netmask(mask):
    return shared_functions.validate_and_correct_netmask(mask)


def validate_xpress_restrictions(global_config):
    """
    Validates Xpress platform restrictions for the current imaging configuration.
    This validation is performed before imaging only for CVM workflow and if
    cluster has to be created.
    
    Args:
      global_config: GlobalConfig object for the imaging session.
    
    Returns:
      None
    
    Raises:
      StandardError if Xpress platform restrictions are violated.
    """
    if imaging_context.get_context() != imaging_context.FIELD_VM:
        return
    clusters = global_config.clusters
    create_cluster = False
    for cluster in clusters:
        if getattr(cluster, 'cluster_init_now', False):
            create_cluster = True

    if not create_cluster:
        return
    err = False
    for cluster in clusters:
        if not validate_xpress_cluster(cluster):
            err = True
            cluster.get_logger().error('Cluster %s does not satisfy Xpress platform requirements' % cluster.cluster_name)

    if err:
        raise StandardError('Requested cluster configurations violate Xpress platform requirements. Check cluster logs for more details')


def validate_xpress_cluster(cluster_config):
    """
    Validates Xpress platform restrictions for a cluster.
    
    Args:
      cluster_config: ClusterConfig object corresponding to the cluster to
          be validated.
    
    Returns:
      True if validation successful, False otherwise.
    """
    if not getattr(cluster_config, 'cluster_init_now', False):
        return True
    nodes = cluster_config.cluster_members
    logger = cluster_config.get_logger()
    logger.info('Validating Xpress platform requirements for cluster %s' % cluster_config.cluster_name)
    xpress_nodes = []
    non_xpress_nodes = []
    hcs = foundation_tools.tmap(foundation_tools.read_hardware_config_from_any, args_list=zip(nodes))
    for node, hc in zip(nodes, hcs):
        if hc:
            hw_attr = hc['node'].get('hardware_attributes', {})
            if hw_attr.get('is_xpress_node', False):
                xpress_nodes.append(node)
                continue
        non_xpress_nodes.append(node)

    x_count = len(xpress_nodes)
    non_x_count = len(non_xpress_nodes)
    xpress_violation = False
    if x_count:
        if non_x_count:
            xpress_violation = True
            msg = 'Found a mix of Xpress platform and non-Xpress platform nodes in cluster %s' % cluster_config.cluster_name
            msg = msg + '\nXpress nodes in cluster: %s' % [ node.cvm_ip for node in xpress_nodes ]
            msg = msg + '\nNon-Xpress nodes in cluster: %s' % [ node.cvm_ip for node in non_xpress_nodes ]
            logger.error(msg)
        if x_count > 4:
            xpress_violation = True
            msg = 'More than 4 Xpress platform nodes found in cluster %s' % cluster_config.cluster_name
            msg = msg + '\nXpress nodes in cluster: %s' % [ node.cvm_ip for node in xpress_nodes ]
            logger.error(msg)
        if imaging_context.get_context() == imaging_context.FIELD_VM:
            nos_package = getattr(cluster_config, 'nos_package', None)
            is_imaging = False
            if filter(lambda nc: nc.image_now, nodes):
                is_imaging = True
            if nos_package and is_imaging:
                cm = config_manager.CacheManager
                nos_version = cm.get(shared_functions.get_nos_version_from_tarball, nos_package_path=nos_package)
                if LooseVersion(nos_version) < LooseVersion('4.6.2'):
                    xpress_violation = True
                    logger.error('AOS version to be installed is %s. But, Xpress nodes are supported only by AOS 4.6.2 or higher versions' % nos_version)
    return not xpress_violation


def validate_and_correct_network_addresses(global_config):
    return shared_functions.validate_and_correct_network_addresses(global_config)


def validate_unc_share(global_config):
    """ Validate the unc share. """
    unc_path = global_config.unc_path
    username = global_config.unc_username
    password = global_config.unc_password
    result = urlparse(unc_path)
    if result.scheme or not result.netloc:
        raise StandardError('UNC path must be in the following form: //ip/share/folder or //ip/share')
    host = result.netloc
    share_folder = result.path.lstrip('/')
    if '/' in share_folder:
        share, folder = result.path.lstrip('/').split('/', 1)
    else:
        share, folder = result.path.lstrip('/'), '/'
    conn = SMBConnection.SMBConnection(username, password, 'foundation', host, use_ntlm_v2=True, is_direct_tcp=True)
    try:
        connected = conn.connect(host, SMB_TCP_PORT)
        if not connected:
            raise StandardError('Unable to connect to UNC server at: %s' % host)
        files = conn.listPath(share, folder)
        filenames = [ file_.filename for file_ in files ]
        DEFAULT_LOGGER.debug('UNC share %s contains: %s', unc_path, filenames)
        return filenames
    except (socket.error, smb_structs.OperationFailure):
        DEFAULT_LOGGER.exception('Exception in testing UNC share: %s', unc_path)
        raise StandardError('%s is not a valid UNC share' % unc_path)


def validate_nos_against_ns(nodes, clusters):
    if not any(map(lambda cc: cc.enable_ns, clusters)):
        return
    for node in nodes:
        if node.image_now:
            if node.svm_install_type:
                nos_package = node.nos_package
                node.nos_version = node._cache.get(shared_functions.get_nos_version_from_tarball, nos_package)

    for cluster in clusters:
        if not cluster.cluster_init_now:
            continue
        if not cluster.enable_ns:
            continue
        for node in cluster.cluster_members:
            if node.hyp_type == 'xen':
                error = 'Network Segmentation is not available on Xen'
                raise StandardError(error)
            if not node.image_now:
                nos_version = foundation_tools.get_nos_version_from_cvm(node.cvm_ip)
                node.nos_version = ('.').join(map(str, nos_version))
            if LooseVersion(node.nos_version) >= LooseVersion(MIN_NOS_VERSION_FOR_NS):
                continue
            error = 'Network Segmentation is available only if the AOS being deployed is %s or later. ' % MIN_NOS_VERSION_FOR_NS
            if not node.image_now:
                error += 'Node with CVM IP %s was to skip imaging but is on AOS %s which does not support Network Segmentation. ' % (
                 node.cvm_ip, node.nos_version)
            else:
                error += 'Version of AOS tarball provided: %s. ' % node.nos_version
            error += 'Please deselect the Network Segmentation option and try again or image all nodes with AOS %s or later' % MIN_NOS_VERSION_FOR_NS
            raise StandardError(error)


def validate_redundancy_factor(global_config):
    """
    Validate redundancy factor. Foundation API says that RF can be
    integer or null. We accept integer in string form as well.
    
    Args:
      global_config (GlobalConfig): An object of type GlobalConfig
    
    Returns:
      None
    
    Raises:
      StandardError
    
    """
    for cluster in global_config.clusters:
        if not getattr(cluster, 'redundancy_factor', None):
            cluster.redundancy_factor = 2
        else:
            try:
                cluster.redundancy_factor = int(cluster.redundancy_factor)
            except:
                raise StandardError('Redundancy factor %s is not a valid integer' % str(cluster.redundancy_factor))

    return


def validate_required_parameters(global_config):
    """
    Validate mandatory parameters.
    
    Args:
      global_config (GlobalConfig): An object of type GlobalConfig
    
    Returns:
      None
    
    Raises:
      StandardError
    
    """
    required_params = [
     'hypervisor_netmask', 'hypervisor_gateway',
     'hypervisor_password']
    ucsm_required_params = [
     'ucsm_ip', 'ucsm_user', 'ucsm_password',
     'ucsm_node_serial']
    for node in global_config.nodes:
        node.get_logger().info('Validating parameters. This may take few minutes')
        missing_params = []
        for name in required_params:
            if not hasattr(node, name):
                missing_params.append(name)

        if getattr(node, 'ucsm_managed_mode', None):
            for key in ucsm_required_params:
                if not hasattr(node, key):
                    missing_params.append(key)

        if missing_params:
            raise StandardError('Missing required parameters: %s' % missing_params)

    return


def validate_hypervisor_hostname_pattern(global_config):
    """
    
    Args:
      global_config (GlobalConfig): global config object
    
    Returns:
      None
    
    Raises:
      StandardError
    
    """
    node_configs = global_config.nodes
    hostnames = [ getattr(node, 'hypervisor_hostname', '') for node in node_configs
                ]
    hostnames = [ hostname for hostname in hostnames if hostname ]
    invalid_hostnames = [ hostname for hostname in hostnames if ILLEGAL_HOSTNAME_RE.search(hostname)
                        ]
    if invalid_hostnames:
        raise StandardError('Invalid hostnames: %s. Hostnames should contain only digits, letters, and hyphens' % (',').join(('"%s"' % hostname for hostname in invalid_hostnames)))


def validate_hostnames_are_not_duplicate(global_config):
    """
    
    Args:
      global_config (GlobalConfig): global config object
    
    Returns:
      None
    
    Raises:
      StandardError
    
    """
    node_configs = global_config.nodes
    hostnames = [ getattr(node, 'hypervisor_hostname', '') for node in node_configs
                ]
    hostnames = [ hostname for hostname in hostnames if hostname ]
    duplicate_hostnames = set([])
    hostnames = sorted(hostnames)
    for i, hostname in enumerate(hostnames):
        if hostname in hostnames[i + 1:]:
            duplicate_hostnames.add(hostname)

    if duplicate_hostnames:
        raise StandardError('Duplicate hostname found: %s' % (' ').join(list(duplicate_hostnames)))


def validate_hyperv_hostname(global_config):
    """
    
    Args:
      global_config (GlobalConfig): global config object
    
    Returns:
      None
    
    Raises:
      StandardError
    
    """
    node_configs = global_config.nodes
    hostnames = []
    for node in node_configs:
        if getattr(node, 'hyp_type', '') == 'hyperv':
            hostnames.append(getattr(node, 'hypervisor_hostname', ''))

    if any(map(lambda name: name and len(name) > 15, hostnames)):
        raise StandardError('Hyper-V does not support hostnames longer than 15 characters.')


def validate_support_restrictions(global_config):
    """
    Validate whether the requested cluster configurations are supported.
    The following validations are done:
      1) Validate whether all nodes in a cluster belong to the same arch.
         Also, populates the arch field for all nodes in the cluster
      2) validate whether all nodes in a cluater belong to the same license class
    
    Args:
      global_config (GlobalConfig): An object of type GlobalConfig
    
    Returns:
      None
    
    Raises:
      StandardError
    
    """
    clusters = global_config.clusters
    unsupported_clusters_found = False
    for cluster in clusters:
        if getattr(cluster, 'cluster_init_now', False):
            logger = cluster.get_logger()
            logger.info('Validating whether all members of cluster %s belong to the same arch' % cluster.cluster_name)
            if not is_single_arch_cluster(cluster) or not is_single_license_class_cluster(cluster):
                unsupported_clusters_found = True

    if unsupported_clusters_found:
        raise StandardError('Requested cluster configurations dont satisfy support requirements. Please check cluster logs for more details')


def validate_one_two_node_checks(global_config):
    """
    Validate one and two node cluster configurations
    
    Args:
      global_config (GlobalConfig): An object of type GlobalConfig
    
    Returns:
      None
    
    Raises:
      StandardError
    
    """
    DEFAULT_LOGGER.info('Running one and two node validations')
    node_configs = global_config.nodes
    for cluster in global_config.clusters:
        cluster_members = cluster.cluster_members
        cluster_create = getattr(cluster, 'cluster_init_now', False)
        if cluster_create and len(cluster_members) < 3:
            if cluster.single_node_cluster:
                continue
            for node in cluster_members:
                if node.hyp_type == 'hyperv':
                    raise StandardError('One and Two node clusters do not support Hyperv')
                if node.hyp_type == 'xen':
                    raise StandardError('One and Two node clusters do not support Xen')

    nodes = filter(lambda node: not getattr(node, 'compute_only', False), node_configs)
    hcs = foundation_tools.tmap(foundation_tools.read_hardware_config_from_any, zip(nodes))
    for node, hc in zip(nodes, hcs):
        if hc:
            hardware_attributes = hc['node'].get('hardware_attributes')
            if not hardware_attributes:
                DEFAULT_LOGGER.warn("Could not read %s's hardware_attributes to run one and two node validation. This is probably an old platform. This is usually OK" % str(node.cvm_ip))
                continue
            no_conventional_cluster = hardware_attributes.get('no_conventional_cluster', False)
            if no_conventional_cluster and node.hyp_type == 'hyperv':
                raise StandardError('This platform does not support HyperV')
            if no_conventional_cluster and node.hyp_type == 'xen':
                raise StandardError('This platform does not support Xen')


def is_single_arch_cluster(cluster_config):
    """
    Validate whether all nodes in the requested cluster configuration
    belong to the same arch.
    
    Args:
      cluster_config : ClusterConfig object for the cluster provided
    
    Returns:
      True if all nodes in the cluster belong to the same arch,
      False otherwise
    """
    nodes = cluster_config.cluster_members
    logger = cluster_config.get_logger()
    context = imaging_context.get_context()
    arch_node_map = {}

    def detect_arch(node):
        hint = getattr(node, 'device_hint', None)
        if context == imaging_context.FIELD_VM or hint == CLASS_VM_INSTALLER:
            node.arch = cvm_utilities.detect_remote_arch(node)
        else:
            if imaging_step_type_detection.detect_if_ppc_node(node):
                node.arch = ARCH_PPC
            else:
                node.arch = ARCH_X86
        return

    foundation_tools.tmap(detect_arch, zip(nodes))
    for node in nodes:
        if node.arch in arch_node_map.keys():
            arch_node_map[node.arch].append(node)
        else:
            arch_node_map[node.arch] = [
             node]

    if len(arch_node_map.keys()) > 1:
        msg = 'Found mixed architecture nodes in cluster %s' % cluster_config.cluster_name
        for arch in arch_node_map.keys():
            msg += '\n%s nodes in cluster: %s' % (
             arch, [ node.cvm_ip for node in arch_node_map[arch] ])

        logger.error(msg)
        return False
    return True


def is_single_license_class_cluster(cluster_config):
    """
    Validates software only and non-software only nodes are
    not part of the same cluster
    
    Args:
      cluster_config (ClusterConfig): cluster to be validated
    
    Returns:
      True if software only and oem/nx nodes are not intermixed, False otherwise
    """
    nodes = cluster_config.cluster_members
    logger = cluster_config.get_logger()
    license_node_map = {'appliance': []}
    for node in nodes:
        hw_layout = None
        if foundation_tools.in_cvm(node):
            hw_layout = foundation_tools.read_hardware_config_from_cvm(node)
        else:
            if foundation_tools.in_phoenix(node):
                hw_layout = foundation_tools.read_hardware_config_from_phoenix(node)
            else:
                logger.error('Foundation is unable to determine state of node with ip %s, postponing validation of intermixing of software only/appliance nodes to cluster creation stage' % node.cvm_ip)
                return True
        if not hw_layout:
            logger.error('Unable to read hardware_config.json, skipping license class validation for node')
            continue
        hw_attr = hw_layout['node'].get('hardware_attributes')
        if hw_attr:
            license_class = hw_attr.get('license_class')
            if license_class:
                if license_class in license_node_map.keys():
                    license_node_map[license_class].append(node)
                else:
                    license_node_map[license_class] = [
                     node]
                continue
        license_node_map['appliance'].append(node)

    if len([ k for k in license_node_map.keys() if license_node_map[k] ]) > 1:
        msg = 'Found intermixed software only & appliance nodes in cluster %s' % cluster_config.cluster_name
        for license_key in license_node_map.keys():
            msg += '\n%s nodes in cluster: %s' % (
             license_key, [ node.cvm_ip for node in license_node_map[license_key] ])

        logger.error(msg)
        return False
    return True


def validate_ntp_servers(global_config):
    """
      raises exception if any of the clusters don't have a valid ntp.
      logs other errors to warning
    """
    ntp_validation_errors = {}
    cluster_ntp_status = {}
    dns_not_provided = 'DNSNotProvided'
    ntp_resolution_failed = 'NTPResolutionFailed'
    ntp_not_reachable = 'NTPNotReachable'
    for cluster in global_config.clusters:
        cvm_ntp_servers = getattr(cluster, 'cvm_ntp_servers', '')
        if not cvm_ntp_servers:
            continue
        dns_servers = getattr(cluster, 'cvm_dns_servers', '')
        cluster_ntp_status[cluster] = False
        cluster_errors = {}

        def ntp_is_reachable(ntp_list):
            return any([ foundation_tools.generic_ping(ntp) for ntp in ntp_list ])

        def resolve_ntp(ntp):
            if not dns_servers:
                raise StandardError(dns_not_provided)
            dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
            dns.resolver.default_resolver.nameservers = dns_servers.split(',')
            try:
                return [ str(ip) for ip in dns.resolver.query(ntp, 'a') ]
            except dns.exception.DNSException:
                raise StandardError(ntp_resolution_failed)

        for c_ntp in cvm_ntp_servers.split(','):
            try:
                shared_functions.validate_and_correct_ip(c_ntp)
                ntp_ip = [c_ntp]
            except StandardError:
                try:
                    ntp_ip = resolve_ntp(c_ntp)
                except StandardError as e:
                    cluster_errors[e.message] = cluster_errors.get(e.message, [])
                    cluster_errors[e.message].append(c_ntp)
                    continue

            else:
                if not ntp_is_reachable(ntp_ip):
                    cluster_errors[ntp_not_reachable] = cluster_errors.get(ntp_not_reachable, [])
                    cluster_errors[ntp_not_reachable].append(c_ntp)
                    continue
                cluster_ntp_status[cluster] = True

        err_msg = ''
        for error in cluster_errors:
            if error == dns_not_provided:
                err_msg += "ntp server %s couldn't be resolved because, a dns entry hasn't been provided. " % (',').join(cluster_errors[error])
            elif error == ntp_resolution_failed:
                err_msg += "ntp server %s couldn't be resolved using the dns entries %s. " % (
                 (',').join(cluster_errors[error]), dns_servers)
            else:
                err_msg += "ntp server %s couldn't be reached. " % (',').join(cluster_errors[error])

        if err_msg:
            ntp_validation_errors[cluster] = err_msg

    if not all(cluster_ntp_status.itervalues()):
        error_message = (' ').join(ntp_validation_errors.values())
        error_message += 'Please use a valid value or setup ntp using Prism after cluster creation.'
        raise StandardError(error_message)
    else:
        for cluster in ntp_validation_errors:
            logger = cluster.get_logger()
            logger.warning(ntp_validation_errors[cluster])


def validate_lacp_restrictions(global_config):
    nodes = global_config.nodes
    for node in nodes:
        if node.hyp_type == 'esx' and getattr(node, 'bond_mode', ''):
            raise StandardError('Switch dependent link aggregation is not supported for Esx with foundation. Please configure link aggregation manually using vCenter after imaging.')
        if node.hyp_type == 'xen' and getattr(node, 'bond_mode', ''):
            raise StandardError('Switch dependent link aggregation is not supported for Xen with foundation yet. Please configure link aggregation manually after imaging.')


def common_validations(global_config=None, quick=False):
    """
    This function is called once imaging process has *started*.
    It should have any operations which may possibly take a long time, such
    as calculating md5sum of an iso.
    
    Args:
      global_config : GlobalConfig object.
      quick: Skip time consuming validations
    Returns:
      None
    Raises:
      StandardError in case of failure in validations.
    """
    if not global_config:
        return
    validate_redundancy_factor(global_config)
    validate_required_parameters(global_config)
    validate_hostnames_are_not_duplicate(global_config)
    validate_hypervisor_hostname_pattern(global_config)
    validate_hyperv_hostname(global_config)
    validate_and_correct_network_addresses(global_config)
    validate_lacp_restrictions(global_config)
    nodes = global_config.nodes
    for node in nodes:
        if getattr(node, 'ucsm_managed_mode', None):
            node.ipmi_user = node.ucsm_user
            node.ipmi_password = node.ucsm_password
            if not (node.ucsm_ip and node.ucsm_user and node.ucsm_password and node.ucsm_node_serial):
                raise StandardError('ucsm_ip, ucsm_user, ucsm_password and ucsm_node_serial are required for imaging software-only nodes')
        if node.hyp_type == 'kvm':
            if 'kvm' not in node.hyp_iso.keys() or not node.hyp_iso['kvm'] or NOS_AHV_BUNDLE_MAGIC in node.hyp_iso['kvm']:
                node.kvm_from_nos = True
                node.nos_with_kvm = node.nos_package
            else:
                global_config.kvm_rpm = node.hyp_iso['kvm']
        is_factory = factory_mode.factory_mode()
        if not is_factory:
            if getattr(node, 'cluster_destroy_now', False):
                continue
            if not getattr(node, 'image_now', False):
                continue
        if node.hyp_type not in node.hyp_iso:
            if node.hyp_type != 'kvm':
                raise StandardError('You specified %s hypervisor for a node but did not provide an iso for it' % node.hyp_type)
        co_kvm_from_nos = getattr(node, 'compute_only', False) and node.kvm_from_nos
        if not node.svm_install_type and not co_kvm_from_nos:
            node.nos_package = None
        if node.svm_install_type:
            if node.nos_package is None:
                raise StandardError('NOS package was not provided in the input %s' % node.nos_package)
            if not os.path.isfile(node.nos_package):
                raise StandardError("Couldn't find nos_package at %s" % node.nos_package)

    host_ip_config_dict = {}
    for node in nodes:
        host_ip_config_dict[node.hypervisor_ip] = node

    xen_nodes = filter(lambda node: getattr(node, 'hyp_type', None) == 'xen', nodes)
    if xen_nodes and len(xen_nodes) != len(nodes):
        raise StandardError("Foundation doesn't support xen and another hypervisor in one session")
    if xen_nodes:
        if all(map(lambda node: getattr(node, 'xen_config_type', None) is None, xen_nodes)):
            DEFAULT_LOGGER.info('xen_config_type is not set for any node, choosing pool master automatically')
            pool_master = None
            if getattr(global_config, 'need_handoff', None):
                pool_master = global_config.first_node_to_image
            else:
                pool_master = xen_nodes[0]
            DEFAULT_LOGGER.info('Choosing %s as pool master', pool_master.hypervisor_ip)
            global_config.xs_master_ip = pool_master.hypervisor_ip
            for node in xen_nodes:
                if node == pool_master:
                    node.xen_config_type = 'master'
                else:
                    node.xen_config_type = 'slave'

        for node in xen_nodes:
            if getattr(node, 'xs_master_ip', None):
                if node.xs_master_ip == node.hypervisor_ip:
                    node.is_xs_master = True
                    node.get_logger().info('Using this node as XenServer master: %s', node.xs_master_ip)
                    continue
                node.is_xs_slave = True
                if node.xs_master_ip not in host_ip_config_dict:
                    node.get_logger().warn('Using external XenServer master: %s', node.xs_master_ip)
                else:
                    node.get_logger().info('Using XenServer master: %s', node.xs_master_ip)

    clusters = global_config.clusters
    for cluster in clusters:
        if not cluster.cluster_init_now:
            continue
        if cluster.setup_replication:
            req_keys_for_replication = [
             'replication_target_name',
             'replication_target_cluster']
            missing_keys = []
            for key in req_keys_for_replication:
                if not getattr(cluster, key, None):
                    missing_keys.append(key)

            if missing_keys:
                raise StandardError("%s keys are required to setup replication and can't have empty values" % missing_keys)
            target_cluster = cluster.replication_target_cluster
            for candidate in clusters:
                if candidate.cluster_name == target_cluster:
                    cluster.replication_target_ips = [ node.cvm_ip for node in candidate.cluster_members ]
                    break
            else:
                raise StandardError('Target cluster %s is not present in list of input clusters' % target_cluster)

        num_members = len(cluster.cluster_members)
        if cluster.single_node_cluster and num_members != 1:
            raise StandardError('Single node cluster %s can have only 1 member, number of members specified: %d' % (
             cluster.cluster_name, num_members))
        else:
            if not cluster.single_node_cluster:
                required_nodes = 2 * int(cluster.redundancy_factor) - 1
                if len(cluster.cluster_members) < required_nodes and len(cluster.cluster_members) > 2:
                    raise StandardError('Cluster %s has too few nodes - cluster actions require %d or more nodes for redundancy factor %d' % (
                     cluster.cluster_name, required_nodes, cluster.redundancy_factor))
        if cluster.enable_ns:
            bp_subnet = getattr(cluster, 'backplane_subnet', None)
            bp_netmask = getattr(cluster, 'backplane_netmask', None)
            bp_vlan = getattr(cluster, 'backplane_vlan', None)
            if not bp_subnet or not bp_netmask or bp_vlan is None:
                raise StandardError('backplane_subnet, backplane_netmask and backplane_vlan must be specified when enabling network segmentation')
            cluster.backplane_subnet = validate_and_correct_ip(bp_subnet)
            cluster.backplane_netmask = validate_and_correct_netmask(bp_netmask)
            cluster.backplane_vlan = int(bp_vlan)
            cluster.backplane_auto_assign_ips = getattr(cluster, 'backplane_auto_assign_ips', True)
            cluster.process_backplane_only = getattr(cluster, 'process_backplane_only', False)
            req_keys = ['backplane_cvm_ip', 'backplane_host_ip']
            missing_keys_members = collections.defaultdict(list)
            if not cluster.backplane_auto_assign_ips:
                for member in cluster.cluster_members:
                    for key in req_keys:
                        if not getattr(member, key, None):
                            missing_keys_members[member.cvm_ip].append(key)

                if missing_keys_members:
                    msg = 'Since backplane_auto_assign_ips is False for cluster %s, some of the required keys are missing for cluster members. These are %s' % (
                     cluster.cluster_name, missing_keys_members)
                    raise StandardError(msg)

    convert_network_information(global_config)
    if quick:
        DEFAULT_LOGGER.info('Quick common validations is done')
        return
    validate_ping_self(global_config)
    nos_package = getattr(global_config, 'nos_package', None)
    if getattr(node, 'image_now', False) and nos_package:
        if not shared_functions.validate_aos_package(name=nos_package):
            raise StandardError("Failed to validate AOS package '%s'" % nos_package)
    validate_ahv_with_aos(global_config)
    validate_ntp_servers(global_config)
    is_imaging = any(map(lambda n: n.image_now, nodes))
    if is_imaging:
        parameter_validation.validate_parameters(global_config)
    validate_nos_against_ns(nodes, clusters)
    validate_xpress_restrictions(global_config)
    validate_chassis_configuration(global_config)
    validate_foundation_payload(global_config)
    validate_rdma_reqs(global_config)
    validate_support_restrictions(global_config)
    validate_one_two_node_checks(global_config)
    return


def validate_ping_self(global_config):
    if not foundation_tools.generic_ping(global_config.foundation_ip):
        raise StandardError("Foundation failed to ping itself. This may be because you have a firewall blocking ICMP traffic on your machine. On a Mac this can be resolved by disabling 'Stealth Mode'.")


def validate_ahv_with_aos(global_config):
    nodes = global_config.nodes
    for node in nodes:
        if getattr(node, 'kvm_from_nos', None) and getattr(node, 'image_now', False):
            nos_package = getattr(global_config, 'nos_package', None)
            if nos_package:
                if not os.path.exists(nos_package):
                    raise StandardError("Provided NOS package %s doesn't exist", nos_package)
                is_kvm_in_nos = foundation_tools.get_kvm_package_in_nos(nos_package)
                if is_kvm_in_nos:
                    return
                raise StandardError('Trying to use AHV from AOS, but no AHV bundle found')
            else:
                raise StandardError('Trying to use AHV from AOS, but no AOS package is given')

    return


def validate_foundation_payload(global_config):
    foundation_payload = getattr(global_config, 'foundation_payload', None)
    if not foundation_payload:
        return
    nos_package = getattr(global_config, 'nos_package', None)
    if not nos_package:
        return
    DEFAULT_LOGGER.debug('Validating foundation payload which has been given for injection')
    if not os.path.exists(foundation_payload):
        raise StandardError("Couldn't find the foundation %s specified by config for injection into NOS" % foundation_payload)
    if not foundation_tools.is_valid_foundation_tar_gz(foundation_payload):
        raise StandardError('Foundation payload %s specified for injection into NOS is not a valid foundation build' % foundation_payload)
    foundation_version_in_nos = foundation_tools.get_foundation_pkg_version_from_nos_tar(nos_package)
    foundation_payload_version = foundation_tools.get_foundation_version_from_foundation_archive(foundation_payload)
    version_cmp = foundation_tools.compare_foundation_version_strings(foundation_payload_version, foundation_version_in_nos)
    if version_cmp == -1:
        raise StandardError('Foundation version specified for injection is less than foundation version bundled in NOS, %s < %s' % (
         foundation_payload_version, foundation_version_in_nos))
    return


def convert_network_information(global_config):
    """
    Converts the network information specified for KVM nodes to
    the new format as described in the Foundation API. This function
    also add the necessary params to bring up eth2 on AHV.
    Args:
      global_config : GlobalConfig object
    Returns:
      None
    """
    for node in global_config.nodes:
        if node.hyp_type != 'kvm':
            continue
        if not node.image_now:
            continue
        vswitches = getattr(node, 'vswitches', None)
        if vswitches is None:
            vswitch_br0 = {'name': 'br0', 'uplinks': (',').join(getattr(node, 'bond_uplinks', [])), 
               'bond-mode': 'active-backup'}
            bond_mode = getattr(node, 'bond_mode', '')
            if bond_mode == 'static':
                vswitch_br0['bond-mode'] = 'balance-slb'
                vswitch_br0['use_ten_gig_only'] = True
                vswitch_br0['other_config'] = [
                 'bond-rebalance-interval=30000']
            else:
                if bond_mode == 'dynamic':
                    vswitch_br0['bond-mode'] = 'balance-tcp'
                    vswitch_br0['lacp'] = 'active'
                    vswitch_br0['use_ten_gig_only'] = True
                    bond_lacp_rate = node.bond_lacp_rate
                    vswitch_br0['other_config'] = ['lacp-fallback-ab=true',
                     'lacp-time=%s' % bond_lacp_rate]
            vswitches = [
             vswitch_br0]
            setattr(node, 'vswitches', vswitches)
        host_interfaces = getattr(node, 'host_interfaces', None)
        if host_interfaces is None:
            host_interfaces = [
             {'name': 'br0', 'vswitch': 'br0', 
                'ip': node.hypervisor_ip, 
                'netmask': node.hypervisor_netmask, 
                'gateway': node.hypervisor_gateway, 
                'vlan': getattr(node, 'cvm_vlan_id', None)}]
            setattr(node, 'host_interfaces', host_interfaces)
        cvm_interfaces = getattr(node, 'cvm_interfaces', None)
        if hasattr(node, 'cvm_ip') and cvm_interfaces is None:
            cvm_interfaces = [
             {'name': 'eth0', 'vswitch': 'br0', 
                'ip': node.cvm_ip, 
                'netmask': node.cvm_netmask, 
                'gateway': node.cvm_gateway, 
                'vlan': getattr(node, 'cvm_vlan_id', -1)}]
            cvm_interfaces.append({'name': 'eth1', 
               'vswitch': '_internal_', 
               'vlan': 0, 
               'ip': None})
            setattr(node, 'cvm_interfaces', cvm_interfaces)

    return


def _validate_chassis_are_heterogeneous(node_frus):

    def is_broadwell(fru_dict):
        model = fru_dict['product_part_number']
        if model.endswith('-G5'):
            return True
        return False

    chassis_map = collections.defaultdict(list)
    for fru in node_frus:
        chassis_serial = fru['chassis_serial']
        chassis_map[chassis_serial].append(fru)

    status = True
    error_message = ''
    for chassis_serial, nodes_fru in chassis_map.iteritems():
        broadwell_nodes = [ node_fru['product_serial'] for node_fru in nodes_fru if is_broadwell(node_fru)
                          ]
        haswell_nodes = [ node_fru['product_serial'] for node_fru in nodes_fru if not is_broadwell(node_fru)
                        ]
        if broadwell_nodes and haswell_nodes:
            status = False
            error_message += 'Chassis %s has a mix of Broadwell (%s) and Haswell (%s) nodes, this is not permitted\n' % (
             chassis_serial, broadwell_nodes, haswell_nodes)

    return (status, error_message)


def validate_chassis_configuration(global_config):
    """
    Makes sure customer has't cannibalized the chassis and mixed
    Broadwell and Haswell in the same chassis. This is a support issue,
    not a technical one.
    
    ENG-50708
    
    We will validate that the nodes that we are about to image or add in a
    cluster make a heterogeneous chassis. We will only do this for SMC nodes.
    
    Args:
      global_config: GlobalConfig object for the imaging session.
    
    Returns:
      None
    
    Raises:
      StandardError if conditions are violated.
    """
    if imaging_context.get_context() != imaging_context.FIELD_IPMI:
        return
    node_frus = []
    validation_result, error_message = True, ''
    clusters = global_config.clusters
    for cluster in clusters:
        if getattr(cluster, 'cluster_init_now', False):
            logger = cluster.get_logger()
            device_hints = map(lambda nc: getattr(nc, 'device_hint', None), cluster.cluster_members)
            if CLASS_VM_INSTALLER in device_hints:
                cluster.get_logger().warn('skip Haswell, Broadwell mix check for cluster %s', cluster)
                continue
            logger.info('Ensuring there is no Haswell, Broadwell mix in the same chassis for cluster %s' % cluster.cluster_name)
            nodes = cluster.cluster_members
            frus = foundation_tools.tmap(foundation_tools.get_smc_fru_info, args_list=zip(nodes))
            node_frus.extend([ fru for fru in frus if fru ])
            cluster_validation_result, cluster_error_message = _validate_chassis_are_heterogeneous(node_frus)
            if not cluster_validation_result:
                validation_result = cluster_validation_result
                logger.error(cluster_error_message)
            error_message += cluster_error_message

    if not validation_result:
        raise StandardError(error_message)


def validate_rdma_reqs(global_config):
    """
    Validate the nodes against RDMA restrictions. If CVM is not up or if the
    node is not in phoenix, then RDMA validation will be skipped.
    
    Args:
      global_config: GlobalConfig object for the imaging session.
    
    Returns:
      None
    
    Raises:
      StandardError if any RDMA restriction is violated.
    """
    success = True
    cvm_ips = []
    rdma_cvm_ips = []
    nodes = filter(lambda node: not getattr(node, 'compute_only', False), global_config.nodes)
    hcs = foundation_tools.tmap(foundation_tools.read_hardware_config_from_any, args_list=zip(nodes))
    for node, hc in zip(nodes, hcs):
        logger = node.get_logger()
        if not hc:
            hint = getattr(node, 'device_hint', None)
            if imaging_context.get_context() == imaging_context.FIELD_VM or hint:
                logger.warning('Failed to read hardware_config.json in CVM mode. Skipping RDMA validations')
            continue
        for nic in hc['node'].get('network_adapters', []):
            if 'rdma' in nic['features']:
                if node.cvm_ip not in rdma_cvm_ips:
                    rdma_cvm_ips.append(node.cvm_ip)
                if node.hyp_type in shared_functions.HYP_WITHOUT_RDMA_SUPPORT:
                    model = hc['node']['model_string']
                    logger.error('Node has RDMA enabled NIC. Imaging %s is not supported on this node (model: %s)' % (
                     node.hyp_type, model))
                    success = False
                    cvm_ips.append(node.cvm_ip)
                    break

    if not success:
        logger.warning('Selected hypervisor is not RDMA NIC compatibleon CVM IPs - %s' % cvm_ips)
    nos_package = getattr(global_config, 'nos_package', None)
    is_imaging = any(map(lambda n: n.image_now, global_config.nodes))
    if rdma_cvm_ips and nos_package and is_imaging:
        cm = config_manager.CacheManager
        nos_version = cm.get(shared_functions.get_nos_version_from_tarball, nos_package_path=nos_package)
        if LooseVersion(nos_version) < LooseVersion(shared_functions.MIN_NOS_FOR_RDMA):
            raise StandardError('Nodes with CVM IPs %s have NICs with RDMA support. AOS %s or higher is required to image these nodes. Current AOS version being imaged is %s' % (
             rdma_cvm_ips, shared_functions.MIN_NOS_FOR_RDMA, nos_version))
    return


def check_min_segmentation_version(global_config):
    """
    Gross hack alert! Segmentation currently makes the bad assumption that we are
    already on 5.5. This will get properly fixed with ENG-119462, but for now,
    prevent the user going forward and leave them a clear error message.
    """
    if not imaging_context.get_context() == imaging_context.FIELD_VM:
        return
    enable_ns = any([ cluster.enable_ns for cluster in global_config.clusters ])
    if enable_ns:
        nos_version = foundation_tools.get_nos_version_from_cvm(None)
        nos_version_str = ('.').join(map(str, nos_version))
        if LooseVersion(nos_version_str) < LooseVersion(MIN_NOS_VERSION_FOR_NS):
            raise StandardError('You must be on AOS %s to enable segmentation (sorry) but this CVM is on AOS %s. Upgrade the node, or create a cluster without segmentation and enable it from Prism.' % (
             MIN_NOS_VERSION_FOR_NS, nos_version_str))
    return