# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/factory_mode.py
# Compiled at: 2019-02-15 12:42:10
import copy, json, logging, os, re, socket
from collections import OrderedDict
from threading import Thread
from Queue import Queue
from netaddr import iter_iprange
import folder_central, foundation_tools, imaging_context
from foundation import shared_functions
SERIAL_RE = re.compile('\\d{2}\\w{2}(\\w{2})\\d{6}(?:-gold)?', flags=re.I)
FACTORY_SMC = 'smc'
FACTORY_SMC_PROD = 'smc_prod'
FACTORY_FLEX = 'flex'
FACTORY_COKEVA = 'cokeva'
FACTORY_IBM = 'ibm'
DEFAULT_LOGGER = logging.getLogger('factory')
MAGIC_STR = 'FOUNDATION_SUPPLIED'
RE_GOLD = re.compile('(-gold)(?i)$')
SW_REMOVE_MODES = [
 None, 'always', 'auto']
C_SW_REMOVE = 'C-SW-REMOVE'
factory_config = {}
ip_queue = []
DEFAULT_LOGGER = logging.getLogger(__name__)

def load_config():
    global factory_config
    global ip_queue
    factory_config_file = folder_central.get_factory_settings_path()
    DEFAULT_LOGGER.info('Loading factory_config from %s', factory_config_file)
    if factory_mode():
        with open(factory_config_file) as (config_fh):
            factory_config = json.load(config_fh, object_pairs_hook=OrderedDict)
        min_ip = factory_config['settings']['min_ip']
        max_ip = factory_config['settings']['max_ip']
        ip_queue = map(str, iter_iprange(min_ip, max_ip))
        DEFAULT_LOGGER.debug('Allocated %s IPs for factory', len(ip_queue))


def factory_mode():
    return imaging_context.get_context() == imaging_context.FACTORY


def get_config():
    if factory_mode():
        return factory_config
    return {}


def _get_model_string(block_id, node, user, password, result_queue, error_queue):
    cmd = [folder_central.get_ipmitool(),
     '-I', 'lanplus',
     '-H', node['ipmi_ip'],
     '-U', user,
     '-P', password,
     'fru']
    for retry in range(3):
        stdout, stderr, return_code = foundation_tools.system(None, cmd, log_on_error=False)
        if return_code == 0:
            model_string = ''
            for line in map(lambda line: line.strip(), stdout.splitlines()):
                if line.startswith('Product Part Number'):
                    model_string = line.split(':')[1].strip().upper()
                    break

            if model_string:
                DEFAULT_LOGGER.debug('Model string of %s is %s', node['ipmi_ip'], model_string)
                result_queue.put((block_id, node, model_string))
                return

    DEFAULT_LOGGER.error('ipmitool returned exit code %d\nStdout:\n%s\nStderr:\n%s', return_code, stdout, stderr)
    error_queue.put((block_id, node,
     'Foundation could not read the model string from FRU at IPMI IP %s.' % node['ipmi_ip']))
    return


def get_nos_version_by_model(block_id, model_string, factory_config):
    logger = DEFAULT_LOGGER
    model_string_map = factory_config['settings']['model_string_version_map']
    best_match = None
    match_len = lambda m: m.end() - m.start() + 1
    for pattern in model_string_map:
        match = re.match(pattern, model_string)
        if match:
            logger.debug('model %s matches pattern %s', model_string, pattern)
            if not best_match or match_len(match) > match_len(best_match):
                logger.info('using pattern %s as best match: %s', pattern, model_string[slice(*match.span())])
                best_match = match

    if not best_match:
        raise StandardError('The model string "%s" isn\'t in Foundation\'s list of recognized models. Please share this message with your system administrator.' % model_string)
    version_string = model_string_map.get(best_match.re.pattern, None)
    logger.debug('Found model %s => NOS %s', model_string, version_string)
    return version_string


def get_nos_version(blocks, ipmi_user, ipmi_password, factory_config):
    logger = DEFAULT_LOGGER
    result_queue = Queue()
    error_queue = Queue()
    threads = []
    for block in blocks:
        for node in block['nodes']:
            threads.append(Thread(target=_get_model_string, args=(block['block_id'],
             node, ipmi_user, ipmi_password, result_queue, error_queue)))

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    if not error_queue.empty():
        error_message = ''
        while not error_queue.empty():
            error_message += '\n\n%s' % error_queue.get()[2]

        raise StandardError("Couldn't read IPMI FRU on some nodes. It's likely that your Foundation VM is not in the same subnet as the IPMI interfaces, or that the FRU is bad. You should also check your IPMI username and password. Here are the errors Foundation found:%s" % error_message)
    nos_version = None
    while not result_queue.empty():
        block_id, node, model_string = result_queue.get()
        if 'gold' in node['node_serial'].lower():
            continue
        logger.debug('Looking for NOS version for model %s', model_string)
        version_string = get_nos_version_by_model(block_id, model_string, factory_config)
        node['node_nos_version_string'] = version_string
        node_version = map(int, version_string.split('.'))
        if not nos_version or node_version > nos_version:
            old_version = ('.').join(map(str, nos_version)) if nos_version else None
            logger.debug('Updating NOS version choice from %s to %s', old_version, version_string)
            nos_version = node_version

    if not nos_version:
        raise StandardError('It looks like all your nodes are gold. You must image at least one real node.')
    nos_version_string = ('.').join(map(str, nos_version))
    for block in blocks:
        for node in block['nodes']:
            node['nos_version_string'] = nos_version_string

    logger.info('Using NOS version %s', node_version)
    return nos_version_string


def adapt_cluster_ips(config, settings):
    """
    Assign IPs to IPMI/HOST/CVM and populate clusters config.
    """
    next_ip_index = 0
    next_cluster_id = 0
    num_nodes = sum(map(lambda block: len(block['nodes']), config['blocks']))
    num_ips_required = 4 * num_nodes
    allocated_ips = len(ip_queue)
    try:
        config['clusters'] = []
        for block in config['blocks']:
            if 'block_id' not in block:
                raise StandardError('This block is missing a block id.')
            for node in block['nodes']:
                node['ipmi_ip'] = ip_queue[next_ip_index]
                node['hypervisor_ip'] = ip_queue[next_ip_index + 1]
                node['cvm_ip'] = ip_queue[next_ip_index + 2]
                node['hypervisor'] = settings['hypervisor']
                next_ip_index += 3
                config['clusters'].append({'cluster_init_successful': None, 
                   'cluster_init_now': True, 
                   'cluster_destroy_successful': None, 
                   'cluster_destroy_now': True, 
                   'cluster_name': 'factory_cluster_%s' % next_cluster_id, 
                   'cluster_external_ip': ip_queue[next_ip_index], 
                   'redundancy_factor': 1, 
                   'single_node_cluster': True, 
                   'cluster_members': [
                                     node['cvm_ip']], 
                   'cvm_dns_servers': '', 
                   'cvm_ntp_servers': '', 
                   'hypervisor_ntp_servers': []})
                next_ip_index += 1
                next_cluster_id += 1

    except IndexError:
        DEFAULT_LOGGER.exception('Exception in assigning ips')
        raise StandardError("This Foundation VM isn't configured to have enough IP addresses for this imaging session. Number of allocated IPs (%s) is less than required number of IPs (%s). Please contact your sysadmin with a copy of this message." % (
         allocated_ips, num_ips_required))

    return


def get_order_info_from_block_id(block_id):
    from foundation import factory_smc as smc
    from foundation import imaging_step_flex as flex
    if smc.is_in_smc_prod_factory():
        return smc.smc_lookup_order_info(block_id)
    if flex.is_in_flex_factory():
        return flex.flex_lookup_order_info(block_id)
    raise NotImplementedError("foundation doesn't know how to lookup order info in factory %s" % factory_config.get('factory_type'))


def choose_profile_from_netsuite(block_id):
    """
    Formerly, chose image profile by looking at order info. Now, returns the only
    profile we support. We're keeping this so that we can add order inspection
    easily in the future.
    
    Returns:
      a profile
    Raises:
      StandardError when failed to read order info. Not currently possible.
    """
    return 'kvm'


def choose_profile(config, factory_config):
    """
    Choose profile from factory_config and other sources.
    
    The lookup order is:
     1. profile field in factory_config
     2. MAGIC_STR
       2.1 NetSuite
    
    Returns:
      a profile name
      None: when profile is not supported/enabled in the config file.
    
    Raise:
      StandardError when no valid profile can be used.
    """
    if 'profiles' not in factory_config or 'profile' not in factory_config:
        return
    profile = factory_config.get('profile')
    if profile == MAGIC_STR:
        selected_profile = None
        for block in config['blocks']:
            block_id = block['block_id']
            if 'gold' in block_id.lower():
                DEFAULT_LOGGER.debug('Ignore gold block %s in selecting profile', block_id)
            else:
                block_profile = choose_profile_from_netsuite(block_id)
                if not selected_profile or selected_profile == block_profile:
                    selected_profile = block_profile
                    DEFAULT_LOGGER.debug('Selected profile %s for block %s', selected_profile, block_id)
                else:
                    DEFAULT_LOGGER.error("Block %s is trying to select a different profile: %s, which it's not supported", block_id, block_profile)
                    raise StandardError("Block %s is not using the same profile as other blocks, which is not supported, please append '-gold' to block_id to identify gold blocks")
        else:
            DEFAULT_LOGGER.info('Using profile %s for all blocks', selected_profile)
            profile = selected_profile

    if profile in factory_config['profiles']:
        return profile
    profiles = factory_config['profiles'].keys()
    raise StandardError("Factory is trying to use profile %s but it's not in the profile list: %s" % (
     profile, profiles))
    return


def choose_sw_remove(config, factory_config):
    sw_remove_mode = factory_config.get('sw_remove_mode', None)
    assert sw_remove_mode in SW_REMOVE_MODES, 'sw_remove_mode must be one of %s' % SW_REMOVE_MODES
    if sw_remove_mode is None:
        DEFAULT_LOGGER.debug('sw_remove_mode not set, will skip C-SW-REMOVE')
        return
    DEFAULT_LOGGER.debug('sw_remove_mode is set to %s', sw_remove_mode)
    for block in config['blocks']:
        block_id = block['block_id']
        if sw_remove_mode == 'always':
            block['erase_disks'] = True
            DEFAULT_LOGGER.info('foundation will erase disks on block %s', block_id)
        elif sw_remove_mode == 'auto':
            if block_id.lower().lower().endswith('gold'):
                units = block['nodes']
                unit_ids = [ node['node_serial'] for node in block['nodes'] ]
            else:
                units = [
                 block]
                unit_ids = [block_id]
            for unit, unit_id in zip(units, unit_ids):
                order_lines = get_order_info_from_block_id(unit_id)
                for line in order_lines:
                    if line['itemname'] == C_SW_REMOVE:
                        unit['erase_disks'] = True
                        DEFAULT_LOGGER.info('foundation will erase disks on %s, Order Line: %s', unit_id, line)
                        break

        else:
            DEFAULT_LOGGER.info('foundation will NOT erase disk on block %s', block_id)

    return


def apply_factory_profile(config, factory_config, profile):
    """
    Apply profile to config and factory_config.
    
    factory_config[profile]["template"] will be applied to both
    factory_config[profile]["settings"] will be applied to factory_config
    """
    if not profile:
        return factory_config
    for block in config['blocks']:
        for node in block['nodes']:
            if node.get('hypervisor') == MAGIC_STR:
                del node['hypervisor']

    for field in ['template', 'settings']:
        if field in factory_config['profiles'][profile]:
            for key, value in factory_config['profiles'][profile][field].iteritems():
                factory_config[field][key] = value
                if field == 'template':
                    config[key] = value


def choose_nos(config, factory_config=None):
    if not factory_mode() or config['nos_package'] != MAGIC_STR:
        return
    if not factory_config:
        factory_config = get_config()
    settings = factory_config['settings']
    nos_version = get_nos_version(config['blocks'], config['ipmi_user'], config['ipmi_password'], factory_config)
    if nos_version not in settings['version_nos_map']:
        raise StandardError('NOS version %s does not have a NOS package assigned to it in the factory settings file. Please update lib/factory/factory_settings.json -> settings -> version_nos_map.' % nos_version)
    DEFAULT_LOGGER.debug('Using NOS version %s', nos_version)
    config['nos_package'] = settings['version_nos_map'][nos_version]


def choose_hypervisor(config, factory_config, profile):
    if not factory_mode() or config['nos_package'] != MAGIC_STR:
        return


def choose_foundation(config, factory_config=None):
    factory_config = factory_config or get_config()
    if not factory_config['settings'].get('nos_foundation_map', {}):
        return
    nos_package = config['nos_package']
    if not os.path.exists(nos_package):
        nos_package = os.path.join(folder_central.get_nos_folder(), nos_package)
    nos_version = shared_functions.get_nos_version_from_tarball(nos_package_path=nos_package)
    nos_foundation_map = factory_config['settings']['nos_foundation_map']
    foundation_payload = nos_foundation_map.get(nos_version, None)
    if not foundation_payload:
        return
    DEFAULT_LOGGER.info('Will inject foundation: %s into NOS: %s' % (
     foundation_payload, nos_version))
    config['foundation_payload'] = foundation_payload
    return


def adapt(config):
    factory_config = get_config()
    settings = factory_config['settings']
    if config['clusters'] == MAGIC_STR:
        adapt_cluster_ips(config, settings)
    return config


def adapt_stage_2(config):
    """
    Replace all fields containing MAGIC_STR to proper values.
    
    Currently supported fields and order:
      1. profile
      2. nos_package
    
    The "hypervisor" field may contain MAGIC_STR, and it should be overwritten
    after choosing profile.
    """
    factory_config = copy.deepcopy(get_config())
    DEFAULT_LOGGER.debug('Choosing profile for factory')
    profile = choose_profile(config, factory_config)
    DEFAULT_LOGGER.debug('Generate config using profile: %s', profile)
    apply_factory_profile(config, factory_config, profile)
    DEFAULT_LOGGER.debug('Choosing NOS version for factory')
    choose_nos(config, factory_config)
    DEFAULT_LOGGER.debug('Choosing Foundation payload for factory')
    choose_foundation(config, factory_config)
    DEFAULT_LOGGER.debug('Detecting C-SW-REMOVE')
    choose_sw_remove(config, factory_config)
    for key, value in config.iteritems():
        if value == MAGIC_STR:
            raise StandardError('Failed to adapt factory, %s is not adapted' % key)

    return config


def what_is_my_block_id(config):
    block_id, node_serial = config.block_id, config.node_serial
    is_gold_block = RE_GOLD.search(block_id)
    is_gold_node = RE_GOLD.search(node_serial)
    if is_gold_node:
        return
    if not is_gold_block:
        return block_id
    if is_gold_block:
        return node_serial
    return


def get_station_id():
    return socket.gethostname()


def is_ibm():
    """
    Determines if foundation is running on IBM factory
    """
    return get_config().get('factory_type') == FACTORY_IBM