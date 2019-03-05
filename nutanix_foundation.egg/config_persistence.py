# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/config_persistence.py
# Compiled at: 2019-02-15 12:42:10
import copy, json, logging, os, tempfile, threading
from foundation import factory_mode
from foundation import folder_central
from foundation import imaging_context
logger = logging.getLogger(__file__)
persistence_lock = threading.RLock()
is_in_factory = factory_mode.factory_mode()

def clear_keys(data, keys_to_fix):

    def fix_data(data_to_fix, keys_to_fix):
        if isinstance(data_to_fix, dict):
            for key, value in data_to_fix.iteritems():
                if key in keys_to_fix:
                    data_to_fix[key] = ''
                else:
                    data_to_fix[key] = fix_data(value, keys_to_fix)

            return data_to_fix
        if isinstance(data_to_fix, list):
            return [ fix_data(x, keys_to_fix) for x in data_to_fix ]
        return data_to_fix

    new_data = copy.deepcopy(data)
    return fix_data(new_data, keys_to_fix)


def persist_config(config):
    with persistence_lock:
        if imaging_context.get_context() != imaging_context.FACTORY:
            config = clear_keys(config, ['ipmi_password'])
        path = folder_central.get_persisted_config_path()
        tmp_path = path + '.tmp'
        with open(tmp_path, 'w') as (f):
            f.write(json.dumps(config, indent=2))
        if os.path.exists(path):
            os.unlink(path)
        os.rename(tmp_path, path)
        path = folder_central.get_persisted_config_path(root_path=True)
        with open(path, 'w') as (f):
            json.dump(config, f, indent=2)


def persist_discovery_info(discovered_nodes, session_id=None):
    path = folder_central.get_discovery_info_path(session_id)
    with tempfile.NamedTemporaryFile(prefix=path, delete=False) as (tmp_f):
        tmp_f.write(json.dumps(discovered_nodes, indent=2))
    os.rename(tmp_f.name, path)


def get_persisted_config(session_id=None):
    with persistence_lock:
        path = folder_central.get_persisted_config_path(session_id=session_id)
        if not os.path.exists(path):
            return {}
        with open(path) as (f):
            text = f.read()
    return json.loads(text)


def post_imaging_result(node_id, result):
    with persistence_lock:
        config = get_persisted_config()
        if 'blocks' not in config:
            return
        blocks = config['blocks']
        for block in blocks:
            nodes = block['nodes']
            for node in nodes:
                if node_id in [node.get('cvm_ip'), node.get('hypervisor_ip')]:
                    node['image_successful'] = result
                    if result:
                        if is_in_factory:
                            logger.debug('FACTORY: Skip toggling image_now')
                        else:
                            node['image_now'] = False
                    persist_config(config)
                    return


def post_cluster_action_result(action, cvm_ip, result):
    assert action in ('init', 'destroy'), "action is one of 'init' or 'destroy'."
    with persistence_lock:
        config = get_persisted_config()
        clusters = config.get('clusters', {})
        for cluster in clusters:
            if cvm_ip in cluster['cluster_members']:
                cluster['cluster_%s_successful' % action] = result
                if result:
                    if is_in_factory:
                        logger.debug('FACTORY: Skip toggling cluster_%s_now', action)
                    else:
                        cluster['cluster_%s_now' % action] = False

        persist_config(config)


def post_cluster_init_result(cvm_ip, result):
    post_cluster_action_result('init', cvm_ip, result)


def post_cluster_destroy_result(cvm_ip, result):
    post_cluster_action_result('destroy', cvm_ip, result)


def fail_all_remaining_work():
    """
    Go through json structure and flag all pending work as failed.
    """
    with persistence_lock:
        config = get_persisted_config()
        clusters = config.get('clusters', {})
        for cluster in clusters:
            if cluster.get('cluster_init_now', False) and cluster.get('cluster_init_successful', None) == None:
                cluster['cluster_init_successful'] = False
            if cluster.get('cluster_destroy_now', False) and cluster.get('cluster_destroy_successful', None) == None:
                cluster['cluster_destroy_successful'] = False

        blocks = config.get('blocks', {})
        for block in blocks:
            nodes = block['nodes']
            for node in nodes:
                if node.get('ipmi_configure_now', False):
                    if node.get('ipmi_configure_successful', None) == None:
                        node['ipmi_configure_successful'] = False
                if node.get('image_now', False):
                    if node.get('image_successful', None) == None:
                        node['image_successful'] = False

        persist_config(config)
    return