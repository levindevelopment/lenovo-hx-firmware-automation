# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/ndp_client.py
# Compiled at: 2019-02-15 12:42:10
import json, platform, select, socket, time, traceback
NDP_PORT = 13000
NDP_VERSION = 1
REPEAT_COUNT = 6
REPEAT_WAIT_MS = 500
IPV6_BROADCAST_ADDRESS = 'ff02::1'
INTERFACE = 'eth0'
RCVBUF = 4194304
if platform.system() == 'Darwin':
    RCVBUF = 1048576
__is_unit_test = False
ndp_legacy_attributes = [
 'rackable_unit_serial',
 'rackable_unit_model',
 'node_uuid',
 'node_position',
 'svm_ip',
 'configured',
 'cluster_id']
ndp_new_attributes = [
 'foundation_version',
 'hypervisor',
 'hypervisor_version',
 'nos_version',
 'attributes',
 'chassis_n',
 'current_network_interface',
 'current_cvm_vlan_tag',
 'ipmi_mac']

def set_unit_test():
    global REPEAT_COUNT
    global __is_unit_test
    __is_unit_test = True
    REPEAT_COUNT = 2


def filter_list(nodes=None, key=None, target_list=None):
    if nodes is None:
        nodes = []
    if target_list is None:
        target_list = []
    if not nodes or not key or not target_list:
        return nodes
    filtered_list = []
    for node in nodes:
        if node[key] in target_list:
            filtered_list.append(node)

    return filtered_list


def enumerate_peers(address_type='IPv4', ip_filter_list=None, uuid_filter_list=None, interface_filter_list=None, interface=None):
    """
    Returns list of discovered peer nodes. Uses ipv6 broadcast.
    
    Throws on error.
    """
    global REPEAT_WAIT_MS
    interface = interface or INTERFACE
    if ip_filter_list is None:
        ip_filter_list = []
    if uuid_filter_list is None:
        uuid_filter_list = []
    if interface_filter_list is None:
        interface_filter_list = []
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF)
    if __is_unit_test:
        targets = socket.getaddrinfo('::1', NDP_PORT, socket.AF_INET6, socket.SOCK_DGRAM)
    else:
        targets = socket.getaddrinfo('%s%%%s' % (IPV6_BROADCAST_ADDRESS, interface), NDP_PORT, socket.AF_INET6, socket.SOCK_DGRAM)
    query = {'protocol': 'NDP', 
       'version': NDP_VERSION, 
       'type': 'discovery_request'}
    query = json.dumps(query)
    responses = {}
    for _ in range(REPEAT_COUNT):
        for target in targets:
            _, _, _, _, address = target
            sock.sendto(query, address)

        start_time = time.time()
        while True:
            now = time.time()
            dtime = now - start_time
            if dtime >= REPEAT_WAIT_MS / 1000.0:
                break
            remain_s = REPEAT_WAIT_MS / 1000.0 - dtime
            rlist, _, elist = select.select([sock], [], [sock], remain_s)
            if elist:
                raise StandardError('Unexpected error in NDP select')
            if rlist:
                json_string, address = sock.recvfrom(10000)
                responses[address] = json_string

    sock.close()
    results = []
    for address, json_test in responses.iteritems():
        try:
            data = json.loads(json_test)
            info = {}
            info['ipv6_address'] = address[0]
            for attr in ndp_legacy_attributes:
                info[attr] = data.get(attr, None)

            if not __is_unit_test:
                for attr in ndp_new_attributes:
                    info[attr] = data.get(attr, None)

            results.append(info)
        except:
            traceback.print_exc()

    if ip_filter_list:
        key = 'svm_ip' if address_type == 'IPv4' else 'ipv6_address'
        results = filter_list(results, key, ip_filter_list)
    if uuid_filter_list:
        results = filter_list(results, 'node_uuid', uuid_filter_list)
    if interface_filter_list:
        filtered_list = []
        for node in results:
            _, netif = node['ipv6_address'].split('%')
            if netif in interface_filter_list:
                filtered_list.append(node)

        return filtered_list
    return results


def discover_all_nodes(address_type, ip_filter_list=None, uuid_filter_list=None, interface_filter_list=None, interface=None):
    """
    API for Unified Node Discovery as described in
    https://goo.gl/FyZ5K9
    
    Returns a dict in the following format containing unconfigured
    as well as configured nodes, discovered through mDNS and NDP:
      [
        {"block_id": <block name>,
         "model": <model>,
         "chassis_n": <int, capacity of the chassis in nodes, empty if not all
                      nodes agree on the value>,
         "nodes": [
           {
             "ipv6_address": <ipv6 address>,
             "node_position": <node position>,
             "node_uuid": <node uuid>,
             "model": <model>,
             "configured": boolean,
             "foundation_version": <string of form "x.y.z">,
             "nos_version": <string of form x.y.z>,
             "hypervisor": <one of "esx", "hyperv", "kvm", or "null">,
             "hypervisor_version": <string, format per-hypervisor>,
             "attributes":
               { # optional
                 <name>: <value>
               },
           },
           . . . <more nodes>
        ]
        . . . <more blocks>
      ]
    """
    interface_filter_list = interface_filter_list
    discovered_blocks = []
    ndp_discovered_nodes = []
    ndp_discovered_nodes = enumerate_peers(address_type=address_type, ip_filter_list=ip_filter_list, uuid_filter_list=uuid_filter_list, interface_filter_list=interface_filter_list, interface=interface)
    for node in ndp_discovered_nodes:
        this_block = None
        for block in discovered_blocks:
            if block['block_id'] == node['rackable_unit_serial']:
                this_block = block
                break
        else:
            new_block = {'block_id': node['rackable_unit_serial'], 
               'model': node['rackable_unit_model'], 
               'chassis_n': node.get('chassis_n', None), 
               'nodes': []}
            this_block = new_block
            discovered_blocks.append(new_block)

        for extant_node in this_block['nodes']:
            if node['ipv6_address'] == extant_node['ipv6_address']:
                break
            if node['node_position'] == extant_node['node_position']:
                if node.get('current_network_interface') == 'eth0':
                    extant_node['current_network_interface'] = 'eth0'
                    extant_node['ipv6_address'] = node.get('ipv6_address')
                    extant_node['current_cvm_vlan_tag'] = node.get('current_cvm_vlan_tag')
                break
        else:
            new_node = {}
            legacy_attributes = [
             'ipv6_address', 'node_position',
             'configured', 'node_uuid', 'svm_ip', 'cluster_id']
            new_attributes = [
             'foundation_version', 'nos_version',
             'hypervisor', 'hypervisor_version',
             'attributes', 'current_network_interface',
             'current_cvm_vlan_tag', 'ipmi_mac']
            for attr in legacy_attributes + new_attributes:
                new_node[attr] = node.get(attr)

            if not node.get('chassis_n', None) == this_block['chassis_n']:
                this_block['chassis_n'] = None
            new_node['model'] = node['rackable_unit_model']
            if new_node['model'] == 'USE_LAYOUT' and node.get('model_string'):
                new_node['model'] = node.get('model_string')
            this_block['nodes'].append(new_node)

    for block in discovered_blocks:
        models = set()
        for node in block['nodes']:
            models.add(node['model'])

        if len(models) > 1:
            block['model'] = 'mixed'

    return discovered_blocks


if __name__ == '__main__':
    import pprint
    pprint.pprint(discover_all_nodes(interface_filter_list=[]))