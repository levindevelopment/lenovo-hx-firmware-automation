# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/foundation_aliases.py
# Compiled at: 2019-02-15 12:42:10
ALIAS_MAP = [
 ('cvm_num_vcpus', 'svm_num_vcpus'),
 ('cvm_gb_ram', 'svm_gb_ram'),
 ('cvm_netmask', 'svm_subnet_mask'),
 ('cvm_gateway', 'svm_default_gw'),
 ('cvm_ip', 'svm_ip'),
 ('hypervisor_ntp_servers', 'per_node_ntp_servers'),
 ('hypervisor_iso', 'hyp_iso')]

def fix_aliases(node_config):
    for name1, name2 in ALIAS_MAP:
        if getattr(node_config, name1, None):
            setattr(node_config, name2, getattr(node_config, name1))

    return