# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/features.py
# Compiled at: 2019-02-15 12:42:10
import os, json, warnings
CUSTOMER_PROVIDED_HYPERVISOR = 'customer_provided_hypervisor'
LINUX_INSTALLATION = 'linux_installation'
XEN = 'xen'
BACKPLANE_NETWORK = 'backplane_network'
QA_SKIP_WHITELIST_ONCE = 'QA_SKIP_WHITELIST_ONCE'
UEFI_SUPPORT = 'uefi_support'
CENTOS = 'centos_phoenix'
COMPUTE_ONLY = 'compute_only'
FOUNDATION_CENTRAL = 'foundation_central'
MULTIHOMING_VLAN = 'multihoming_vlan'
PORTABLE_WIN = 'portable_win'
PORTABLE_MAC = 'portable_mac'
HARDWARE_QUAL = 'hardware_qualification'
HFCL_CHECKER = 'hfcl_checker'
AURORA = 'aurora'
TARTARUS = 'tartarus'
_all_features = [
 CUSTOMER_PROVIDED_HYPERVISOR, LINUX_INSTALLATION, XEN,
 BACKPLANE_NETWORK, QA_SKIP_WHITELIST_ONCE, HARDWARE_QUAL,
 UEFI_SUPPORT, COMPUTE_ONLY, FOUNDATION_CENTRAL, CENTOS,
 MULTIHOMING_VLAN, PORTABLE_MAC, PORTABLE_WIN, AURORA,
 HFCL_CHECKER, TARTARUS]
_enabled_features = [
 XEN, LINUX_INSTALLATION, BACKPLANE_NETWORK, CENTOS,
 MULTIHOMING_VLAN, FOUNDATION_CENTRAL]
sub_features_map = {HARDWARE_QUAL: [
                 AURORA, TARTARUS], 
   HFCL_CHECKER: [
                AURORA, TARTARUS], 
   AURORA: [
          TARTARUS]}
_phoenix_pluggable_components = [
 AURORA, TARTARUS]

def all():
    return dict([ (f, f in _enabled_features) for f in _all_features ])


def get_phoenix_pluggable_components():
    """
    Returns features related to phoenix pluggable components
    """
    return _phoenix_pluggable_components


def is_enabled(feature_name):
    return feature_name in _enabled_features


def enable(feature_name):
    if feature_name not in _all_features:
        raise StandardError("Unknown feature '%s'" % feature_name)
    map(enable, sub_features_map.get(feature_name, []))
    _enabled_features.append(feature_name)


def disable(feature_name):
    if feature_name in _enabled_features:
        _enabled_features.remove(feature_name)


def load_features_from_json(features_path):
    if os.path.isfile(features_path):
        with open(features_path) as (fd):
            try:
                features = json.load(fd)
            except ValueError as e:
                print 'malformed features.json', e
                raise

            assert isinstance(features, (list, dict)), 'features must be in a dict format, was: %s' % features
            if type(features) == list:
                features = dict(zip(features, [True] * len(features)))
            for feature, value in features.items():
                if value:
                    warnings.warn('enabling feature: %s' % feature, RuntimeWarning)
                    enable(feature)
                else:
                    warnings.warn('disabling feature: %s' % feature, RuntimeWarning)
                    disable(feature)


try:
    from foundation.portable import is_portable, is_win, is_mac
    if is_portable():
        disable(MULTIHOMING_VLAN)
        if is_win():
            enable(PORTABLE_WIN)
        elif is_mac():
            enable(PORTABLE_MAC)
except ImportError:
    pass