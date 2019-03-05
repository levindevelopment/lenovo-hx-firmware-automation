# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_context.py
# Compiled at: 2019-02-15 12:42:10
import os, folder_central
from foundation import features
FIELD_VM = 'cvm'
FIELD_IPMI = 'ipmi'
FACTORY = 'factory'
VALID_CONTEXTS = [FIELD_VM, FIELD_IPMI, FACTORY]
features._all_features.extend(VALID_CONTEXTS)
_context = None

def get_context():
    global _context
    return _context


def set_context(value):
    global _context
    assert value in VALID_CONTEXTS
    _context = value
    for ctx in VALID_CONTEXTS:
        if ctx != value:
            features.disable(ctx)
        else:
            features.enable(ctx)


def _is_in_factory():
    return os.path.exists(folder_central.get_factory_settings_path())


def _is_in_cvm():
    return os.path.exists(folder_central.get_svm_version_path())


def _detect_context():
    if _is_in_cvm():
        return FIELD_VM
    if _is_in_factory():
        return FACTORY
    return FIELD_IPMI


set_context(_detect_context())