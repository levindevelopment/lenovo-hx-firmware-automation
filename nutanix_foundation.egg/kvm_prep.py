# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/kvm_prep.py
# Compiled at: 2019-02-15 12:42:10
import os, sys, foundation.folder_central as folder_central
from foundation.shared_functions import prepare_kvm_from_rpms

def generate_kvm_iso(kvm_rpm, workspace, logger):
    if not kvm_rpm:
        logger.error('Must specify kvm rpm tarball via --kvm argument')
        sys.exit(1)
    kvm_rpm = os.path.expanduser(kvm_rpm)
    kvm_rpm = os.path.realpath(kvm_rpm)
    if not os.path.exists(kvm_rpm):
        logger.error("Provided kvm tarball doesn't exist at %s" % kvm_rpm)
        sys.exit(1)
    anaconda_tarball = folder_central.get_anaconda_tarball()
    output_dir = workspace or os.getcwd()
    kvm_iso_path = os.path.join(output_dir, 'kvm.iso')
    prepare_kvm_from_rpms(anaconda_tarball, kvm_iso_path, kvm_rpm_pkg=kvm_rpm, workspace=workspace)
    logger.info('KVM generated in %s' % kvm_iso_path)
    return kvm_iso_path