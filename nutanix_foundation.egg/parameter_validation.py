# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/parameter_validation.py
# Compiled at: 2019-02-15 12:42:10
import json, logging, os, re, shutil
from foundation import config_manager
from foundation import features
from foundation import foundation_tools
from foundation import imaging_context
from foundation import iso_checksums
from foundation import iso_whitelist
from foundation import shared_functions
FOUNDATION_IN_NOS_PREFIX = 'install/pkg/nutanix-foundation'
WHITELIST_IN_FOUNDATION_PREFIX = 'foundation/config/iso_whitelist.json'
ISO_NOT_SUPPORTED = 'Hypervisor installer with md5sum %s is not supported'
UPGRADE_NEEDED = 'Foundation needs to be upgraded to version %s or higher to use this installer with md5sum %s'
UPDATE_WHITELIST = 'ISO Whitelist needs to be updated to use this hypervisor installer'
HANDOFF_FAILURE = "Foundation can't use this hypervisor installer because it will fail in handoff"
WHITELIST_EXTRACTION_ERROR = 'Unable to extract whitelist from AOS'
PRE_45_NOT_SUPPORTED = 'CVM-Foundation can not be used to image pre-4.5 AOS releases. Please use Standalone-Foundation for it'
NOS_NOT_SUPPORTED = 'Hypervisor with md5sum %s needs a minimum AOS version of %s. Current AOS version is %s'
logger = logging.getLogger(__file__)

def extract_whitelist_from_nos(nos_path=None):
    """
    Extract the iso_whitelist.json from NOS tarball.
    Args:
      nos_path : Path to the NOS tarball.
    Returns:
      A tuple (dict, foundation_version) where:
        dict: The contents of the whitelist, if successful.
        foundation_version : The version of foundation inside NOS.
      (None, None) on any errors.
    """
    fn = foundation_tools.extract_file_from_compressed_tar
    foundation_in_nos = None
    tmp_dir, pkg_path = fn(nos_path, '.tar.gz', FOUNDATION_IN_NOS_PREFIX)
    if not pkg_path:
        logger.error('Could not find foundation package in %s. Will consider in-memory whitelist only' % nos_path)
        return (None, None)
    tmp_dir_wl, wl_path = fn(pkg_path, '.json', WHITELIST_IN_FOUNDATION_PREFIX)
    if not wl_path:
        logger.error('Could not find iso_whitelist.json in extracted foundation package')
        shutil.rmtree(tmp_dir)
        return (None, None)
    tmp_dir_fv, fv_path = fn(pkg_path, 'version', 'foundation_version')
    if fv_path:
        foundation_in_nos = foundation_tools.read_foundation_version(foundation_version_file=fv_path)
        shutil.rmtree(tmp_dir_fv)
    try:
        with open(wl_path) as (fd):
            in_nos_whitelist = json.load(fd)
        return (in_nos_whitelist, foundation_in_nos)
    except:
        logger.exception('Exception occurred while reading the in_nos whitelist')
        return (None, None)
    finally:
        shutil.rmtree(tmp_dir)
        shutil.rmtree(tmp_dir_wl)

    return


def does_hypervisor_support_nodemodel(md5sum, node_model):
    """
    Checks whether hypervisor with given md5sum supports the node model.
    Args:
      md5sum : md5sum of the hypervisor iso.
      node_model : Model of the node.
    Returns:
      bool- True if the hypervisor iso supports node model or hypervisor iso
            not in whitelist, False otherwise.
    """
    whitelist = iso_whitelist.whitelist['iso_whitelist']
    if md5sum in whitelist:
        for model_regex in whitelist[md5sum].get('unsupported_hardware', []):
            if re.match(model_regex, node_model):
                return False

    return True


def no_handoff_whitelist_check(md5sum, hypervisor_type, nos_version=None):
    """
    Checks the given md5sum in the whitelist in cases of standalone foundation or
    no handoff or hypervisor only imaging.
    Args:
      md5sum : md5sum of the installer.
      hypervisor_type: Hypervisor Type.
      nos_version: NOS version. (optional for hypervisor only imaging)
    Returns:
      Tuple consisting of following:
        bool - True if hypervisor is supported, False otherwise.
        str  - Error info when not supported.
        dict - iso properties from whitelist.
    """
    whitelist = iso_whitelist.whitelist['iso_whitelist']
    if md5sum not in whitelist:
        if hypervisor_type == 'kvm':
            return (True, None, {})
        return (False, ISO_NOT_SUPPORTED % md5sum, {})
    iso_prps = whitelist[md5sum]
    min_nos = iso_prps.get('min_nos', '0.0')
    if nos_version and foundation_tools.compare_version_strings(nos_version, min_nos) == -1:
        return (False, NOS_NOT_SUPPORTED % (md5sum, min_nos, nos_version), iso_prps)
    min_fnd = iso_prps.get('min_foundation', '0.0')
    current_fnd = foundation_tools.get_current_foundation_version()
    if foundation_tools.compare_version_strings(current_fnd, min_fnd) == -1:
        return (False, UPGRADE_NEEDED % (min_fnd, md5sum), iso_prps)
    return (True, None, iso_prps)


def whitelist_check(md5sum, iso_path, hypervisor_type, nos_path=None, need_handoff=False):
    """
    Checks the given md5sum in the whitelist residing in memory
    as well as in the NOS tarball.
    Args:
      md5sum   : The md5sum of the installer.
      iso_path : Path to the installer iso.
      hypervisor_type: Hypervisor type.
      nos_path : Path to the NOS tarball. Optional.
    Returns:
      (True, None) if imaging can proceed.
      (False, str) in case of error, where str is the
                   error string.
    Raises:
      StandardError if whitelist is not found in nos_path.
    Note:
      1. This is crucial to resolve ENG-52449.
      2. On standalone/factory, whitelist in NOS does not matter.
      3. To check compatibility with only the in memory whitelist,
         provide nos_path as None.
    """
    in_memory_whitelist = iso_whitelist.whitelist['iso_whitelist']
    in_memory_whitelist_version = iso_whitelist.whitelist['last_modified']
    logger.debug('in_memory iso_whitelist version: %s' % in_memory_whitelist_version)
    foundation_in_nos = None
    nos_version = None
    if nos_path and os.path.exists(nos_path):
        cm = config_manager.CacheManager
        nos_version = cm.get(shared_functions.get_nos_version_from_tarball, nos_package_path=nos_path)
    if imaging_context.get_context() != imaging_context.FIELD_VM or not nos_path or not os.path.exists(nos_path) or not need_handoff:
        return no_handoff_whitelist_check(md5sum, hypervisor_type, nos_version)[:2]
    if foundation_tools.compare_version_strings(nos_version, '4.5') == -1:
        return (False, PRE_45_NOT_SUPPORTED)
    in_nos_whitelist, foundation_in_nos = cm.get(extract_whitelist_from_nos, nos_path=nos_path)
    if not in_nos_whitelist:
        raise StandardError(WHITELIST_EXTRACTION_ERROR)
    in_nos_whitelist_version = in_nos_whitelist['last_modified']
    in_nos_whitelist = in_nos_whitelist['iso_whitelist']
    current_version = foundation_tools.get_current_foundation_version()
    logger.debug('current foundation version %s' % current_version)
    logger.debug('current whitelist timestamp %s' % in_memory_whitelist_version)
    logger.debug('foundation_in_nos version %s' % foundation_in_nos)
    logger.debug('whitelist_in_nos timestamp %s' % in_nos_whitelist_version)
    if md5sum not in in_memory_whitelist:
        if md5sum not in in_nos_whitelist:
            return (False, ISO_NOT_SUPPORTED % md5sum)
        if in_nos_whitelist_version > in_memory_whitelist_version:
            min_foundation = in_nos_whitelist[md5sum].get('min_foundation', None)
            if current_version and min_foundation and foundation_tools.compare_version_strings(min_foundation, current_version) in (-1,
                                                                                                                                    0):
                return (
                 False, UPDATE_WHITELIST)
            return (
             False, UPGRADE_NEEDED % (min_foundation, md5sum))
        return (
         False, ISO_NOT_SUPPORTED % md5sum)
    logger.debug('Whitelist entry is:\n%s' % json.dumps(in_memory_whitelist[md5sum], indent=2))
    min_nos = in_memory_whitelist[md5sum].get('min_nos', '0.0')
    if foundation_tools.compare_version_strings(nos_version, min_nos) == -1:
        return (False, NOS_NOT_SUPPORTED % (md5sum, min_nos, nos_version))
    min_foundation_version_needed = in_memory_whitelist[md5sum].get('min_foundation', '0.0')
    if min_foundation_version_needed and foundation_tools.compare_version_strings(current_version, min_foundation_version_needed) == -1:
        return (False, UPGRADE_NEEDED % (min_foundation_version_needed, md5sum))
    if md5sum in in_nos_whitelist:
        return (
         True, None)
    if foundation_in_nos and current_version:
        if foundation_tools.compare_version_strings(foundation_in_nos, current_version) in (1,
                                                                                            0):
            if in_memory_whitelist_version <= in_nos_whitelist_version:
                return (
                 False, HANDOFF_FAILURE)
            logger.info('Both local foundation version (%s) and in-NOS foundation version (%s) supports the installer. But in-NOS whitelist version (%s) does not support it. But since in-NOS Foundation version is higher than current one, whitelist upload during handoff will allow it to succeed' % (
             current_version, foundation_in_nos,
             in_nos_whitelist_version))
            return (
             True, None)
        else:
            logger.info('Foundation version (%s) in NOS is older than the local foundation version (%s). Foundation injection will allow handoff to succeed' % (
             foundation_in_nos, current_version))
            return (
             True, None)
    return (False, HANDOFF_FAILURE)


def validate_parameters(global_config):
    global_config.md5sum_hyp_iso = {}
    if getattr(global_config, 'hyp_from_url', False):
        return
    isos = iso_whitelist.whitelist['iso_whitelist']
    node_configs = global_config.nodes
    incoming_hypervisor_iso = global_config.hypervisor_iso
    need_handoff = getattr(global_config, 'need_handoff', False)
    iso_info = ''
    if incoming_hypervisor_iso:
        unnecessary_hyps = []
        for hyp, iso_path in incoming_hypervisor_iso.iteritems():
            if hyp not in [ node.hyp_type for node in node_configs ]:
                unnecessary_hyps.append(hyp)

        for hyp in unnecessary_hyps:
            del incoming_hypervisor_iso[hyp]

        for hyp, iso_path in incoming_hypervisor_iso.iteritems():
            logger.debug('Validating %s: %s', hyp, iso_path)
            kvm_from_nos = not iso_path or foundation_tools.NOS_AHV_BUNDLE_MAGIC in iso_path
            global_config.md5sum_hyp_iso[hyp] = ''
            if not (hyp == 'kvm' and kvm_from_nos):
                md5sum = iso_checksums.get_checksum(iso_path, blocking=True)
            global_config.md5sum_hyp_iso[hyp] = md5sum
            nos_path = None
            if any(map(lambda nc: nc.svm_install_type, global_config.nodes)):
                if getattr(global_config, 'nos_package', None) is None:
                    raise StandardError('AOS package is missing')
                nos_path = global_config.nos_package
            if global_config.hypervisor_checksum.get(hyp) is not None:
                if global_config.hypervisor_checksum[hyp] == md5sum:
                    logger.debug('Unsupported ISO passed integrity check')
                    continue
                else:
                    raise StandardError("Input MD5 checksum for ISO, %s, didn't match the one computed on the server! Try reuploading and recheck checksum with supplier." % os.path.basename(iso_path))
            else:
                logger.debug('Starting whitelist_check')
                ret, msg = whitelist_check(md5sum, iso_path, hyp, nos_path=nos_path, need_handoff=need_handoff)
                logger.debug('Finished whitelist_check')
                if not ret:
                    if features.is_enabled(features.QA_SKIP_WHITELIST_ONCE):
                        logger.warn('This ISO is NOT supported, but skipping whitelist check this time for QA-test only')
                        return
                    if hyp != 'kvm':
                        raise StandardError(msg)
                if hyp == 'kvm':
                    logger.warn("It's recommended to use AHV bundled with AOS.")
                    if md5sum not in isos:
                        continue
            if hyp == 'hyperv':
                iso_info = isos[md5sum]
            try:
                info = isos[md5sum]
            except KeyError:
                raise StandardError('Unsupported Hypervisor Installer: %s' % str(iso_path))
            else:
                session_id = global_config._session_id
                foundation_tools.update_metadata({'iso_entry': info}, session_id)
                deprecated_version = info.get('deprecated', None)
                min_version = info.get('min_foundation', None)
                loc_version = foundation_tools.get_current_foundation_version()
                if min_version and loc_version and foundation_tools.compare_version_strings(min_version, loc_version) == 1:
                    message = "The current version of Foundation '%s' is less than the minimum required version '%s' to use this hypervisor installer" % (
                     loc_version, min_version)
                    raise StandardError(message)
                if deprecated_version:
                    if not loc_version or foundation_tools.compare_version_strings(loc_version, deprecated_version) in (0,
                                                                                                                        1):
                        raise StandardError('A deprecated version of %s installer is provided. This installer has been deprecated from Foundation %s onwards' % (
                         hyp, deprecated_version))

    if 'hyperv' in incoming_hypervisor_iso:
        for node in node_configs:
            if node.hyp_type == 'hyperv':
                if not iso_info:
                    logger.info('User is using hyperv ISO which is not in whitelist. Skipping SKU check against whitelist')
                    continue
                sku_list = iso_info['skus']
                selected_sku = getattr(node, 'hyperv_sku', None)
                if not selected_sku:
                    raise StandardError('A SKU must be specified for Hyper-V')
                selected_sku = selected_sku.lower()
                if selected_sku not in sku_list:
                    message = 'Selected SKU %s is not in the iso you uploaded. This iso contains SKUs %s. Please consult the Field Install Guide for a list of supported ISOs and the SKUs available in each.' % (
                     selected_sku, sku_list)
                    raise StandardError(message)

    nodes_image_now = [ cfg for cfg in node_configs if cfg.image_now ]
    if any((cfg.svm_install_type for cfg in nodes_image_now)):
        nos_package = global_config.nos_package
        if not nos_package:
            raise StandardError('AHV package not provided')
        if not os.path.exists(nos_package):
            raise StandardError('AHV not found in %s' % nos_package)
    return