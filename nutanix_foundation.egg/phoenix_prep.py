# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/phoenix_prep.py
# Compiled at: 2019-02-15 12:42:10
import glob, json, logging, os, platform, shutil, string, tempfile
from threading import Lock
import features, folder_central, foundation_aliases, foundation_tools as tools, imaging_context
from config_manager import CacheManager
from shared_functions import AUTOMATION_FRAMEWORK_KEY, get_nos_version_from_tarball
from foundation.consts import ARCH_X86
from config_persistence import clear_keys
BASE_FILES_SETUP_LOCK = Lock()
logger = logging.getLogger(__file__)

def generate_foundation_payload_if_necessary(nos_package_path):
    """
    
    Args:
      nos_package_path: Path to the nos_package.
    
    Returns:
      path to foundation tar if one needed to be made.
    
    """
    if imaging_context.get_context() != imaging_context.FIELD_VM or not nos_package_path:
        return
    if platform.system() != 'Linux':
        logger.warn('skipping generate_foundation_payload_if_necessary for this platform')
        return
    foundation_version_in_nos = tools.get_foundation_pkg_version_from_nos_tar(nos_package_path)
    current_version = tools.get_current_foundation_version()
    if not foundation_version_in_nos or tools.newer_than_target_version(foundation_version_in_nos):
        logger.info('Foundation version in NOS is %s, will patch it with %s' % (
         foundation_version_in_nos, current_version))
        foundation_tar_path = tools.get_foundation_tar(['kvm'])
        tools.system(None, ['gzip', '-f', foundation_tar_path])
        foundation_tar_path += '.gz'
        return foundation_tar_path
    return


def gunzip_nos(nos_package_path):
    nos_package_path = os.path.realpath(nos_package_path)
    if nos_package_path.endswith('.gz'):
        if os.path.exists(nos_package_path):
            logger.info('Unzipping NOS package')
            try:
                tools.system(None, ['gzip', '-d', '-f', nos_package_path])
            except StandardError as e:
                msg = 'The file at %s is not a valid NOS package in gzip format, or you are out of disk space: %s' % (
                 nos_package_path, e)
                raise StandardError(msg)

            logger.info('Done unzipping NOS package')
        else:
            if not os.path.exists(nos_package_path[:-3]):
                raise StandardError('Neither the NOS package path %s nor its extraction %s exist. Did you specify the right NOS package ?' % (
                 nos_package_path, nos_package_path[:-3]))
        nos_package_path = nos_package_path[:-3]
    return nos_package_path


def prep_image(node_config):
    """
    Gunzip NOS package if it's in gzip format and read nos version.
    
    prep_image is called in two forms:
        init_ipmi : calls it once for every node
        init_cvm  : calls it once for every cluster
    In IPMI mode, the concurrent invocations of prep_image are
    protected via prepare_and_make_iso, making them serialized.
    """
    with BASE_FILES_SETUP_LOCK:
        nos_package = node_config.nos_package
        if nos_package:
            node_config.nos_package = gunzip_nos(nos_package)
            return CacheManager.get(get_nos_version_from_tarball, node_config.nos_package)


def _update_hcl(updates_dir):
    """
    Inject possibly newer hcl in phoenix image.
    """
    hcl_src = folder_central.get_hcl_path()
    hcl_target = os.path.join(updates_dir, 'hcl.json')
    if os.path.exists(hcl_target):
        os.unlink(hcl_target)
    shutil.copyfile(hcl_src, hcl_target)


def _copy_phoenix_override(updates_dir):
    """
    Inject optional Phoenix override package.
    """
    src = folder_central.get_phoenix_override_path()
    dest = os.path.join(updates_dir, 'phoenix_override.tar.gz')
    if os.path.exists(src):
        logger.info('Using phoenix override from %s' % src)
        shutil.copyfile(src, dest)


def _copy_features_json(updates_dir):
    """
    Inject optional features.json to phoenix.
    """
    features_json = os.path.join(updates_dir, 'features.json')
    features_dump = features.all()
    for key in imaging_context.VALID_CONTEXTS:
        del features_dump[key]

    with open(features_json, 'w') as (fp):
        json.dump(features_dump, fp)


def create_phoenix_updates_dir(phoenix_iso_dir):
    updates_dir = os.path.join(phoenix_iso_dir, 'updates')
    os.mkdir(updates_dir)
    _update_hcl(updates_dir)
    _copy_phoenix_override(updates_dir)
    _copy_features_json(updates_dir)


def create_phoenix_components_dir(phoenix_iso_dir):
    foundation_components_dir = folder_central.get_components_folder()
    if os.path.exists(foundation_components_dir):
        components_dir = os.path.join(phoenix_iso_dir, 'components')
        shutil.copytree(foundation_components_dir, components_dir)


def make_phoenix_for_node(node_config):
    """
      Create bootable phoenix iso for a node.
    
      Copy kernel and initrd, render boot.cfg template and mkisofs
    """
    from foundation.http_server import FileServer, HTTP_PORT
    node_id = node_config.node_id
    foundation_ip = node_config.foundation_ip
    session_files_dir = folder_central.get_http_files_folder()
    phoenix_src_dir = folder_central.get_phoenix_dir(arch=node_config.arch)
    iso = os.path.join(folder_central.get_phoenix_node_isos_folder(), 'foundation.node_%s.iso' % node_id)
    phoenix_iso_dir = tempfile.mkdtemp('phoenix_iso_%s' % node_id)
    shutil.rmtree(phoenix_iso_dir)
    shutil.copytree(phoenix_src_dir, phoenix_iso_dir)
    livecd_tar_path = os.path.join(phoenix_iso_dir, 'livecd.tar')
    if os.path.exists(livecd_tar_path):
        os.unlink(livecd_tar_path)
    squashfs_img_path = os.path.join(phoenix_iso_dir, 'squashfs.img')
    if os.path.exists(squashfs_img_path):
        os.remove(squashfs_img_path)
    create_phoenix_updates_dir(phoenix_iso_dir)
    if any([ features.is_enabled(feature) for feature in features.get_phoenix_pluggable_components()
           ]):
        create_phoenix_components_dir(phoenix_iso_dir)
    templates = folder_central.get_templates_folder()
    if node_config.arch == ARCH_X86:
        menu_paths = [
         (
          templates + '/isolinux.cfg', 'boot/isolinux/isolinux.cfg'),
         (
          templates + '/grub_efi.cfg', 'boot/EFI/BOOT/grub.cfg')]
    else:
        menu_paths = [
         (
          templates + '/grub_ppc64le.cfg', 'grub.cfg')]
    arizona_file_name = 'arizona.node_%s.json' % node_id
    arizona_file_name = os.path.join(session_files_dir, arizona_file_name)
    arizona_url = 'http://%s:%s/%s' % (node_config.foundation_ip, HTTP_PORT,
     FileServer.add_file(arizona_file_name))
    if features.is_enabled(features.CENTOS):
        type_img = 'squashfs'
    else:
        type_img = 'gentoo'
    live_cd_path = folder_central.get_livecd_path(type_img, node_config.arch)
    for source, dest in menu_paths:
        with open(source) as (template_menu):
            text = template_menu.read()
        phoenix_bond_mode = ''
        bond_lacp_rate = ''
        bond_mode = getattr(node_config, 'bond_mode', '')
        if bond_mode == 'static':
            phoenix_bond_mode = 0
        else:
            if bond_mode == 'dynamic':
                phoenix_bond_mode = 4
                bond_lacp_rate = node_config.bond_lacp_rate
                if bond_lacp_rate == 'slow':
                    bond_lacp_rate = 0
                else:
                    bond_lacp_rate = 1
        text = string.Template(text).substitute(foundation_ip=foundation_ip, foundation_port=HTTP_PORT, az_conf_url=arizona_url, livefs_url=FileServer.make_url_and_hash(live_cd_path, node_config)['url'], phoenix_ip=node_config.phoenix_ip, phoenix_netmask=node_config.phoenix_netmask, phoenix_gw=node_config.phoenix_gateway, vlan_id=getattr(node_config, 'cvm_vlan_id', ''), boot_script='rescue_shell', session=node_config._session_id, bond_mode=phoenix_bond_mode, bond_uplinks=(',').join(getattr(node_config, 'bond_uplinks', [])), bond_lacp_rate=bond_lacp_rate, type_img=type_img)
        with open('%s/%s' % (phoenix_iso_dir, dest), 'w') as (menu_fd):
            menu_fd.write(text)

    mkisofs = folder_central.get_mkisofs_path()
    if node_config.arch == ARCH_X86:
        iso_cmd = [mkisofs, '-q', '-R', '-V', 'PHOENIX',
         '-no-emul-boot', '-boot-load-size', '4',
         '-boot-info-table', '-joliet-long',
         '-b', 'boot/isolinux/isolinux.bin',
         '-uid', '0', '-gid', '0']
        if platform.system() == 'Linux':
            iso_cmd.extend([
             '-eltorito-alt-boot',
             '-e', 'boot/images/efiboot.img',
             '-allow-limited-size',
             '-no-emul-boot'])
        if platform.system() == 'Darwin':
            iso_cmd[1] = '-quiet'
        iso_cmd.extend(['-o', iso, phoenix_iso_dir])
    else:
        iso_cmd = [
         mkisofs, '-q', '-R', '-V', 'PHOENIX', '-o', iso,
         phoenix_iso_dir]
    tools.system(node_config, iso_cmd)
    node_config.phoenix_iso = iso
    shutil.rmtree(phoenix_iso_dir)


def make_json_for_node(node_config):
    """
      Create arizona.json config for Phoenix.
    """
    from foundation.http_server import FileServer, HTTP_PORT
    foundation_ip = node_config.foundation_ip
    session_files_dir = folder_central.get_http_files_folder()
    foundation_aliases.fix_aliases(node_config)
    params = dict(map(lambda k: (k, getattr(node_config, k)), node_config.keys()))
    un_serializable_keys = []
    for key in params:
        try:
            json.dumps({1: getattr(node_config, key)})
        except TypeError:
            un_serializable_keys.append(key)

    logging.debug('Skipping non serializable keys: %s', un_serializable_keys)
    for key in un_serializable_keys:
        del params[key]

    params = clear_keys(params, ['ipmi_password'])
    automation = getattr(node_config, AUTOMATION_FRAMEWORK_KEY, {})
    co_kvm_from_nos = getattr(node_config, 'compute_only', False) and getattr(node_config, 'kvm_from_nos', False)
    if node_config.svm_install_type or co_kvm_from_nos:
        nos_package = node_config.nos_package
        if 'svm_installer_url' in automation:
            params['svm_installer_url'] = {'url': automation['svm_installer_url'], 'md5sum': ''}
        else:
            params['svm_installer_url'] = FileServer.make_url_and_hash(nos_package, node_config)
    hyp_iso = node_config.incoming_hypervisor_iso
    hyp_type = node_config.hyp_type
    node_id = node_config.node_id
    if getattr(node_config, 'foundation_payload', None):
        foundation_payload = node_config.foundation_payload
        params['foundation_payload_url'] = FileServer.make_url_and_hash(foundation_payload, node_config)
    if hyp_iso and hyp_iso.get(hyp_type):
        hyp_path = hyp_iso[hyp_type]
        params['hypervisor_iso'] = os.path.basename(hyp_path)
        if 'hypervisor_iso_url' in automation:
            params['hypervisor_iso_url'] = {'url': automation['hypervisor_iso_url'], 'md5sum': ''}
            if hyp_type == 'kvm' and 'storage_node_iso_url' in automation:
                params['hypervisor_iso_url'] = {'url': automation['storage_node_iso_url'], 'md5sum': ''}
        else:
            params['hypervisor_iso_url'] = FileServer.make_url_and_hash(hyp_path, node_config)
    if 'hypervisor_ip' in params:
        params['host_ip'] = params['hypervisor_ip']
        params['host_subnet_mask'] = params['hypervisor_netmask']
        params['default_gw'] = params['hypervisor_gateway']
        params['dns_ip'] = params.get('hypervisor_nameserver', None)
    params['foundation_node_id'] = '%s' % node_id
    params['monitoring_url_root'] = 'http://%s:%d/foundation/log?session_id=%s&node_id=%s' % (
     foundation_ip, HTTP_PORT, node_config._session_id, node_id)
    params['foundation_ip'] = foundation_ip
    if node_config.hyp_type == 'esx':
        vibs_path = os.path.join(folder_central.get_driver_dir('esx'), 'vibs')
        vibs_path_glob = vibs_path + '/*/*'
        paths = glob.glob(vibs_path_glob)
        print paths
        params['vib_urls_list'] = map(lambda path: FileServer.make_url_and_hash(path, node_config), paths)
    if node_config.hyp_type == 'linux':
        ks_path = os.path.join(session_files_dir, 'linux_kickstart')
        with open(ks_path, 'w') as (fd):
            fd.write(node_config.linux_kickstart)
        params['linux_kickstart'] = FileServer.make_url_and_hash(ks_path, node_config)['url']
    if node_config.hyp_type == 'hyperv':
        params['hyperv_binaries_url'] = FileServer.make_url_and_hash(folder_central.get_driver_dir('hyperv/hyperv_binaries.zip'), node_config)
    if node_config.hyp_type == 'kvm':
        if node_config.arch == ARCH_X86:
            if 'anaconda_tarball_url' in automation:
                params['anaconda_tarball_url'] = {'url': automation['anaconda_tarball_url'], 'md5sum': ''}
            else:
                params['anaconda_tarball_url'] = FileServer.make_url_and_hash(folder_central.get_anaconda_tarball(), node_config)
        paths = glob.glob(folder_central.get_driver_dir('kvm/rpms') + '/*')
        params['rpm_urls_list'] = map(lambda path: FileServer.make_url_and_hash(path, node_config), paths)
    if node_config.hyp_type == 'xen':
        xen_package = folder_central.get_driver_dir('xen/xen_package.tar.gz')
        params['xen_package_url'] = FileServer.make_url_and_hash(xen_package, node_config)
    params['foundation_version'] = tools.get_current_foundation_version() or 'developer-environment'
    if node_config.hyp_type == 'kvm' and node_config.hardware_config:
        hardware_attrs = node_config.hardware_config['node'].get('hardware_attributes', {})
        vswitch_nics = hardware_attrs.get('vswitch_nics')
        if vswitch_nics:
            vswitches = getattr(node_config, 'vswitches', None)
            if not vswitches:
                params['vswitches'] = [
                 {'name': 'br0', 'uplinks': vswitch_nics, 
                    'bond_mode': 'active-backup'}]
            else:
                for vswitch in vswitches:
                    if not vswitch.get('uplinks'):
                        vswitch['uplinks'] = vswitch_nics

                params['vswitches'] = vswitches
    if features.is_enabled(features.HARDWARE_QUAL):
        params['patch_hcl'] = True
    arizona_file_name = 'arizona.node_%s.json' % node_id
    arizona_file_name = os.path.join(session_files_dir, arizona_file_name)
    with open(arizona_file_name, 'w') as (fp):
        json.dump(params, fp, indent=4)
    node_config.arizona_loc = FileServer.make_url_and_hash(arizona_file_name, node_config)['url']
    return