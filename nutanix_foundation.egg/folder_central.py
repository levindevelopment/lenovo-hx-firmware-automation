# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/folder_central.py
# Compiled at: 2019-02-15 12:42:10
import os, platform, re, sys, threading
from foundation.consts import ARCH_PPC, ARCH_X86
folder_lock = threading.Lock()
NTNXLOGDIR = 'NUTANIX_LOG_DIR'
CVM_PATH_RE = re.compile('(.*/foundation/)lib/py/.*\\.egg/foundation')
REPO_PATH_RE = re.compile('(.*/foundation/)py/foundation')
REPO_PATH_RE2 = re.compile('(.*\\\\foundation\\\\)py\\\\foundation')
PERSISTED_CONFIG_NAME = 'persisted_config.json'
STATES_REACHED_NAME = 'states_reached.json'
SESSIONS_FOLDER_NAME = 'sessions'
CACHE_FOLDER_NAME = 'cache'

def get_current_session(session_id, raise_on_empty=True):
    """
    Gets the current session id from input or from the thread.
    Args:
      session_id: Id of the current session.
      raise_on_empty: If True, an error will be raised if session id cannot be
          determined.
    Raises:
      Raises StandardError if session id cannot be determined.
    Returns:
      Current session id.
    """
    from foundation import session_manager
    session_id = session_id or session_manager.get_session_id()
    if session_id is None and raise_on_empty:
        raise StandardError("Couldn't figure out the imaging session id")
    return session_id


def get_foundation_dir():
    """
    Get absolute path to where foundation lives.
    """
    file_dir = os.path.realpath(os.path.dirname(os.path.abspath(__file__)))
    for root_path_re in [CVM_PATH_RE, REPO_PATH_RE, REPO_PATH_RE2]:
        match = root_path_re.match(file_dir)
        if match:
            return match.group(1)

    if getattr(sys, 'frozen', False):
        exec_dir = os.path.dirname(sys.executable)
        exec_dir_basename = os.path.basename(exec_dir)
        if 'bin' == exec_dir_basename:
            exec_dir = os.path.dirname(exec_dir)
        else:
            if 'MacOS' == exec_dir_basename:
                exec_dir = os.path.join(os.path.dirname(exec_dir), 'Resources')
        return exec_dir
    raise StandardError("Foundation didn't expect to be run with its code in directory %s. Please try a clean deployment." % file_dir)


def get_update_foundation_dir():
    """
    Get absolute path to where foundation update tars lives.
    """
    return os.path.join(os.path.expanduser('~'), 'foundation_updates')


def get_upgrade_foundation_script():
    """
    Get absolute path to foundation_upgrade script.
    """
    return os.path.join(get_bin_folder(), 'foundation_upgrade')


def _get_folder(subdir, set_owner=False, is_abs_path=False):
    if is_abs_path:
        path = subdir
    else:
        path = os.path.join(get_foundation_dir(), subdir)
    with folder_lock:
        if not os.path.exists(path):
            os.makedirs(path)
            if set_owner:
                import foundation_tools
                foundation_tools.assign_nutanix_owner(path)
    return path


def _get_file(tail):
    path = os.path.join(get_foundation_dir(), tail)
    return path


def get_boot_elf_path():
    return _get_file('templates/boot.elf')


def get_esx_boot_template_path():
    return _get_file('templates/boot.cfg')


def get_kvm_boot_template_path(arch):
    if arch == ARCH_X86:
        return _get_file('templates/grub.conf')
    if arch == ARCH_PPC:
        return _get_file('templates/grub_ppc64le.cfg')


def get_xen_boot_template_path():
    return _get_file('templates/xen-grub.cfg')


def get_hyperv_boot_template_path():
    return _get_file('templates/syslinux.cfg')


def get_syslinux_files():
    return [
     _get_file('templates/syslinux64.exe'),
     _get_file('templates/libutil.c32'),
     _get_file('templates/libcom32.c32'),
     _get_file('templates/chain.c32')]


def _get_ntnx_log_folder(subdir='.'):
    if NTNXLOGDIR in os.environ:
        return _get_folder(os.path.join(os.environ[NTNXLOGDIR], 'foundation', subdir), set_owner=True, is_abs_path=True)
    return _get_folder(os.path.join('log', subdir), set_owner=True, is_abs_path=False)


def get_log_folder():
    return _get_ntnx_log_folder()


def get_session_log_folder(session_id):
    if not session_id:
        return None
    return _get_ntnx_log_folder(subdir=session_id)


def get_log_archive_folder():
    return _get_ntnx_log_folder('archive')


def get_factory_log_archive_folder():
    return _get_ntnx_log_folder('factory_archive')


def get_hypervisor_isos_folder(hypervisor_type):
    return _get_folder(os.path.join('isos', 'hypervisor', hypervisor_type))


def get_qemu_path_in_phoenix():
    return '/usr/bin/qemu-system-x86_64'


def get_kvm_isos_folder():
    return get_hypervisor_isos_folder('kvm')


def get_esx_isos_folder():
    return get_hypervisor_isos_folder('esx')


def get_hyperv_isos_folder():
    return get_hypervisor_isos_folder('hyperv')


def get_linux_isos_folder():
    return get_hypervisor_isos_folder('linux')


def get_xen_isos_folder():
    return get_hypervisor_isos_folder('xen')


def get_xen_package():
    return get_driver_dir('xen/xen_package.tar.gz')


def get_phoenix_dir(arch='x86_64'):
    return _get_folder('lib/phoenix/%s' % arch)


def get_phoenix_initrd(arch='x86_64'):
    return _get_file('lib/phoenix/%s/boot/initrd' % arch)


def get_phoenix_kernel(arch='x86_64'):
    return _get_folder('lib/phoenix/%s/boot/kernel' % arch)


def get_phoenix_livecd(arch='x86_64'):
    return _get_folder('lib/phoenix/%s/livecd.tar' % arch)


def get_phoenix_squashfs(arch='x86_64'):
    return _get_folder('lib/phoenix/%s/squashfs.img' % arch)


def get_livecd_path(distro='squashfs', arch='x86_64'):
    if distro == 'squashfs':
        return get_phoenix_squashfs(arch)
    return get_phoenix_livecd(arch)


def get_components_folder():
    return _get_folder('components')


def get_nos_folder():
    return _get_folder('nos')


def get_tmp_folder(session_id=None):
    session_id = get_current_session(session_id, raise_on_empty=False)
    if session_id:
        session_folder = get_sessions_folder(session_id)
        return _get_folder(os.path.join(session_folder, 'tmp'))
    return _get_folder('tmp')


def get_garbage_dir():
    """
    Directory to be used for all temporary files and directories. This is
    slightly different from foundation/tmp. The files in foundation/tmp are
    also temporary but it acts more like a workspace for foundation. Having a
    separate garbage folder helps organize the workspace foundation/tmp/.
    """
    return _get_folder(os.path.join(get_tmp_folder(), 'garbage'), is_abs_path=True)


def get_cache_folder():
    return _get_folder(CACHE_FOLDER_NAME)


def get_bin_folder():
    return _get_folder('bin')


def get_phoenix_node_isos_folder(session_id=None):
    session_id = get_current_session(session_id)
    session_folder = get_sessions_folder(session_id)
    return _get_folder(os.path.join(session_folder, 'phoenix_node_isos'))


def get_boot_confs_folder(session_id=None):
    session_id = get_current_session(session_id, raise_on_empty=False)
    if session_id:
        session_folder = get_sessions_folder(session_id)
        return _get_folder(os.path.join(session_folder, 'node_boot_confs'))
    return _get_folder('tmp/node_boot_confs')


def get_kvm_template():
    return _get_file('templates/kvm_template.cfg')


def get_samba_folder(session_id):
    session_id = get_current_session(session_id)
    session_folder = get_sessions_folder(session_id)
    return _get_folder(os.path.join(session_folder, 'samba'))


def get_fuse_folder(session_id):
    session_id = get_current_session(session_id)
    session_folder = get_sessions_folder(session_id)
    return _get_folder(os.path.join(session_folder, 'fuse'))


def get_http_root_folder():
    return get_foundation_dir()


def get_service_log_path():
    import imaging_context
    if imaging_context.get_context() == imaging_context.FIELD_VM:
        return os.path.join(os.path.normpath(os.path.join(_get_ntnx_log_folder(), '..')), 'foundation.out')
    return os.path.join(get_log_folder(), 'service.log')


def get_node_log_path(node_id, session_id):
    log_dir = get_log_folder()
    session_id = get_current_session(session_id)
    session_log_dir = os.path.join(log_dir, session_id)
    log_filename = 'node_%s.log' % node_id
    return os.path.join(session_log_dir, log_filename)


def get_cluster_log_path(cluster_name, session_id):
    log_dir = get_log_folder()
    session_id = get_current_session(session_id)
    session_log_dir = os.path.join(log_dir, session_id)
    log_filename = 'cluster_%s.log' % cluster_name
    return os.path.join(session_log_dir, log_filename)


def get_http_access_path():
    return os.path.join(get_log_folder(), 'http.access')


def get_http_error_path():
    return os.path.join(get_log_folder(), 'http.error')


def get_http_files_folder(session_id=None):
    session_id = get_current_session(session_id)
    session_folder = get_sessions_folder(session_id)
    return _get_folder(os.path.join(session_folder, 'files'))


def get_common_http_files_folder():
    return _get_folder(os.path.join('tmp', 'files'))


def get_gui_folder():
    return _get_folder('gui')


def get_dynamic_iso_config(session_id):
    session_id = get_current_session(session_id)
    session_folder = get_sessions_folder(session_id)
    return os.path.join(_get_folder(os.path.join(session_folder, 'tmp')), 'dynamic_isos.json')


def get_relative_files_path(session_id=None):
    session_id = get_current_session(session_id, raise_on_empty=False)
    if session_id:
        session_folder = os.path.join('tmp/sessions', session_id)
        return os.path.join(session_folder, 'files')
    return 'files'


def get_relative_gui_path():
    return 'gui'


def get_standalone_gui_path():
    return os.path.join(get_gui_folder(), 'standalone')


def get_gui_for_docs():
    return os.path.join(get_gui_folder(), 'docs')


def get_swagger_json():
    return os.path.join(get_gui_for_docs(), 'swagger.json')


def get_pid_file_path():
    return '/var/run/foundation/foundation.pid'


def get_proxy_path():
    return _get_file('bin/cuttlefish.py')


def get_proxy_path_in_phoenix():
    return '/root/cuttlefish.py'


def get_installer_vm_template():
    return _get_file('templates/qemu_installer_vm.config')


def get_templates_folder():
    return _get_folder('templates')


def get_templates_file(filename):
    return _get_file(os.path.join('templates', filename))


def get_persisted_config_path(session_id=None, root_path=False):
    if root_path:
        return _get_file(PERSISTED_CONFIG_NAME)
    session_id = get_current_session(session_id, raise_on_empty=False)
    if session_id:
        session_folder = get_sessions_folder(session_id)
        return _get_file(os.path.join(session_folder, PERSISTED_CONFIG_NAME))
    return _get_file(PERSISTED_CONFIG_NAME)


def get_states_reached_path(session_id=None):
    session_id = get_current_session(session_id, raise_on_empty=False)
    if session_id:
        session_folder = get_sessions_folder(session_id)
        return _get_file(os.path.join(session_folder, STATES_REACHED_NAME))
    return _get_file(STATES_REACHED_NAME)


def get_discovery_info_path(session_id=None):
    session_id = get_current_session(session_id)
    session_log_dir = get_session_log_folder(session_id)
    return os.path.join(session_log_dir, 'discovery_info.json')


def get_nfs_path_from_tmp_path(path):
    return path


def get_config(filename):
    return _get_file(os.path.join('config', filename))


def get_foundation_settings_path():
    return get_config('foundation_settings.json')


def get_foundation_windows_timezone_map_path():
    return get_config('windows_timezone_map.json')


def get_foundation_settings_template_path():
    return get_config('foundation_settings.json.template')


def get_factory_settings_path():
    return _get_file('config/factory/factory_settings.json')


def get_disk_check_config_path():
    return _get_file('config/factory/disk_check_config.json')


def get_foundation_features_path():
    return get_config('features.json')


def get_hcl_path():
    return _get_file('lib/hcl.json')


def get_phoenix_override_path():
    return _get_file('phoenix_override.tar.gz')


def get_foundation_lib_pkg_path():
    return _get_file('lib/foundation_lib_package.tar')


def get_smc_ipmitool_path():
    return _get_file('lib/bin/smcipmitool/SMCIPMITool.jar')


def get_smc_sum_path():
    return _get_file('lib/bin/smcsumtool/sum')


def get_dell_racadm_path():
    return '/opt/dell/srvadmin/sbin/racadm'


def get_curl_path():
    return '/usr/bin/curl'


def get_ssh_path():
    return '/usr/bin/ssh'


def get_scp_path():
    return '/usr/bin/scp'


def get_cvm_sshkey():
    return _get_file('templates/cvm_sshkey')


def get_timeout_path():
    return '/usr/bin/timeout'


def get_ipmitool():
    return 'ipmitool'


def get_i40e_tardisk():
    return _get_file('lib/net_i40e.v00')


def get_iso_whitelist():
    return get_config('iso_whitelist.json')


def get_iso_checksums():
    return get_config('iso_checksums.json')


def get_foundation_version():
    return _get_file('foundation_version')


def get_lenovo_asu_path():
    return _get_folder('lib/bin/asu')


def get_driver_dir(subdir=''):
    return _get_folder(os.path.join('lib/driver', subdir))


def get_anaconda_tarball():
    return _get_file('lib/driver/kvm/anaconda.tar.gz')


def get_svm_version_path():
    return '/etc/nutanix/svm-version'


def get_cvm_hardware_config_path():
    return '/etc/nutanix/hardware_config.json'


def get_ucsm_profile_template():
    return get_templates_file('ucsm_template.json')


def get_ucs_platform_reference():
    return get_templates_file('cisco_ucs_platform_reference.json')


def get_hpe_platform_reference():
    return get_templates_file('hp_platform_reference.json')


def get_crystal_platform_reference():
    return get_templates_file('crystal_plat_reference.json')


def get_sessions_root_folder():
    return _get_folder(os.path.join('tmp', SESSIONS_FOLDER_NAME), set_owner=True)


def get_sessions_folder(session_id):
    return _get_folder(os.path.join(get_sessions_root_folder(), session_id), is_abs_path=True, set_owner=True)


def get_smc_rmh_path():
    if platform.system() == 'Darwin':
        return _get_file('lib/bin/mac/smcipmitool/RemoteMediaHelper.jar')
    return _get_file('lib/bin/smcipmitool/RemoteMediaHelper.jar')


def get_mkisofs_path():
    if platform.system() == 'Darwin':
        return _get_file('lib/bin/mac/mkisofs')
    return 'mkisofs'


def get_cygwin_bin():
    return _get_folder(os.path.join('lib', 'bin', 'cygwin'))


def get_cvm_eos_metadata_path():
    return '/etc/nutanix/eos_metadata.json'


def get_fc_metadata_path():
    return '/etc/nutanix/foundation_central.json'


def get_provision_network_utils_egg(filename):
    return _get_file('lib/py/' + filename)