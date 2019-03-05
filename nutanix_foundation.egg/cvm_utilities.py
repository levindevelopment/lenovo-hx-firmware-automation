# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/cvm_utilities.py
# Compiled at: 2019-02-15 12:42:10
import glob, json, logging, ntpath, os, posixpath, shutil, tarfile, tempfile, time
from string import Template
from cluster.genesis.node_manager import NodeManager
from util.net.rpc import RpcError
from foundation import features
from foundation import folder_central
from foundation import foundation_tools as tools
from foundation import host_utilities as host_utils
from foundation.config_manager import NodeConfig
from foundation.consts import ARCH_PPC, ARCH_X86, ALL_ARCH
from foundation.foundation_settings import settings as foundation_settings
from foundation.shared_functions import get_nos_hcl_from_tarball
from foundation.tinyrpc import call_genesis_method
HYPERVISOR_NAME_MAP = {0: 'esx', 
   1: 'xen', 
   2: 'hyperv', 
   3: 'kvm', 
   99: 'null'}
MAX_BOOT_WAIT_CYCLES = 6 * 15
CHECK_INTERVAL_S = 10
SCP_RETRIES = 3
LIVECD_TMP_PATH = '/home/nutanix/foundation/tmp/phoenix_livecd'
DEFAULT_LOGGER = logging.getLogger(__file__)
SG_DISK_DIR = '/home/nutanix/data/stargate-storage/disks'
WORKLOAD_MARKER = 'workload.json'
MARKERS = [
 'hyperv_first_boot.ps1', '.foundation_staging_partition']

class RemoteNode(object):

    def __init__(self, node):
        self.node = node
        self.logger = node.get_logger()

    @property
    def ip(self):
        raise NotImplementedError

    @property
    def default_user(self):
        raise NotImplementedError

    def ssh(self, *args, **kwargs):
        return tools.ssh(self.node, self.ip, user=self.default_user, *args, **kwargs)

    def scp(self, src, dst, *args, **kwargs):
        return tools.scp(self.node, self.ip, user=self.default_user, target_path=dst, files=src, *args, **kwargs)


class CVMGuest(RemoteNode):

    @property
    def ip(self):
        return self.node.cvm_ip

    @property
    def default_user(self):
        return 'nutanix'


class LinuxHost(RemoteNode):

    def __init__(self, *arg, **kwarg):
        super(LinuxHost, self).__init__(*arg, **kwarg)
        self.cvm = CVMGuest(self.node)

    @property
    def ip(self):
        ip = getattr(self.node, 'hypervisor_ip', None)
        assert ip, 'no hypervisor_ip is provided, foundation will not access this host directly'
        return ip

    def ssh_via_cvm(self, command, *args, **kwargs):
        command = [
         'ssh', '-i', '~/.ssh/id_rsa', 'root@192.168.5.1'] + command
        return self.cvm.ssh(command, *args, **kwargs)

    def scp_to_host_from_cvm(self, src, dst):
        try:
            command = [
             'scp', '-i', '~/.ssh/id_rsa', src, 'root@192.168.5.1:%s' % dst]
            return self.cvm.ssh(command)
        except StandardError as e:
            self.logger.error('Failed while copying file %s to host with error %s' % (
             src, e))
            raise
        finally:
            command = [
             'rm', '-rf', os.path.dirname(src)]
            self.cvm.ssh(command)

    def scp_via_cvm(self, src, dst):
        for _ in range(SCP_RETRIES):
            dtemp, err, ret = self.cvm.ssh(['mktemp', '-d'], throw_on_error=False)
            if ret == 0:
                break
        else:
            message = 'Foundation tried to create a temp dir on CVM but failed to do so. (%s)' % (
             dtemp, err)
            raise StandardError(message)

        dtemp = dtemp.strip()
        basename = os.path.basename(ntpath.basename(dst))
        cvm_dst = posixpath.join(dtemp, basename)
        for _ in range(SCP_RETRIES):
            out, err, ret = self.cvm.scp(src, cvm_dst, throw_on_error=False, timeout=60)
            if ret == 0:
                break
        else:
            raise StandardError('Foundation failed to scp %s to CVM: (%s)' % (
             src, (out, err)))

        return self.scp_to_host_from_cvm(cvm_dst, dst)

    @property
    def default_user(self):
        return 'root'

    def get_boot_conf_tmpl(self):
        """
        Returns path to the boot_conf template
        """
        raise NotImplementedError

    def generate_boot_cfg(self):
        from foundation.http_server import FileServer
        node = self.node
        node_id = node.phoenix_ip
        node.foundation_ip = tools.get_my_ip(node.phoenix_ip)
        foundation_port = foundation_settings['http_port']
        session_id = getattr(node, '_session_id', '')
        session_files_dir = folder_central.get_http_files_folder(session_id)
        arizona_file_name = 'arizona.node_%s.json' % node_id
        arizona_file_name = os.path.join(session_files_dir, arizona_file_name)
        arizona_url = 'http://%s:%s/%s' % (node.foundation_ip,
         foundation_port, FileServer.add_file(arizona_file_name))
        if features.is_enabled(features.CENTOS):
            type_img = 'squashfs'
        else:
            type_img = 'gentoo'
        livecd_path = folder_central.get_livecd_path(type_img, node.arch)
        phoenix_bond_mode = ''
        bond_lacp_rate = ''
        bond_mode = getattr(node, 'bond_mode', '')
        if bond_mode == 'static':
            phoenix_bond_mode = 0
        else:
            if bond_mode == 'dynamic':
                phoenix_bond_mode = 4
                bond_lacp_rate = node.bond_lacp_rate
                if bond_lacp_rate == 'slow':
                    bond_lacp_rate = 0
                else:
                    bond_lacp_rate = 1
        with open(self.get_boot_conf_tmpl()) as (template):
            text = template.read()
        text = Template(text).substitute(foundation_ip=node.foundation_ip, foundation_port=foundation_port, az_conf_url=arizona_url, livefs_url=FileServer.make_url_and_hash(livecd_path, node)['url'], node_id=node_id, phoenix_ip=node.phoenix_ip, phoenix_netmask=node.phoenix_netmask, phoenix_gw=node.phoenix_gateway, vlan_id=getattr(self.node, 'cvm_vlan_id', ''), boot_script='rescue_shell', session=session_id, bond_mode=phoenix_bond_mode, bond_uplinks=(',').join(getattr(node, 'bond_uplinks', [])), bond_lacp_rate=bond_lacp_rate, type_img=type_img)
        boot_conf = os.path.join(folder_central.get_boot_confs_folder(), 'boot_conf_%s.cfg' % node_id)
        with open(boot_conf, 'w') as (boot_conf_fp):
            boot_conf_fp.write(text)
        self.boot_conf = boot_conf
        return boot_conf

    def copy_livecd(self):
        stage_livecd_on_cvm(self.node)

    def get_files_to_copy(self):
        """
        Returns a list of files to copy over
        
        eg.
        {
         "path/to/kernel": ["/boot/kernel"],
         "path/to/boot_conf": ["/bootbank/boot.cfg"]
        }
        """
        raise NotImplementedError

    def backup_boot_conf(self, boot_conf, boot_conf_backup):
        """
        Backs up the hypervisor boot configuration file (boot_conf) to
        boot_conf_backup. This will ensure that only a non-phoenix boot
        configuration is backed up.
        Args:
          boot_conf: Full path to the boot config file of the hypervisor.
          boot_conf_backup: Full path to the backup file.
        
        Returns:
          None
        
        Raises:
          StandardError if unable to ssh to target node.
        """
        logger = self.logger
        out, _, ret = self.ssh(command=['cat', boot_conf])
        if 'AZ_CONF_URL' in out or 'LIVEFS_URL' in out:
            logger.info('Boot config file (%s) is already configured to boot into phoenix. Not backing up boot config file' % boot_conf)
            return
        self.ssh(command=['cp', boot_conf, boot_conf_backup])
        logger.info('Backed up boot conf %s to %s', boot_conf, boot_conf_backup)

    def remote_dir_free_space(self, remote):
        out, _, ret = self.ssh(command=['df', '-k', remote])
        if ret or not out.startswith('Filesystem'):
            return -1
        lines = out.splitlines()[1:]
        if not lines:
            return -1
        lines = map(lambda l: l.split(), lines)
        lines = filter(lambda l: len(l) == 6, lines)
        lines = sorted(lines, key=lambda p: len(p[-1]) if remote.startswith(p[-1]) else -1)
        if int(lines[-1][3]) < 0:
            self.logger.warn('No matching entry found for %s\n%s', remote, out)
            return -1
        return int(lines[-1][3]) * 1024

    def space_check(self, files):
        space_req = {}
        for local_file, remote_files in files.items():
            for remote_file in remote_files:
                remote_dir = os.path.dirname(remote_file)
                space = space_req.get(remote_dir, 0)
                space_req[remote_dir] = space + os.path.getsize(local_file)

        for remote_dir, req in space_req.items():
            free_space = self.remote_dir_free_space(remote_dir)
            if free_space < req:
                self.logger.error('insufficient free space on %s, %s Bytes required, but only %s Bytes free', remote_dir, req, free_space)
                raise StandardError('Insufficient free space on target host')

    def copy_phoenix(self):
        files = self.get_files_to_copy()
        self.space_check(files)
        for src, dsts in files.items():
            for dst in dsts:
                self.logger.debug('copying %s to host:%s', src, dst)
                if src == self.boot_conf:
                    backup = dst + '.backup'
                    self.logger.debug('Backup %s to %s', dst, backup)
                    self.backup_boot_conf(dst, backup)
                self.scp(src, dst)

    def install_boot_loader(self):
        pass

    def test_ssh(self):
        _, _, ret = self.ssh(command=['true'], throw_on_error=False)
        if ret:
            raise StandardError('Failed to ssh to host, please check the status')

    def reboot(self, command=['reboot']):
        self.logger.debug('Checking ssh connection')
        self.test_ssh()
        self.logger.info('Rebooting using command: %s', command)
        out, err, ret = self.ssh(command=command, throw_on_error=False)
        if ret:
            self.logger.warn("Foundation tried to reboot the remote node over ssh, and it returns with error %s: %s, which is usually normal for AHV, Xen or HyperV. If the system didn't reboot in 5 minutes, please contact foundation team for support.", ret, (out, err))
        return (out, err, ret)

    def reboot_to_phoenix(self):
        self.generate_boot_cfg()
        self.copy_phoenix()
        if not getattr(self.node, 'compute_only', False):
            self.copy_livecd()
        self.install_boot_loader()
        self.reboot()


class KVMHost(LinuxHost):

    def ssh(self, *args, **kwargs):
        return self.ssh_via_cvm(*args, **kwargs)

    def scp(self, src, dst):
        return self.scp_via_cvm(src, dst)

    def get_boot_conf_tmpl(self):
        return folder_central.get_kvm_boot_template_path(self.node.arch)

    def get_files_to_copy(self):
        return {self.boot_conf: [
                          '/boot/grub/grub.conf'], 
           folder_central.get_phoenix_kernel(): [
                                               '/boot/kernel'], 
           folder_central.get_phoenix_initrd(): [
                                               '/boot/initrd']}

    def reboot(self):
        out, err, ret = super(KVMHost, self).reboot()
        if not ret:
            out, err, ret = self.cvm.ssh(['sudo', 'poweroff'], throw_on_error=False)
            if ret:
                self.logger.debug('Ignoring reboot error %s: %s', ret, (out, err))


class KVMDirectHost(LinuxHost):

    def __init__(self, node, *args, **kwargs):
        super(LinuxHost, self).__init__(node, *args, **kwargs)

    def get_phoenix_network(self):
        return (
         self.node.phoenix_ip, self.node.hypervisor_netmask,
         getattr(self.node, 'hypervisor_gateway', ''))

    def get_boot_conf_tmpl(self):
        return folder_central.get_kvm_boot_template_path(self.node.arch)

    def get_files_to_copy(self):
        return {self.boot_conf: [
                          '/boot/grub/grub.conf'], 
           folder_central.get_phoenix_kernel(): [
                                               '/boot/kernel'], 
           folder_central.get_phoenix_initrd(): [
                                               '/boot/initrd']}


class KVMPPCHost(KVMHost):

    def get_files_to_copy(self):
        return {self.boot_conf: [
                          '/boot/grub2/grub.cfg'], 
           folder_central.get_phoenix_kernel(ARCH_PPC): [
                                                       '/boot/kernel'], 
           folder_central.get_phoenix_initrd(ARCH_PPC): [
                                                       '/boot/initrd']}


class ESXHost(KVMHost):

    def get_boot_conf_tmpl(self):
        return folder_central.get_esx_boot_template_path()

    def get_files_to_copy(self):
        files = {self.boot_conf: [
                          '/bootbank/boot.cfg'], 
           folder_central.get_phoenix_kernel(): [
                                               '/bootbank/kernel'], 
           folder_central.get_phoenix_initrd(): [
                                               '/bootbank/initrd'], 
           folder_central.get_boot_elf_path(): [
                                              '/bootbank/boot.elf']}
        for key in files:
            files[key].append(files[key][0].replace('bootbank', 'altbootbank'))

        return files

    def remote_dir_free_space(self, remote):
        out, _, ret = self.ssh(command=['readlink', '-f', remote])
        if not ret and out:
            remote = out.strip()
        return super(ESXHost, self).remote_dir_free_space(remote)


class XenHost(KVMHost):

    def get_boot_conf_tmpl(self):
        return folder_central.get_xen_boot_template_path()

    def get_files_to_copy(self):
        return {self.boot_conf: [
                          '/boot/grub/grub.cfg'], 
           folder_central.get_phoenix_kernel(): [
                                               '/boot/kernel'], 
           folder_central.get_phoenix_initrd(): [
                                               '/boot/initrd']}


class HypervHost(LinuxHost):
    """
    Treating HyperV as a an Linux host, seems to be a legit hack.
    
    Be be careful on path manipulation!
    """

    def ssh(self, command, *args, **kwargs):
        command = [
         '/usr/local/nutanix/bin/winsh'] + command
        return self.cvm.ssh(command, *args, **kwargs)

    def scp_to_host_from_cvm(self, src, dst):
        try:
            command = ['/usr/local/nutanix/bin/wincp', '--force', src, dst]
            return self.cvm.ssh(command, throw_on_error=False)
        except StandardError as e:
            self.logger.error('Failed while copying file %s to host with error %s' % (
             src, e))
            raise
        finally:
            command = [
             'rm', '-rf', os.path.dirname(src)]
            self.cvm.ssh(command)

    def scp(self, src, dst):
        return self.scp_via_cvm(src, dst)

    def get_boot_conf_tmpl(self):
        return folder_central.get_hyperv_boot_template_path()

    def find_drive(self, marker_files=MARKERS, timeout=60):
        r"""
        This function searches for files present in marker_files list in all drives
        and return the corresponding drive letter.
        
        Args:
          marker_files: List of files to be searched relative to the root of drive.
              Ex: ["folder1\/file1"] will return <drive> for which
              "<drive>:\/folder1\/file" is a valid file or folder. If multiple
              such files are present, the first drive (in lexicographical order) is
              returned. File separator should be '\/'.
          timeout: Timeout for executing each ssh command. Default value is
              60 seconds. Some Lenovo nodes take 30 to 60 seconds to finish this
              operation.
        
        Returns:
          Drive letter if any of the marker file is found in any drive.
          None otherwise.
        """
        cmd = [
         'Get-PSDrive', '-PSProvider', 'FileSystem']
        out, _, ret = self.ssh(cmd, timeout=timeout, throw_on_error=False)
        if ret:
            self.logger.error('Unable to determine the drives on HyperV host')
            return
        drives = []
        for line in out.splitlines():
            words = line.split()
            if words and len(words[0]) == 1:
                drives.append(line[0])

        for drive in drives:
            for marker_path in marker_files:
                marker = '%s:\\/%s' % (drive, marker_path)
                cmd = ['ls', marker]
                _, _, ret = self.ssh(cmd, timeout=timeout, throw_on_error=False, log_on_error=False)
                if not ret:
                    return drive

        return

    def check_drive(self):
        drive = self.find_drive()
        if not drive:
            raise StandardError('Unable to detect staging drive for boot files')
        self.drive = drive

    def get_files_to_copy(self):
        drive = self.drive
        unc = '%s:\\\\' % drive
        file_list = [
         folder_central.get_phoenix_kernel(),
         folder_central.get_phoenix_initrd()]
        file_list += folder_central.get_syslinux_files()
        files = {}
        for file_ in file_list:
            files[file_] = [unc + os.path.basename(file_)]

        files[self.boot_conf] = [
         unc + 'syslinux.cfg']
        return files

    def backup_boot_conf(self, boot_conf, boot_conf_backup):
        pass

    def install_boot_loader(self):
        drive = self.drive
        self.ssh(command=[
         '%s:\\\\syslinux64.exe' % drive,
         '-a', '-m', '-f', '-i', '%s:' % drive])
        self.logger.info('syslinux installed successfully')
        self.ssh(command=[
         'Set-Partition', '-DriveLetter', drive, '-IsActive', '1'])
        self.logger.info('Marked drive %s as active' % drive)

    def reboot(self):
        return super(HypervHost, self).reboot(['Restart-Computer', '-Force'])

    def reboot_to_phoenix(self):
        self.check_drive()
        super(HypervHost, self).reboot_to_phoenix()


class HypervDirectHost(LinuxHost):
    """
    Direct version of HyperV host
    
    Requires the hypervisor_ip attribute
    """

    def ssh(self, *args, **kwargs):
        if args and type(args[0]) != str:
            args[0] = (' ').join(args[0])
        if 'command' in kwargs and type(kwargs['command']) != str:
            kwargs['command'] = (' ').join(kwargs['command'])
        if 'timeout' in kwargs:
            kwargs['timeout_secs'] = kwargs.pop('timeout')
        if 'throw_on_error' in kwargs:
            kwargs['raise_on_error'] = kwargs.pop('throw_on_error')
        return host_utils.ssh_on_hyperv_host(host_ip=self.node.hypervisor_ip, logger=self.logger, *args, **kwargs)

    def scp(self, src, dst, *args, **kwargs):
        return host_utils.scp_to_hyperv_host(host_ip=self.node.hypervisor_ip, src_target_map={src: dst}, logger=self.logger, *args, **kwargs)

    def check_direct_access(self):
        out, _, ret = self.ssh('true')
        if not ret:
            self.logger.debug('Foundation is able to ssh into hyperv host directly.')
            return True
        self.logger.warning('Foundation is unable to ssh into hyperv host directly.')

    def copy_phoenix(self):
        files = self.get_files_to_copy()
        host_utils.scp_to_hyperv_host(host_ip=self.node.hypervisor_ip, src_target_maps=files, logger=self.logger)


class PhoenixHost(LinuxHost):

    def __init__(self, node, *args, **kwargs):
        super(LinuxHost, self).__init__(node, *args, **kwargs)

    @property
    def ip(self):
        return self.node.phoenix_ip


def _format_stdout_stderr(out='', err=''):
    out = out.strip()
    err = err.strip()
    message = 'Please check the stdout, stderr for the exact reason.\nstdout:\n%sstderr:\n%s'
    return message % (out, err)


def stage_livecd_on_cvm(node_config):
    """
    Copies livecd.tar or squashfs.img to target cvm. Since staging livecd is
    a backup option, this function will not raise any exception.
    Args:
      node_config: NodeConfig object for the target node.
    """
    logger = node_config.get_logger()
    if features.is_enabled(features.CENTOS):
        livecd_path = folder_central.get_phoenix_squashfs(node_config.arch)
    else:
        livecd_path = folder_central.get_phoenix_livecd(node_config.arch)
    _, _, ret = tools.ssh(node_config, node_config.cvm_ip, [
     'mkdir', '-p', LIVECD_TMP_PATH], throw_on_error=False)
    if not ret:
        _, _, ret = tools.scp(node_config, node_config.cvm_ip, LIVECD_TMP_PATH, [livecd_path], throw_on_error=False, timeout=60)
        if not ret:
            logger.info('Staged livecd.tar on cvm at %s/livecd.tar' % LIVECD_TMP_PATH)
            return
    logger.warning('Failed to stage livecd.tar on cvm')


def stage_mdadm_on_host(node_config, target_host_path, hyp, use_hyperv_host=False, livecd=None):
    """
    Extracts mdadm utility from livecd and stages it on host so that phoenix
    can use it to read livecd.tar from cvm in case of network issues. Since this
    is a backup plan, this function will not raise any exception.
    Args:
      node_config: NodeConfig object for the target node.
      target_host_path: Target path on host where mdadm should be staged.
      hyp: Target hypervisor type.
    """
    tf = None
    tmp_path = None
    logger = node_config.get_logger()
    livecd_path = livecd
    if not livecd_path:
        if features.is_enabled(features.CENTOS):
            livecd_path = folder_central.get_phoenix_squashfs(node_config.arch)
        else:
            livecd_path = folder_central.get_phoenix_livecd(node_config.arch)
    try:
        tf = tarfile.open(livecd_path)
        tmp_path = tempfile.mkdtemp()
        src_target_map = {'symlinks': {'src': None, 
                        'target': '%s/000-symlinks.tbz2' % target_host_path}, 
           'mdadm': {'src': None, 'target': '%smdadm.tbz2' % target_host_path}, 'glibc': {'src': None, 'target': '%sglibc.tbz2' % target_host_path}}
        for pkg in src_target_map:
            pkg_path = tools.get_packages_path_in_tar(tf=tf, path_contains=pkg, raise_on_error=False)
            if not pkg_path:
                raise StandardError('Could not find %s in livecd' % pkg)
            if pkg_path[0] == '/':
                path = os.path.join(tmp_path, pkg_path[1:])
            else:
                path = os.path.join(tmp_path, pkg_path)
            if not os.path.exists(os.path.dirname(path)):
                os.makedirs(os.path.dirname(path))
            data_fd = tf.extractfile(pkg_path)
            if not data_fd:
                raise StandardError('Could not extract %s package from livecd' % pkg)
            with open(path, 'wb') as (fd):
                shutil.copyfileobj(data_fd, fd)
            src_target_map[pkg]['src'] = path

        tf.close()
    except:
        logger.exception('Failed to extract raid utilities from livecd')
        if tmp_path:
            shutil.rmtree(tmp_path)
        return
    finally:
        if tf:
            tf.close()

    try:
        for k, v in src_target_map.iteritems():
            if not use_hyperv_host:
                scp_to_host_via_cvm(node_config=node_config, target_path=v['target'], files=[
                 v['src']], hyp=hyp)
            else:
                host_utils.scp_to_hyperv_host(node_config.hypervisor_ip, {v['src']: v['target']}, logger=logger, raise_on_error=True)

        logger.info('Staged raid utilities on host')
    except:
        logger.exception('Failed to stage raid utilities on target host')
    finally:
        if tmp_path:
            shutil.rmtree(tmp_path)

    return


def stage_best_hcl(node_config):
    """
    #Stage right HCL file inside CVM from AOS whitelist, Own, CVM whitelist
    Args:
      node_config: NodeConfig object for the target node.
    """
    logger = node_config.get_logger()
    cvm_ip = getattr(node_config, 'cvm_ip', None) or node_config.phoenix_ip
    foundation_etc_hcl_last_edit = None
    with open('/etc/nutanix/hcl.json') as (data_file):
        foundation_etc_hcl = json.load(data_file)
        foundation_etc_hcl_last_edit = foundation_etc_hcl.get('last_edit')
    etc_hcl, _, ret = tools.ssh(node_config, cvm_ip, ['cat',
     '/etc/nutanix/hcl.json'], throw_on_error=False)
    logger.info('Checking if CVM has an older hcl.json')
    if not ret and etc_hcl:
        etc_hcl = json.loads(etc_hcl)
        if etc_hcl and etc_hcl.get('last_edit'):
            etc_hcl_last_edit = etc_hcl.get('last_edit')
            with open(folder_central.get_hcl_path()) as (data_file):
                foundation_hcl = json.load(data_file)
                foundation_hcl_last_edit = foundation_hcl.get('last_edit')
                if node_config.nos_package:
                    nos_hcl = get_nos_hcl_from_tarball(node_config.nos_package)
                    nos_hcl_json = json.load(nos_hcl)
                    nos_hcl_last_edit = nos_hcl_json.get('last_edit')
                else:
                    nos_hcl_json = None
                    nos_hcl_last_edit = 0
                if foundation_hcl_last_edit > etc_hcl_last_edit and foundation_hcl_last_edit > nos_hcl_last_edit and foundation_hcl_last_edit > foundation_etc_hcl_last_edit:
                    logger.info('Updating hcl.json inside the CVM from Foundation')
                    for retry in range(5):
                        out, err, ret = tools.scp(config=node_config, ip=node_config.cvm_ip, target_path='/etc/nutanix/', files=[
                         folder_central.get_hcl_path()], log_on_error=True, throw_on_error=False)
                        if ret == 0:
                            return

                if nos_hcl_last_edit and nos_hcl_last_edit > etc_hcl_last_edit and nos_hcl_last_edit > foundation_etc_hcl_last_edit:
                    logger.info('Updating hcl.json inside the CVM from NOS')
                    tmp_path = tempfile.mkdtemp()
                    with open(os.path.join(tmp_path, 'hcl.json'), 'w') as (outfile):
                        json.dump(nos_hcl_json, outfile, sort_keys=True, indent=4, ensure_ascii=False)
                    for retry in range(5):
                        out, err, ret = tools.scp(config=node_config, ip=node_config.cvm_ip, target_path='/etc/nutanix/', files=[
                         os.path.join(tmp_path, 'hcl.json')], log_on_error=True, throw_on_error=False)
                        if ret == 0:
                            return

                if foundation_etc_hcl_last_edit and foundation_etc_hcl_last_edit > etc_hcl_last_edit:
                    logger.info('Updating hcl.json inside the CVM from Foundation /etc')
                    for retry in range(5):
                        out, err, ret = tools.scp(config=node_config, ip=node_config.cvm_ip, target_path='/etc/nutanix/', files=[
                         '/etc/nutanix/hcl.json'], log_on_error=True, throw_on_error=False)
                        if ret == 0:
                            return

    return


def detect_remote_arch(node_config, ip=None):
    """
    Detect remote arch by running uname -m on cvm
    
    This function will try to ssh using user nutanix and root
    
    Args:
      node_config(NodeConfig): the target node
    Returns:
      arch: ARCH_PPC or ARCH_X86
    """
    if getattr(node_config, 'compute_only', False):
        return ARCH_X86
    if ip is None:
        ip = node_config.phoenix_ip
    for user in ['nutanix', 'root']:
        out, err, ret = tools.ssh(node_config, ip, [
         'uname', '-m'], user=user, throw_on_error=False)
        if not ret:
            if out.strip() in ALL_ARCH:
                return out.strip()
            node_config.get_logger().debug("Unknown arch: '%s'", out)
    else:
        raise StandardError('Unable to detect remote arch of %s' % node_config)

    return


def detect_local_hypervisor_type():
    node_config = NodeConfig()
    node_config.cvm_ip = '127.0.0.1'
    return detect_remote_hypervisor_type(node_config)


def detect_remote_hypervisor_type(node_config, ip=None):
    assert isinstance(node_config, NodeConfig), 'node_config must be of type NodeConfig'
    if getattr(node_config, 'compute_only', False):
        return 'kvm'
    if ip is None:
        cvm_ip = getattr(node_config, 'cvm_ip', None) or node_config.phoenix_ip
    else:
        cvm_ip = ip
    ret = call_genesis_method(cvm_ip, NodeManager.hypervisor_type, timeout_secs=30)
    if not isinstance(ret, RpcError):
        return HYPERVISOR_NAME_MAP[ret]
    command = [
     'ssh',
     '-i',
     '/home/nutanix/.ssh/id_rsa',
     'root@192.168.5.1',
     'uname', '-a']
    out, err, ret = tools.ssh(config=node_config, ip=cvm_ip, command=command, log_on_error=False, throw_on_error=False)
    if not ret:
        if 'linux' in out.lower():
            if '.nutanix.' in out.lower():
                return 'kvm'
            return 'xen'
        else:
            if 'vmkernel' in out.lower():
                return 'esx'
            raise StandardError('Remote host seems to be a linux-like host but Foundation is not able to get it right. The stdout is %s\nThe stderr is %s\n' % (
             out, err))
    command = ['/usr/local/nutanix/bin/winsh',
     '"get-ciminstance win32_operatingsystem | % caption"']
    out, err, ret = tools.ssh(config=node_config, ip=cvm_ip, command=command, log_on_error=False, throw_on_error=False, timeout=10, escape_cmd=True)
    if not ret:
        if 'windows' in out.lower():
            return 'hyperv'
        raise StandardError('Remote host seems to be a Windows host but Foundation is not able to get it right. The stdout is %s\nThe stderr is %s\n' % (
         out, err))
    host_ip = getattr(node_config, 'hypervisor_ip', None)
    if host_ip:
        cmd = 'get-ciminstance win32_operatingsystem | % caption'
        out, _, ret = host_utils.ssh_on_hyperv_host(cmd, node_config.hypervisor_ip, logger=node_config.get_logger())
        if not ret:
            if 'windows' in out.lower():
                return 'hyperv'
    raise StandardError('Unable to detect type of remote hypervisor')
    return


def detect_workload():
    """
    Detect workload on CVM.
    
    This function detects workload on stargate data disk.
    
    Returns:
      a dict of workloads
      {"path_to_marker_file": <marker content>}
    """
    logger = DEFAULT_LOGGER
    workloads = {}
    disks = glob.glob('%s/*' % SG_DISK_DIR)
    for disk in disks:
        marker_path = os.path.join(disk, WORKLOAD_MARKER)
        if os.path.exists(marker_path):
            try:
                marker_json = json.load(open(marker_path))
                workloads[marker_path] = marker_json
            except (IOError, ValueError):
                logger.exception('Exception in processing marker file')

    return workloads


def get_host_class(node):
    host_class_map = {KVMHost: {'arch': ARCH_X86, 'current_hyp_type': 'kvm', 'compute_only': lambda v: v in [False, None]}, 
       KVMDirectHost: {'arch': ARCH_X86, 'current_hyp_type': 'kvm', 
                       'hypervisor_ip': lambda v: v is not None, 
                       'compute_only': lambda v: v is True}, 
       KVMPPCHost: {'arch': ARCH_PPC}, ESXHost: {'current_hyp_type': 'esx'}, XenHost: {'current_hyp_type': 'xen'}, HypervHost: {'current_hyp_type': 'hyperv'}, HypervDirectHost: {'current_hyp_type': 'hyperv', 'hypervisor_ip': lambda v: v is not None, 
                          'cvm_ip': lambda v: not v}}
    match = []
    for cls, attrs in host_class_map.items():
        for k, v in attrs.items():
            node_v = getattr(node, k, None)
            if callable(v) and v(node_v):
                continue
            else:
                if node_v == v:
                    continue
            break
        else:
            match.append(cls)

    assert len(match) == 1, 'unable to get exact match for host %s: %s' % (node, match)
    return match[0]


def ssh_wait(host, command, name, timeout=30):
    logger = host.logger
    for i in range(MAX_BOOT_WAIT_CYCLES):
        _, _, ret = host.ssh(command, throw_on_error=False, log_on_error=False, timeout=timeout)
        if not ret:
            break
        logger.debug('[%s/%s] Waiting for %s to come up after reboot.', i, MAX_BOOT_WAIT_CYCLES, name)
        time.sleep(CHECK_INTERVAL_S)
    else:
        raise StandardError('Failed to connect to %s at %s', name, host.ip)

    logger.info('%s is up at %s', name, host.ip)


def reboot_to_phoenix(node):
    """
    Reboot the CVM into phoenix image.
    Args:
      node_config: NodeConfig object corresponding to the node to be rebooted.
        Following fields must be present in NodeConfig object:
          mandatory: cvm_ip, cvm_netmask.
          optional:
            cvm_vlan_id, hypervisor_ip.
            If hypervisor_ip is provided, Foundation will try to stage files
            directly on the host instead of using cvm as an intermediate staging
            area. If this attempt fails, Foundation falls back to the old way of
            staging files via cvm.
    """
    if node.phoenix_ip == tools.get_my_ip(node.phoenix_ip):
        raise StandardError('Trying to reboot the same node from which foundation is driving the reboot. This operation is not permitted.')
    logger = node.get_logger()
    if tools.in_phoenix(node, log_on_error=True):
        raise StandardError('The remote node is already running in Phoenix')
    node.arch = detect_remote_arch(node)
    node.current_hyp_type = detect_remote_hypervisor_type(node)
    logger.info('Rebooting %s/%s to phoenix', node.current_hyp_type, node.arch)
    cls = get_host_class(node)
    logger.debug('Uisng host type %s', cls)
    host = cls(node)
    host.reboot_to_phoenix()
    phoenix = PhoenixHost(node)
    ssh_wait(phoenix, [
     'test', '-f', '/phoenix/layout/layout_finder.py'], 'Phoenix')


def reboot_from_phoenix(node_config):
    """
    Reboot the phoenix image back into CVM.
    Args:
      node_config: NodeConfig object corresponding to the node to be rebooted.
    Returns:
      None
    Raises:
      StandardError upon failure.
    """
    assert isinstance(node_config, NodeConfig), 'node_config must be of type NodeConfig'
    check_cvm = True
    check_host = False
    if getattr(node_config, 'compute_only', None):
        assert getattr(node_config, 'hypervisor_ip', None), 'cannot wait for host without hypervisor_ip'
        check_cvm = False
        check_host = True
    if not (check_cvm and getattr(node_config, 'cvm_ip', None)):
        raise AssertionError('cannot wait for CVM without cvm_ip')
    logger = node_config.get_logger()
    if not tools.in_phoenix(node_config, log_on_error=True):
        raise StandardError('The remote node is not running in Phoenix')
    phoenix = PhoenixHost(node_config)
    phoenix_ip = node_config.phoenix_ip
    logger.info('rebooting %s from phoenix', phoenix_ip)
    reboot_to_host_path = '/phoenix/reboot_to_host.py'
    command = ['python', reboot_to_host_path]
    out, err, ret = phoenix.ssh(command, throw_on_error=False)
    if ret not in (0, -1):
        message = 'Failed to execute %s in Phoenix running on %s' % (
         reboot_to_host_path, phoenix_ip)
        logger.error(message + _format_stdout_stderr(out, err))
        raise StandardError(message)
    if check_host:
        if getattr(node_config, 'compute_only', None):
            host = KVMDirectHost(node_config)
            ssh_wait(host, ['test', '-f', '/etc/nutanix-release'], 'AHV')
        else:
            raise NotImplementedError
    if check_cvm:
        cvm = CVMGuest(node_config)
        ssh_wait(cvm, ['test', '-f', '/etc/nutanix/release_version'], 'CVM')
    return