# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/shared_functions.py
# Compiled at: 2019-02-15 12:42:10
import json, collections, logging, os, re, shutil, socket, struct, tarfile, tempfile, traceback
from functools import partial
CONTEXT_IS_IN_FOUNDATION = False
try:
    from foundation import folder_central as _
    CONTEXT_IS_IN_FOUNDATION = True
except ImportError:
    pass

def run_command(cmd):
    if CONTEXT_IS_IN_FOUNDATION:
        from foundation.foundation_tools import system
        func = partial(system, None)
    else:
        from shell import shell_cmd
        func = partial(shell_cmd)
    return func(cmd)


KVM_REPO_IN_NOS_PREFIX = 'install/ahv/kvm_host_bundle'
KVM_VERSION_FILE = 'repo/version.txt'
HYP_WITHOUT_RDMA_SUPPORT = ['xen']
MIN_NOS_FOR_RDMA = '5.1'
AUTOMATION_FRAMEWORK_KEY = 'nutanix_automation_framework_2O17'
PACKAGE_FILE = 'install/nutanix-packages.json'
HCL_FILE = 'install/config/hcl.json'
NOS_VERSION_RE = re.compile('(?:\\S+-)+(\\d(?:\\.\\d+){1,3})(?:-\\w+)+')
MASTER_VERSION = '99.0'

def get_packages_path_in_tar(tf, path_suffix=None, path_contains=None, raise_on_error=True):
    """
    Returns the path inside the tarfile which can be uniquely identified using
    the arguments path_contains and path_suffix. The tarfile distinguishes
    between "some/path" and "./some/path". Given a suffix or string distinct
    enough to uniquely identify one file (typically the /logical/ path within
    a tarball), and an open Tarfile instance, find the path we can use to extract
    the file. If both path_contains and path_suffix are provided, both are used
    to identify the file.
    
    Args:
      tf: Opened tarfile object.
      path_suffix: Suffix filter for the file inside tarball.
      path_contains: String which should be part of the file name to be filtered.
      raise_on_error: If True, raises StandardError in case of an exception. If
          False, exceptions will be ignored.
    
    Returns:
      If possible, returns the unique file path inside the tarfile that was
      identified by the filters path_contains and path_suffix.
    
    Exception:
      Raises StandardError if a file cannot be identified uniquely and
      raise_on_error is True.
    """
    if not path_contains and not path_suffix:
        return None
    if path_contains:
        path_matches = filter(lambda x: x.path.find(path_contains) >= 0, tf.getmembers())
        if path_matches and path_suffix:
            path_matches = filter(lambda x: x.path.endswith(path_suffix), path_matches)
    else:
        if path_suffix:
            try:
                path_matches = filter(lambda x: x.path.endswith(path_suffix), tf.getmembers())
            except IOError as e:
                raise StandardError('Corrupted tarball file, %s. %s' % (os.path.basename(tf.name), e))

        if raise_on_error:
            if not path_matches:
                raise StandardError("The tarball %s didn't contain a file %s. This usually means that your NOS tarball is missing a file we expect. Make sure the file you provided is a complete NOS tarball, and not some other file." % (
                 tf.name, path_suffix))
            if len(path_matches) > 1:
                raise StandardError('The path %s matched more than one file in tarball %s. The matching files are %s. This usually means that your NOS tarball is missing a file we expect. Make sure the file you provided is a complete NOS tarball, and not some other file.' % (
                 path_suffix, tf.name, (', ').join(path_matches)))
        else:
            if len(path_matches) != 1:
                return None
    return path_matches[0].path


def prepare_kvm_from_rpms(anaconda_tarball, kvm_iso_path, nos_pkg_path=None, kvm_rpm_pkg=None, workspace=None):
    """
    Prepares KVM installer iso from the provided RPM package or from the
    RPM package in NOS tarball.
    
    Args:
      anaconda_tarball : Anaconda bits.
      kvm_iso_path : Path to where the iso should be generated.
      nos_pkg_path: File system path to NOS tarball.
      kvm_rpm_pkg: KVM rpms tarball containing RPM repo.
      workspace: Workspace to use for generating kvm iso and using temp space.
                 Useful for cli.
    
    Returns:
      None
    
    Raises:
      StandardError if invalid AOS or KVM rpms package is provided.
    """
    if CONTEXT_IS_IN_FOUNDATION:
        logger = logging.getLogger(__file__).info
    else:
        import log
        logger = log.INFO
    if not kvm_rpm_pkg and not nos_pkg_path:
        raise StandardError('AHV RPM tarball / AOS tarball not provided')
    tf = None
    if workspace:
        tmp_path = os.path.join(workspace, 'tmp')
        if not os.path.exists(tmp_path):
            os.makedirs(tmp_path)
    else:
        tmp_path = tempfile.mkdtemp()
    try:
        if not kvm_rpm_pkg:
            tf = tarfile.open(nos_pkg_path)
            kvm_pkg_path = get_packages_path_in_tar(tf=tf, path_suffix='.tar.gz', path_contains=KVM_REPO_IN_NOS_PREFIX, raise_on_error=False)
            if not kvm_pkg_path:
                raise StandardError('AHV rpm tarball is missing in AOS package')
            if kvm_pkg_path[0] == '/':
                kvm_path = os.path.join(tmp_path, kvm_pkg_path[1:])
            else:
                kvm_path = os.path.join(tmp_path, kvm_pkg_path)
            os.makedirs(os.path.dirname(kvm_path))
            data_fd = tf.extractfile(kvm_pkg_path)
            if not data_fd:
                raise StandardError('Could not extract kvm_host_bundle from NOS')
            with open(kvm_path, 'wb') as (fd):
                fd.write(data_fd.read())
            tf.close()
        else:
            kvm_path = kvm_rpm_pkg
        tf = tarfile.open(kvm_path)
        tf.extractall(path=tmp_path)
        tf.close()
        tf = tarfile.open(anaconda_tarball)
        tf.extractall(path=tmp_path)
        tf.close()
        anaconda_path = os.path.join(tmp_path, 'iso')
        repo_path = os.path.join(tmp_path, 'repo')
        run_command(['rm', '-f', kvm_iso_path])
        run_command([
         'mkisofs', '-o', kvm_iso_path, '-T', '-J', '-R', '-f', '-v',
         '-b', 'isolinux/isolinux.bin', '-c', 'isolinux/boot.cat',
         '-no-emul-boot', '-boot-load-size', '4', '-boot-info-table',
         anaconda_path, repo_path])
        logger('AHV iso created in %s' % kvm_iso_path)
    except:
        message = 'Error while trying to process AHV RPMs: %s' % traceback.format_exc()
        logger(message)
        raise StandardError(message)
    finally:
        if tf:
            tf.close()
        if tmp_path:
            shutil.rmtree(tmp_path)

    return


def get_nos_version_from_package_file(package_file):
    try:
        package_manifest = json.load(package_file)
    except Exception as e:
        raise StandardError("The NOS package %s contained a package file, but it doesn't seem to be valid JSON. The package may be corrupt. Here's the problem:\n%s" % (
         nos_package_path, str(e)))

    version_match = NOS_VERSION_RE.match(package_manifest['release'])
    if not version_match:
        print 'The NOS package contained a manifest file, but an unrecognizable release. We will assume this is a dev release and treat it as the very latest version.'
        nos_version = MASTER_VERSION
    else:
        nos_version = version_match.group(1)
    return nos_version


def get_nos_version_from_tarball(nos_package_path):
    if not os.path.exists(nos_package_path):
        filename, file_extension = os.path.splitext(nos_package_path)
        if file_extension == '.gz':
            nos_package_path = filename
            if not os.path.exists(nos_package_path):
                raise StandardError('Could not find the NOS package file at %s' % nos_package_path)
        else:
            raise StandardError('Could not find the NOS package file at %s' % nos_package_path)
    nos_package_path = os.path.expanduser(nos_package_path)
    if not os.path.getsize(nos_package_path) or not tarfile.is_tarfile(nos_package_path):
        raise StandardError('Unable to untar the NOS package file provided at %s. The file may be corrupt or a partial download.' % nos_package_path)
    tarball = tarfile.open(nos_package_path)
    packages_path = get_packages_path_in_tar(tarball, path_suffix=PACKAGE_FILE)
    package_file = tarball.extractfile(packages_path)
    return get_nos_version_from_package_file(package_file)


def get_nos_version_from_dir(nos_package_path):
    package_file = os.path.join(nos_package_path, PACKAGE_FILE)
    try:
        with open(package_file) as (json_data):
            return get_nos_version_from_package_file(json_data)
    except Exception as e:
        raise StandardError("The NOS package %s did not contain a package fileThe package may be corrupt. Here's the problem:\n%s" % (
         nos_package_path, str(e)))


def get_nos_hcl_from_tarball(nos_package_path):
    if not os.path.exists(nos_package_path):
        filename, file_extension = os.path.splitext(nos_package_path)
        if file_extension == '.gz':
            nos_package_path = filename
            if not os.path.exists(nos_package_path):
                raise StandardError('Could not find the NOS package file at %s' % nos_package_path)
        else:
            raise StandardError('Could not find the NOS package file at %s' % nos_package_path)
    nos_package_path = os.path.expanduser(nos_package_path)
    if not os.path.getsize(nos_package_path) or not tarfile.is_tarfile(nos_package_path):
        raise StandardError('Unable to untar the NOS package file provided at %s. The file may be corrupt or a partial download.' % nos_package_path)
    tarball = tarfile.open(nos_package_path)
    packages_path = get_packages_path_in_tar(tarball, path_suffix=HCL_FILE)
    hcl_file = tarball.extractfile(packages_path)
    return hcl_file


def ipv4_to_int(ipv4_addr):
    return struct.unpack('!I', socket.inet_aton(ipv4_addr))[0]


def int_to_ipv4(ipv4_int):
    return socket.inet_ntoa(struct.pack('!I', ipv4_int))


def validate_and_correct_ip(ip):
    """
    Validate and fix ip whenever possible.
    
    Args:
      ip : IP address in string format.
    
    Returns:
      Corrected IP address.
    
    Raises:
      StandardError if input ip is invalid.
    """
    try:
        ip_int = map(int, ip.split('.'))
    except ValueError:
        raise StandardError('Invalid ip: %s' % ip)

    if len(ip_int) != 4:
        raise StandardError('Invalid ip: %s' % ip)
    if filter(lambda x: x > 255 or x < 0, ip_int):
        raise StandardError('Invalid ip: %s' % ip)
    return ('.').join(map(str, ip_int))


def validate_and_correct_netmask(mask):
    """
    Validates and returns the corrected subnet mask. Some users provides
    subnet mask as 255.255.252.000 instead of 255.255.252.0. This function
    converts each octet in string format to integer and then convert it back.
    It also validates each octet in the process.
    
    Args:
      mask: Subnet mask in string form.
    
    Returns:
      Corrected subnet mask in string form.
    
    Raises:
      StandardError if the subnet mask input is invalid and cannot be corrected.
    """
    try:
        mask_int = map(int, mask.split('.'))
    except ValueError:
        raise StandardError('Invalid subnet mask %s' % mask)

    if len(mask_int) != 4:
        raise StandardError('Invalid subnet mask %s' % mask)
    if filter(lambda x: x > 255 or x < 0, mask_int):
        raise StandardError('Invalid subnet mask %s' % mask)
    mask_bin = int(('').join(map(lambda x: format(x, '08b'), mask_int)), 2)
    allf = 4294967295
    if (~mask_bin & allf) + 1 & (~mask_bin & allf):
        raise StandardError('Invalid subnet mask %s' % mask)
    return ('.').join(map(str, mask_int))


def validate_and_correct_network_addresses(global_config):
    """
    Validate and correct ip, gateway and netmask addresses used in imaging.
    
    This function will also verify the ip/gw against it's netmask.
    
    Args:
      global_config: GlobalConfig object for the imaging session.
    
    Raises:
      StandardError if any address/mask is invalid.
    """
    if CONTEXT_IS_IN_FOUNDATION:
        logger = logging.getLogger(__file__).info
    else:
        import log
        logger = log.INFO
    keys = ['cvm_ip', 'hypervisor_ip', 'ipmi_ip',
     'cvm_netmask', 'hypervisor_netmask', 'ipmi_netmask',
     'cvm_gateway', 'hypervisor_gateway', 'ipmi_gateway',
     'hypervisor_nameserver', 'ucsm_ip']
    invalid_attrs = set()
    for node in global_config.nodes:
        if CONTEXT_IS_IN_FOUNDATION:
            logger = node.get_logger()
        for key in keys:
            try:
                address = getattr(node, key, '')
                if address:
                    if 'netmask' in key:
                        address = validate_and_correct_netmask(address)
                    else:
                        if 'nameserver' in key:
                            addresses = address.split(',')
                            ip_list = []
                            for ip in addresses:
                                if ip:
                                    ip_list.append(validate_and_correct_ip(ip))

                            address = (',').join(ip_list)
                        else:
                            address = validate_and_correct_ip(address)
                    setattr(node, key, address)
            except StandardError:
                if CONTEXT_IS_IN_FOUNDATION:
                    logger.error('Invalid %s: %s' % (key, getattr(node, key, '')))
                invalid_attrs.add(key)

    if invalid_attrs:
        raise StandardError('Failed to validate network addresses. Invalid values for attributes: %s. Check node logs for more details' % (' ').join(invalid_attrs))
    bad_settings = collections.defaultdict(list)
    cluster_keys = ['hypervisor_ntp_servers', 'cvm_ntp_servers',
     'cvm_dns_servers']
    for cluster in global_config.clusters:
        if CONTEXT_IS_IN_FOUNDATION:
            c_logger = cluster.get_logger()
        for c_key in cluster_keys:
            c_addr_str = getattr(cluster, c_key, None)
            if c_addr_str:
                c_addr_list = []
                for c_addr in c_addr_str.split(','):
                    if c_addr:
                        c_addr = c_addr.strip()
                        if ' ' in c_addr:
                            if CONTEXT_IS_IN_FOUNDATION:
                                c_logger.error("Invalid network address '%s' in %s. Cannot have whitespace in an IP address" % (
                                 c_addr, c_key))
                            invalid_attrs.add(c_key)
                        else:
                            c_addr_list.append(c_addr)

                setattr(cluster, c_key, (',').join(c_addr_list))

        if invalid_attrs:
            raise StandardError('Invalid values for attributes: %s. Cannot have whitespace in a network address' % (' ').join(invalid_attrs))

    for node in global_config.nodes:
        for ip_type in ['cvm', 'hypervisor', 'ipmi']:
            ip, gw, mask = map(lambda key: getattr(node, '%s_%s' % (ip_type, key), None), [
             'ip', 'gateway', 'netmask'])
            if not ip or not gw:
                continue
            ip_int, gw_int, mask_int = map(ipv4_to_int, [ip, gw, mask])
            if ip_int & mask_int != gw_int & mask_int:
                ip_network = int_to_ipv4(ip_int & mask_int)
                gw_network = int_to_ipv4(gw_int & mask_int)
                if CONTEXT_IS_IN_FOUNDATION:
                    logger.error(('Node({node}) has invalid network settings, {ip_type}_ip({ip} network:{ip_net}) and {ip_type}_gateway({gw} network:{gw_net}) are not in the same subnet').format(node=node, ip_type=ip_type, ip=ip, gw=gw, ip_net=ip_network, gw_net=gw_network))
                bad_settings[(ip_type, ip_network, gw_network)].append(node)

    if bad_settings:
        msg_tpl = '{n} node(s) has invalid {k[0]} network settings, ip and gateway are in different network ({k[1]} and {k[2]})'
        msg = (',').join(map(lambda (k, v): msg_tpl.format(n=len(v), k=k), bad_settings.items()))
        raise StandardError(msg)
    return


def in_same_subnet(ip1, ip2, netmask):
    """
    Check if ip1 and ip2 are in same subnet.
    
    Args:
      ip1, ip2: ipv4 ip, eg. "1.2.3.4"
      netmask: eg. "255.255.255.0"
    """
    ip_int, gw_int, mask_int = map(ipv4_to_int, [ip1, ip2, netmask])
    return ip_int & mask_int == gw_int & mask_int


def validate_aos_package(name=None, fileobj=None, marker='install/nutanix-packages.json'):
    """
    Check if given tarball is a valid AOS package.
    
    Args:
      name: path to a tarball file
      fileobj: a file object of a tarball file
      If fileobj is given, it is used for reading or writing data.
    
    Returns:
      True: if it's a valid AOS package, else False
    """
    if CONTEXT_IS_IN_FOUNDATION:
        logger = logging.getLogger(__file__).exception
    else:
        import log
        logger = log.ERROR
    tf = None
    try:
        if name:
            tf = tarfile.open(name=name)
        else:
            if fileobj:
                tf = tarfile.open(fileobj=fileobj)
            else:
                raise StandardError('Neither file name nor file object is provided')
        tar_path = get_packages_path_in_tar(tf=tf, path_suffix=marker, raise_on_error=True)
        if tar_path:
            for mem in tf.getmembers():
                if marker in mem.name:
                    packages_json = json.load(tf.extractfile(mem))
                    image_type = packages_json.get('image_type', 'PE-image')
                    if image_type != 'PE-image':
                        raise StandardError("AOS tarball should have image type 'PE-image'. But the provided tarball has image type '%s'" % image_type)
                    break

            return True
        return False
    except (StandardError, IOError, OSError, KeyError, tarfile.ReadError, tarfile.TarError) as e:
        logger("Exception in validating AOS tarball '%s': %s" % (name, e))
        return False
    finally:
        if tf:
            tf.close()

    return