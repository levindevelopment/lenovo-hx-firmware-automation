# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/foundation_tools.py
# Compiled at: 2019-02-15 12:42:10
import contextlib, errno, functools, hashlib, json, logging, math, os, platform, re, shutil, socket, struct, tarfile, tempfile, threading, time, warnings, subprocess32 as subprocess
from collections import defaultdict
from itertools import izip
import paramiko, psutil
from scp import SCPClient, SCPException
from foundation import folder_central
from foundation import imaging_context
from foundation import iso_whitelist
from foundation.shared_functions import get_packages_path_in_tar, MASTER_VERSION, NOS_VERSION_RE
from foundation.portable import is_portable, is_mac, is_win
FOUNDATION_CURRENT_VERSION = None
MAC_RE = re.compile('^[0-9a-fA-F]{12}$')
ANSI_ESC_RE = re.compile('\\x1b[^m]*m')
UNCOMPRESSED_RE = re.compile('\\s+\\d+\\s+(\\d+)\\s+.*')
FOUNDATION_VERSION_RE = re.compile('(?:foundation-)?(\\d(?:\\.\\d+){1,3})(?:-\\w+)?')
SESSION_ID_RE = re.compile('[0-9]+-[0-9]+-[0-9]+')
UPLOAD_RETRY = 6
foundation_tar_lock = threading.Lock()
thread_safe_lock_dict = defaultdict(threading.Lock)
default_logger = logging.getLogger(__file__)
PRODUCT_PART_NUMBER_RE = re.compile('Product PartModel Number *.* *= *(?P<result>[\\w-]+)')
CHASSIS_SERIAL_RE = re.compile('Chassis Serial Number .* *= *(?P<result>[\\w-]+)')
PRODUCT_SERIAL_RE = re.compile('Product Serial Number *.* *= *(?P<result>[\\w-]+)')
VALID_BLOCK_ID = re.compile('[\\w-]+$')
NOS_AHV_BUNDLE_MAGIC = 'AHV bundled with AOS (version 4.6+)'
HYP_TYPES = [
 'kvm', 'esx', 'hyperv', 'linux', 'xen']
DEFAULT_CVM_KEYS = []
if imaging_context.get_context() == imaging_context.FIELD_VM:
    DEFAULT_CVM_KEYS.append(os.path.expanduser('~/.ssh/id_rsa'))
    DEFAULT_CVM_KEYS.append(os.path.expanduser('~/ssh_keys/nutanix'))
else:
    DEFAULT_CVM_KEYS.append(folder_central.get_templates_file('nutanix.key'))
DEFAULT_CVM_KEYS = filter(lambda p: os.path.exists(p), DEFAULT_CVM_KEYS)
SSH_TIMEOUT = 30
SSH_SEMA = threading.Semaphore(value=32)
DEVNULL = open(os.devnull)
CREATE_NO_WINDOW = 134217728

def which_exec(exec_name):
    """
    use executable from lib/bin/cygwin/ if found.
    """
    exec_path = os.path.join(folder_central.get_cygwin_bin(), exec_name) + '.exe'
    if os.path.isfile(exec_path):
        default_logger.debug('using %s for %s', exec_path, exec_name)
        return exec_path
    return exec_name


def system(config, cmd_list, throw_on_error=True, log_on_error=True, timeout=None, log_command=True):
    """
      Execute shell command and return captured stdout.
      If timeout occurs, -9 (SIGKILL) is returned in return_code
    
    Returns:
      (stdout, stderr, return_code)
    """
    stdout = ''
    stderr = ''
    if platform.system() == 'Windows':
        cmd_list[0] = which_exec(cmd_list[0])
    if log_on_error:
        if config:
            logger = config.get_logger()
        else:
            logger = default_logger
    if log_command:
        cmd_as_str = (' ').join(cmd_list)
    else:
        cmd_as_str = '<obfuscated_command>'
    try:
        if is_win():
            process = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=DEVNULL, creationflags=CREATE_NO_WINDOW)
        else:
            process = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(timeout=timeout)
        return_code = process.returncode
    except subprocess.TimeoutExpired:
        if log_on_error:
            logger.error("Command '%s' timed out" % cmd_as_str)
        process.kill()
        process.wait()
        return_code = process.returncode
    except OSError:
        if log_on_error:
            logger.exception("Could not execute '%s'" % cmd_as_str)
        return_code = -1

    if return_code != 0:
        message = "Command '%s' returned error code %d\n" % (
         cmd_as_str, return_code)
        try:
            stdout = ANSI_ESC_RE.sub('', stdout.decode('ascii', 'ignore'))
            stderr = ANSI_ESC_RE.sub('', stderr.decode('ascii', 'ignore'))
        except Exception as e:
            logger.exception(str(e))
            raise

        message += 'stdout:\n%s\nstderr:\n%s' % (stdout, stderr)
        if log_on_error:
            logger.error(message)
        if throw_on_error:
            raise StandardError(message)
    return (
     stdout, stderr, return_code)


def get_ssh_client(*args, **kwargs):
    with SSH_SEMA:
        timeout = kwargs.get('timeout', None)
        assert timeout is None or timeout > 0, 'timeout cannot be negative: %s' % timeout
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if 'key_filename' not in kwargs:
            kwargs['key_filename'] = DEFAULT_CVM_KEYS
        if timeout:
            timer = threading.Timer(timeout, client.close)
            timer.daemon = True
            timer.start()
        else:
            timer = None
        client.connect(*args, **kwargs)
        if timer:
            timer.cancel()
        return client
    return


def ssh(config, ip, command, throw_on_error=True, user='nutanix', password='nutanix/4u', log_on_error=True, timeout=SSH_TIMEOUT, escape_cmd=False, **kwargs):
    """
    Execute the commands via ssh on the remote machine with given ip.
    
    Note: some sshd impl doesn't handle the fallback-to-password well,
          use `key_filename=None, look_for_keys=False` to disable key-based auth
          explicitly to work with those servers (eg. ilo's sshd).
    """
    logger = default_logger
    if log_on_error and config:
        logger = config.get_logger()
    params = {'hostname': ip, 'username': user, 'password': password}
    if timeout:
        params['timeout'] = timeout
    params.update(kwargs)
    try:
        client = get_ssh_client(**params)
    except (paramiko.AuthenticationException, paramiko.SSHException,
     socket.error, Exception) as e:
        if log_on_error:
            logger.exception('Exception on executing cmd: %s', command)
        if throw_on_error:
            raise
        else:
            return (
             '', str(e), -1)

    cmd_str = (' ').join(command)
    if escape_cmd:
        warnings.warn('escape_cmd is deprecated', DeprecationWarning)
    out, err = [], []
    if timeout:
        timer = threading.Timer(timeout, client.close)
        timer.daemon = True
        timer.start()
    else:
        timer = None
    try:
        stdin, stdout, stderr = client.exec_command(cmd_str, timeout=timeout)
        channel = stdout.channel
        while not channel.exit_status_ready():
            if channel.recv_ready():
                outbuf = channel.recv(1024)
                while outbuf:
                    out.append(outbuf)
                    outbuf = channel.recv(1024)

            if channel.recv_stderr_ready():
                errbuf = channel.recv_stderr(1024)
                while errbuf:
                    err.append(errbuf)
                    errbuf = channel.recv_stderr(1024)

        else:
            out.append(stdout.read())
            err.append(stderr.read())

        exit_status = stdout.channel.recv_exit_status()
    except (socket.timeout, paramiko.SSHException, EOFError) as e:
        err.append(str(e))
        exit_status = -1
    finally:
        client.close()

    if timer:
        timer.cancel()
    out = ('').join(out)
    err = ('').join(err)
    if exit_status != 0:
        message = "Command '%s' returned error code %d\n" % (
         (' ').join(command), exit_status)
        message += 'stdout:\n%s\nstderr:\n%s' % (out, err)
        if log_on_error:
            logger.error(message)
        if throw_on_error:
            raise StandardError(message)
    return (out, err, exit_status)


def scp(config, ip, target_path, files, throw_on_error=True, user='nutanix', password='nutanix/4u', log_on_error=True, timeout=SSH_TIMEOUT, recursive=False):
    """
    Transfer files via scp on the remote machine with given ip.
    
    Args:
      timeout: Use None for no-timeout limit , do not use -1, that means
      timeout immediately after (or before) connect.
    """
    logger = default_logger
    if config and log_on_error:
        logger = config.get_logger()
    params = {'hostname': ip, 'username': user, 'password': password}
    if timeout:
        params['timeout'] = timeout
    try:
        client = get_ssh_client(**params)
    except (paramiko.AuthenticationException, paramiko.SSHException,
     socket.error, Exception) as e:
        if log_on_error:
            logger.exception('Failed to connect to remote host %s', ip)
        if throw_on_error:
            raise
        else:
            return (
             '', str(e), -1)
    else:
        scp_client = SCPClient(client.get_transport(), socket_timeout=timeout)
        try:
            scp_client.put(files, target_path, recursive=recursive)
        except SCPException as e:
            if log_on_error:
                logger.exception('Failed to scp files %s to %s:%s', files, ip, target_path)
            if throw_on_error:
                raise
            return (
             '', str(e), -1)

    return ('', '', 0)


def upload(installer_type='', local_file=None, remote_file=None, target_config=None, verify_existence=True, throw_on_error=False):
    """
    Upload local file to remote (target_config.cvm_ip) via scp
    
    """
    if not local_file or not target_config:
        return
    logger = target_config.get_logger()
    target_path = remote_file if remote_file else local_file
    pdir = os.path.dirname(target_path)
    if verify_existence:
        target_check = "test -f '%s'" % target_path
        out, err, ret = ssh(config=target_config, ip=target_config.cvm_ip, command=[
         target_check], throw_on_error=False)
        if ret == 0:
            message = 'Target file %s(%s) already exists. Skipping upload' % (
             target_config.cvm_ip, target_path)
            logger.info(message)
            return local_file
        message = 'Target file %s(%s) not present. Uploading file' % (
         target_config.cvm_ip, target_path)
        logger.info(message)
    for retry in range(UPLOAD_RETRY):
        out, err, ret = ssh(config=target_config, ip=target_config.cvm_ip, command=[
         'mkdir', '-p', pdir], throw_on_error=False)
        out, err, ret = scp(config=target_config, ip=target_config.cvm_ip, target_path=target_path, files=[
         local_file], log_on_error=True, throw_on_error=False, timeout=None)
        if ret == 0:
            return local_file
    else:
        message = 'Failed to upload %s(%s) to %s:%s' % (installer_type,
         local_file, target_config.cvm_ip, target_path)
        logger.error(message)
        if throw_on_error:
            raise StandardError(message)
        return


def ipmitool(node_config, cmd_list, throw_on_error=True):
    return system(node_config, [
     folder_central.get_ipmitool(),
     '-I', 'lanplus',
     '-H', node_config.ipmi_ip,
     '-U', node_config.ipmi_user,
     '-P', node_config.ipmi_password] + cmd_list, throw_on_error=throw_on_error, log_on_error=False, timeout=60, log_command=False)


def ipmitool_with_retry(node_config, cmd_list, throw_on_error=True, retries=5, delay_s=5, ipmitool_=ipmitool):
    """
    Execute command on remote BMC via the ipmitool.
    Args:
      node_config : A NodeConfig object.
      cmd_list    : The commands to be executed as a list.
      throw_on_error : Whether to throw on error.
      retries     : Number of retries after first failed attempt.
      delay_s     : Delay between retries.
      ipmitool_    : Function which provides the functionality of ipmitool.
    Returns:
      stdout, stderr, exit_code on success.
    Raises:
      Exception raised by system() once retries have exhausted and
      throw_on_error is True.
    """
    while True:
        try:
            stdout, stderr, return_code = ipmitool_(node_config, cmd_list, throw_on_error=throw_on_error)
            if return_code == 0 or retries == 0:
                return (stdout, stderr, return_code)
        except Exception as e:
            if retries == 0:
                if throw_on_error:
                    raise e
                return (str(e), str(e), 1)
        else:
            retries -= 1
            time.sleep(delay_s)


def get_my_ip(dest_ip, port=80):
    """
    Find foundation external IP address by UDP connect.
    NOTE: dest_ip:port could be an invalid UDP address, `connect` will route
    the local socket, no packet is send in this process.
    
    Raises:
      socket.error(IOError) when dest_ip is not in the same subnet and default
      gateway is not set.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((dest_ip, port))
    my_ip = s.getsockname()[0]
    s.close()
    return my_ip


def get_interface_ip(ifname='eth0'):
    """
    Find local IP address assigned to a given interface without gateway.
    
    Raises:
      StandardError containing IOError from underlying socket/ioctl call.
    """
    import fcntl
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 35093, struct.pack('256s', ifname[:15]))[20:24])
    except Exception as exp:
        message = 'An exception occurred while trying to get local ip of interface %s.' % ifname
        default_logger.error(message)
        raise StandardError(str(exp))


def get_md5sum(file_name):
    """
    Calculate the md5sum of file.
    Returns a valid md5sum if successful, raises StandardError otherwise.
    """
    logger = default_logger
    try:
        with open(file_name, 'rb') as (fh):
            return get_md5sum_obj(fh)
    except IOError as io_err:
        message = ''
        if io_err.errno == errno.ENOENT:
            message = 'Unable to compute md5sum of file at path %s because it does not exist' % file_name
        else:
            if io_err.errno == errno.EACCES:
                message = "Unable to compute md5sum of file at path %s because file permissions don't allow it to be read by the current user" % file_name
            else:
                message = 'Encountered exception while trying to compute md5sum of file at path %s' % file_name
                logger.exception(str(io_err))
        raise StandardError(str(message))
    except Exception as exc:
        raise StandardError(str(exc))


def get_md5sum_obj(file_obj):
    """
    Calculate the md5sum of file object.
    Returns a valid md5sum if successful, None otherwise.
    """
    md5 = insecure_md5()
    block_size = 128 * md5.block_size
    while True:
        data = file_obj.read(block_size)
        if not data:
            break
        md5.update(data)

    return md5.hexdigest()


def get_sha256sum(file_name):
    """
    Calculate the sha256sum of file.
    Returns a valid sha256sum if successful, None otherwise.
    """
    try:
        with open(file_name, 'rb') as (fh):
            return get_sha256sum_obj(fh)
    except:
        return

    return


def get_sha256sum_obj(file_obj):
    """
    Calculate the sha256sum of file object.
    Returns a valid sha256sum if successful, None otherwise.
    """
    sha = hashlib.new('sha256')
    block_size = 128 * sha.block_size
    while True:
        data = file_obj.read(block_size)
        if not data:
            break
        sha.update(data)

    return sha.hexdigest()


def get_nutanix_ids():
    """
    Returns uid and gid of nutanix user.
    """
    import pwd
    entry = pwd.getpwnam('nutanix')
    uid = entry[2]
    gid = entry[3]
    return (
     uid, gid)


def assign_nutanix_owner(path):
    if is_portable():
        return
    if os.path.isdir(path):
        os.chmod(path, 493)
    else:
        os.chmod(path, 420)
    if os.geteuid() == 0:
        uid, gid = get_nutanix_ids()
        os.chown(path, uid, gid)


def get_nos_version_from_cvm(cvm_ip, config=None):
    """
    Get the NOS version from a CVM by reading the
    /etc/nutanix/release_version file.
    
    Args:
      cvm_ip : IP of target CVM
      config : A NodeConfig object, used only for logging purposes.
    Returns:
      The NOS version if it matches the NOS regex in the form of [a,b,c].
      [int(MASTER_VERSION)] in other cases.
    Raises:
      StandardError if unable to ssh to cvm_ip.
    
    Additional note: NO SUPPORT FOR "-E" notation.
    """
    logger = config.get_logger() if config else default_logger
    cmd = ['cat', '/etc/nutanix/release_version']
    if cvm_ip:
        release_version, _, _ = ssh(config, cvm_ip, cmd)
    else:
        release_version, _, _ = system(None, cmd)
    nos_version_match = NOS_VERSION_RE.match(release_version)
    if not nos_version_match:
        message = "Couldn't parse nutanix version %s from CVM ip %s" % (
         release_version, cvm_ip)
        logger.info(message)
        logger.info('Foundation will assume this is a dev build')
        return map(int, MASTER_VERSION.split('.'))
    return map(int, nos_version_match.group(1).split('.'))


def get_cvm_uptime(cvm_ip, config=None, throw_on_error=False):
    """
    Get the uptime from a CVM by reading /proc/uptime
    
    Args:
      cvm_ip : IP of target CVM
      throw_on_error : Raises StandardError if set to true
    Returns:
      The duration for which CVM is up in seconds
    """
    proc_uptime, _, ret = ssh(config, cvm_ip, ['cat', '/proc/uptime'], throw_on_error=throw_on_error)
    if ret != 0:
        return None
    return float(proc_uptime.split()[0])


def get_ncc_version_from_cvm(cvm_ip, config=None):
    """
    Get the NCC version from a CVM.
    
    Args:
      cvm_ip : IP of target CVM.
      config : A Config object, used only for logging purposes.
    Returns:
      The NCC version if it matches the NCC regex in the form of [a,b,c].
      [int(MASTER_VERSION)] in other cases.
    Raises:
      StandardError if unable to ssh to cvm_ip.
    
    """
    logger = config.get_logger() if config else default_logger
    version_output, _, _ = ssh(config, cvm_ip, [
     'ncc/bin/ncc', '--version'])
    logger.debug('NCC version: %s' % version_output)
    ncc_version_match = re.match('(\\d(?:\\.\\d+){1,3})[\\-0-9a-f]*', version_output)
    if not ncc_version_match:
        message = "Couldn't parse ncc version %s from CVM ip %s" % (
         version_output, cvm_ip)
        logger.warn(message)
        return map(int, MASTER_VERSION.split('.'))
    return map(int, ncc_version_match.group(1).split('.'))


def update_metadata(updates, session_id):
    """
    Logs the provided key-value pairs as JSON to debug.log for the session in
    to allow for easy processing-end parsing via Insights, Nusights, or
    equivalent.
    
    Args:
      updates: a dict to update metadata with
    Returns: success or failure (true or false)
    """
    if not isinstance(session_id, (str, unicode)) or not SESSION_ID_RE.match(session_id):
        return False
    session_log = logging.getLogger('foundation.session.%s' % session_id)
    try:
        session_log.info('metadata update: %s' % json.dumps(updates))
        return True
    except (OSError, IOError, ValueError, TypeError):
        return False


def normalize_mac(mac):
    if MAC_RE.match(mac):
        mac = (':').join((mac[i:i + 2] for i in range(0, 12, 2)))
    return mac


def _get_free_space_on_device_in_mb(path):
    return psutil.disk_usage(path).free / 1024 / 1024


def _ignore_error(exception):
    pass


def _get_disk_usage_in_mb(path):
    space = 0
    if not os.path.exists(path):
        pass
    else:
        if os.path.isfile(path):
            space = os.path.getsize(path)
        else:
            for root, _, files in os.walk(path, onerror=_ignore_error):
                space += sum(map(os.path.getsize, files))

    return int(math.ceil(space * 1.0 / 1024 / 1024))


def _get_device(path):
    return os.stat(path).st_dev


def _get_uncompressed_size(file_gz):
    output, err, ret = system(None, ['gzip', '-d', '-l', file_gz])
    for line in output.splitlines():
        size_match = UNCOMPRESSED_RE.match(line)
        if size_match:
            break
    else:
        raise StandardError('Unable to get uncompressed size of %s.\nstdout, stderr=(%s, %s)' % (
         file_gz, output, err))

    size = int(size_match.group(1))
    return size


def check_disk_space(hypervisors=None, nos=None):
    """
    Checks whether enough disk space is available on the VM to start imaging.
    
    Note: phoenix is not taking any cache space anymore.
    
    Args:
      hypervisors: Dictionary of hypervisor isos.
      nos: NOS package path.
    Returns:
      (0, None, -1) if there is enough disk space available.
      (1, error message, -1) if any error occurred while checking for free disk
      space.
      (2, error message, available disk space) if there is not enough disk space
      available. Freeing up unwanted files may help in creating enough disk
      space.
    """
    hypervisors = hypervisors or {}
    min_cache_space = 0
    min_tmp_space = 0
    nos_size_in_mb = 0
    if nos and os.path.exists(nos):
        if nos.endswith('.gz'):
            nos_size_in_mb = _get_uncompressed_size(nos) / 1048576
            free_space_on_device = _get_free_space_on_device_in_mb(os.path.dirname(nos))
            if free_space_on_device < nos_size_in_mb:
                return (2, 'Insufficient free disk space for decompression of NOS package',
                 free_space_on_device)
        elif nos.endswith('.tar'):
            nos_size_in_mb = os.path.getsize(nos) / 1048576
        else:
            return (1, 'Unknown format of nos package', -1)
    for hyp, iso_path in hypervisors.iteritems():
        if hyp == 'kvm':
            if os.path.exists(iso_path):
                min_tmp_space = min_tmp_space + 2 * _get_disk_usage_in_mb(iso_path)
            else:
                kvm_from_nos_size_in_mb = 500
                min_tmp_space = min_tmp_space + kvm_from_nos_size_in_mb

    cushion_size_in_mb = 256
    min_cache_space = min_cache_space + cushion_size_in_mb
    min_tmp_space = min_tmp_space + cushion_size_in_mb
    if imaging_context.get_context() == imaging_context.FIELD_VM:
        min_tmp_space += nos_size_in_mb
    cache = folder_central.get_cache_folder()
    tmp = folder_central.get_tmp_folder()
    tmp_size_in_mb = _get_disk_usage_in_mb(tmp)
    cache_size_in_mb = _get_disk_usage_in_mb(cache)
    if _get_device(cache) == _get_device(tmp):
        free_space = _get_free_space_on_device_in_mb(tmp)
        available_space = free_space + tmp_size_in_mb + cache_size_in_mb
        required_space = min_tmp_space + min_cache_space
        if available_space < required_space:
            return (2,
             'Not enough free space on disk. Reported %d MB, need at least %d MB' % (
              available_space, required_space),
             available_space)
    else:
        complaints = []
        free_tmp_space = _get_free_space_on_device_in_mb(tmp)
        available_tmp_space = free_tmp_space + tmp_size_in_mb
        if available_tmp_space < min_tmp_space:
            complaints.append("The device holding foundation/tmp doesn't have enough free space. The tmp directory needs at least %d MB, but only %d MB is available." % (
             min_tmp_space, available_tmp_space))
        free_cache_space = _get_free_space_on_device_in_mb(cache)
        available_cache_space = free_cache_space + cache_size_in_mb
        if available_cache_space < min_cache_space:
            complaints.append("The device holding foundation/cache doesn't have enough free space. The cache directory needs at least %d MB, but only %d MB is available." % (
             min_cache_space, available_cache_space))
        if complaints:
            return (2, ('\n').join(complaints),
             available_tmp_space + available_cache_space)
    return (0, None, -1)


def get_current_foundation_version():
    return FOUNDATION_CURRENT_VERSION


def read_foundation_version(foundation_version_file=None):
    """
    Returns the foundation_version from reading the foundation_version_file.
    Returns master version, if contents don't match expected regex.
    Raises:
      StandardError when foundation_version_file does not exist if given.
      When foundation_version_file is not given and the default version
      file does not exist, StandardError is still raised.
    """
    if not foundation_version_file:
        foundation_version_file = folder_central.get_foundation_version()
    if not os.path.exists(foundation_version_file):
        raise StandardError('%s does not exist' % foundation_version_file)
    with open(foundation_version_file) as (fh):
        match = FOUNDATION_VERSION_RE.match(fh.read())
        if match:
            return match.group(1)
        return MASTER_VERSION


def compare_foundation_version_strings(string_a, string_b):
    version_match_a = FOUNDATION_VERSION_RE.match(string_a)
    if version_match_a:
        version_a = [ int(digit) for digit in version_match_a.group(1).split('.') ]
    else:
        version_a = [
         99, 0]
    version_match_b = FOUNDATION_VERSION_RE.match(string_b)
    if version_match_b:
        version_b = [ int(digit) for digit in version_match_b.group(1).split('.') ]
    else:
        version_b = [
         99, 0]
    return cmp(version_a, version_b)


def newer_than_target_version(target_version):
    """
    Compares the current version of Foundation with the given
    target_version.
    Returns:
      True if current foundation is at a higher version or
           if current foundation is a dev build.
      False in all other cases.
    """
    local_version_str = get_current_foundation_version()
    if not local_version_str:
        return True
    local_version = [ int(digit) for digit in local_version_str.split('.') ]
    target_version_match = FOUNDATION_VERSION_RE.match(target_version)
    if not target_version_match:
        return False
    target_version = map(int, target_version_match.group(1).split('.'))
    return local_version > target_version


def get_foundation_tar(dirs_to_keep=None):
    """
    Creates a tarball containing foundation and the data directories in
    dirs_to_keep, if not already created, and returns the absolute path of the
    tarball.
    """
    dirs_to_keep = dirs_to_keep or []
    exclude_set = set()

    def ignore_path(path):
        exclude_set.add(os.path.abspath(path))

    for hyp in HYP_TYPES:
        if hyp not in dirs_to_keep:
            hyp_dir = getattr(folder_central, 'get_%s_isos_folder' % hyp)()
            ignore_path(hyp_dir)

    if 'nos' not in dirs_to_keep:
        ignore_path(folder_central.get_nos_folder())
    ignore_path(os.path.join(folder_central.get_foundation_dir(), 'log'))
    ignore_path(os.path.join(folder_central.get_foundation_dir(), 'tmp'))
    ignore_path(os.path.join(folder_central.get_foundation_dir(), 'persisted_config.json'))
    ignore_path(folder_central.get_tmp_folder())
    ignore_path(folder_central.get_sessions_root_folder())
    ignore_path(folder_central.get_cache_folder())
    ignore_path(folder_central.get_persisted_config_path())
    ignore_path(folder_central.get_foundation_settings_path())
    ignore_path(folder_central.get_factory_settings_path())

    def exclude_fn(fn):
        return fn in exclude_set

    tar_dir = folder_central.get_http_files_folder()
    filename = 'foundation'
    for req_param in HYP_TYPES + ['nos']:
        if req_param in dirs_to_keep:
            filename += '-%s' % req_param

    filename = '%s.tar' % filename
    tar_file = '%s/%s' % (tar_dir, filename)
    with contextlib.nested(foundation_tar_lock):
        if not os.path.isfile(tar_file):
            tar = tarfile.open(tar_file, mode='w')
            tar.add(os.path.realpath(folder_central.get_foundation_dir()), arcname='foundation', exclude=exclude_fn)
            tar.close()
    return tar_file


def get_kvm_package_in_nos(nos_pkg_path, logger=None):
    """
    Returns the name of the KVM RPM bundle embedded in NOS, if one exists.
    
    Args:
      nos_pkg_path: Complete path to the NOS tarball.
      logger: Logging object to be used in case of any exception.
    
    Returns:
      Name of the KVM RPM bundle embedded in NOS. If KVM bundle is not found,
      returns None.
    """
    from shared_functions import KVM_REPO_IN_NOS_PREFIX
    tf = None
    try:
        tf = tarfile.open(nos_pkg_path)
        kvm_pkg_path = get_packages_path_in_tar(tf=tf, path_suffix='.tar.gz', path_contains=KVM_REPO_IN_NOS_PREFIX, raise_on_error=False)
        if kvm_pkg_path:
            return os.path.basename(kvm_pkg_path)
    except:
        if not logger:
            logger = default_logger
        logger.exception('Exception in finding embedded KVM bundle')
        return
    finally:
        if tf:
            tf.close()

    return


def get_kvm_version_in_nos(nos_pkg_path=None, nos_tf=None):
    """
    Returns the version of KVM in NOS.
    
    Args:
      nos_pkg_path: Complete path to the NOS tarball. This will be used if
          tarfile object is not provided.
      nos_tf: Tarfile object of the NOS tarball which is already opened.
          Caller must close this object once the function returns.
    
    Returns:
      Version of the AHV tarball in NOS.
    """
    from shared_functions import KVM_REPO_IN_NOS_PREFIX, KVM_VERSION_FILE
    if not nos_pkg_path and not nos_tf:
        return
    tf = None
    tmp_path = None
    try:
        tmp_path = tempfile.mkdtemp()
        if nos_tf:
            kvm_pkg_path = get_packages_path_in_tar(tf=nos_tf, path_suffix='.tar.gz', path_contains=KVM_REPO_IN_NOS_PREFIX, raise_on_error=False)
            if not kvm_pkg_path:
                return
            nos_tf.extract(member=kvm_pkg_path, path=tmp_path)
        else:
            tf = tarfile.open(nos_pkg_path)
            kvm_pkg_path = get_packages_path_in_tar(tf=tf, path_suffix='.tar.gz', path_contains=KVM_REPO_IN_NOS_PREFIX, raise_on_error=False)
            if not kvm_pkg_path:
                return
            tf.extract(member=kvm_pkg_path, path=tmp_path)
            tf.close()
        kvm_path = os.path.join(tmp_path, kvm_pkg_path)
        kvm_version = None
        tf = tarfile.open(kvm_path)
        kvm_version_path = get_packages_path_in_tar(path_suffix=KVM_VERSION_FILE, tf=tf, raise_on_error=False)
        if kvm_version_path:
            tf.extract(member=kvm_version_path, path=tmp_path)
            with open(os.path.join(tmp_path, kvm_version_path), 'r') as (fd):
                kvm_version = fd.readline().strip()
        tf.close()
        if not kvm_version:
            md5sum = get_md5sum(kvm_path)
            whitelist = iso_whitelist.get_whitelist()['iso_whitelist']
            if md5sum in whitelist:
                kvm_version = whitelist[md5sum]['version']
        return kvm_version
    except:
        return
    finally:
        if tf:
            tf.close()
        if tmp_path:
            shutil.rmtree(tmp_path)

    return


def extract_file_from_compressed_tar(compressed_tar, path_suffix, path_contains):
    """
    A generic utility function to extract out a file from a given
    compressed tar.
    Args:
      compressed_tar : Path to the compressed file.
      path_suffix    : Same as in get_packages_path_in_tar
      path_contains  : Same as in get_packages_path_in_tar
    Returns:
      (extract_dir, path_to_extracted_file) on success.
      (None, None) on failure.
    Note:
      1. It is the callers responsibility to clean up the extract_dir.
      2. If a file can't be uniquely identified within the tar, it is
         treated as failure. Refer get_packages_path_in_tar.
    """
    logger = default_logger
    return_tuple = (None, None)
    if not os.path.exists(compressed_tar):
        return return_tuple
    tf = None
    extract_dir = tempfile.mkdtemp()
    try:
        tf = tarfile.open(compressed_tar)
        target_file_path = get_packages_path_in_tar(tf=tf, path_suffix=path_suffix, path_contains=path_contains, raise_on_error=False)
        if not target_file_path:
            logger.error('Could not find the target file with path_suffix as %s, path_contains as %s, in the compressed file %s' % (
             path_suffix, path_contains, compressed_tar))
            return return_tuple
        if target_file_path[0] == '/':
            target_path = os.path.join(extract_dir, target_file_path[1:])
        else:
            target_path = os.path.join(extract_dir, target_file_path)
        os.makedirs(os.path.dirname(target_path))
        data_fd = tf.extractfile(target_file_path)
        if not data_fd:
            logger.error('Could not extract %s from %s' % (
             target_file_path, compressed_tar))
            return return_tuple
        logger.debug('Extracting %s from %s' % (target_file_path, compressed_tar))
        with open(target_path, 'wb') as (write_fd):
            shutil.copyfileobj(data_fd, write_fd)
        tf.close()
        return_tuple = (extract_dir, target_path)
    except Exception as e:
        logger.exception('Exception while trying to extract file')
    finally:
        if tf:
            tf.close()
        if return_tuple[0] is None:
            shutil.rmtree(extract_dir)

    return return_tuple


def compare_version_strings(v1, v2):
    """
    Compare version strings of the form "a.b.c".
    Note: If version string is None or empty, it is treated as "0.0".
    Args:
      v1: Version string 1.
      v2: Version string 2.
    Return:
      -1 if version string 1 is smaller.
      0 if version string 1 is same as version string 2 .
      1 if version string 1 is larger.
    """

    def to_int_list(version):
        if not version:
            version = '0.0'
        return map(int, version.split('.'))

    return cmp(to_int_list(v1), to_int_list(v2))


def tmap(func, args_list=None, kwargs_list=None):
    """ A function runs func in parallel/threads.
    
    Args:
      func: a callable function object
            eg. lambda a, b: a + b
      args_list: list of tuple as args
                 eg. [(1, 2), (3, 4)]
      kwargs_list: list of dict as kwargs
    
    Hint:
      use `zip` to convert args to args_list
      zip([1, 2, 3]) => [(1,), (2,), (3,)]
    
    Returns:
      list of value returned by each func(*args, **kwargs)
      >>> tmap(func=int, args_list=zip("123"))
      [1, 2, 3]
    
    Raises:
      StandardError("message", exception_list, result_list)
      >>> tmap(func=int, args_list=zip("1b"))
      StandardError("Failed to execute some task", [None, ValueError], [1, None])
    """
    if not (args_list or kwargs_list):
        default_logger.warn('tmap was called %s with empty args and kwargs, ignoring', func)
        return []
    if not (args_list is not None and kwargs_list is not None and len(args_list) == len(kwargs_list)):
        raise AssertionError('args_list and kwargs_list must be at same length')
    if args_list and kwargs_list is None:
        kwargs_list = [{}] * len(args_list)
    else:
        if kwargs_list and args_list is None:
            args_list = [
             ()] * len(args_list)
    assert all(map(lambda i: isinstance(i, (tuple, list)), args_list)), 'args must be tuple or list'
    assert all(map(lambda i: isinstance(i, dict), kwargs_list)), 'kwargs must be dict'
    threads = {}
    results = {}
    exceptions = {}
    for i, (args, kwargs) in enumerate(izip(args_list, kwargs_list)):

        def warp_func(i_=i, args_=args, kwargs_=kwargs):
            try:
                results[i_] = func(*args_, **kwargs_)
            except Exception as e:
                default_logger.exception('Failed to execute %s %s %s' % (
                 func, args, kwargs))
                exceptions[i_] = e

        threads[i] = threading.Thread(target=warp_func)
        threads[i].daemon = True
        threads[i].start()

    for thread in threads.values():
        thread.join()

    exception_list = map(exceptions.get, range(len(args_list)))
    result_list = map(results.get, range(len(args_list)))
    if exceptions:
        raise StandardError('Failed to execute %s' % func, exception_list, result_list)
    return result_list


def run_command_on_cvms(ip_cmd_map, cluster_config, timeout_secs=None, log_on_error=True):
    """
    Run command on CVMs in parallel.
    
    ip_cmd_map: dict mapping from ip to the command to run on each CVM.
                cmd here is a list of args. Example: ["ls","-l"]
    
    timeout_secs: The ssh command is timed for this much of secs.
                  timeout_secs = None or 0 implies waiting forever for the cmds
                  to finish.
    
    Returns dict of command results mapping from ip to (stdout, stderr, retval).
    retval = -1 on command timeout.
    If there was an error executing the command, (None, None, None) is returned.
    Note that ssh command timing out is not an error executing the command.
    """
    logger = cluster_config.get_logger()
    result_map = {}
    args_list = map(lambda (ip, cmd): (cluster_config, ip, cmd), ip_cmd_map.iteritems())
    kwargs_list = [
     {'throw_on_error': False, 'timeout': timeout_secs, 'log_on_error': log_on_error}] * len(ip_cmd_map)
    try:
        results = tmap(ssh, args_list=args_list, kwargs_list=kwargs_list)
    except StandardError as e:
        if len(e.args) != 3:
            raise
        msg, exceptions, results = e.args
        for (ip, cmd), exception in zip(ip_cmd_map.iteritems(), exceptions):
            logger.warn('Command %s failed on %s', cmd, ip)
            result_map[ip] = (None, None, None)

        results = results

    for (ip, cmd), result in zip(ip_cmd_map.iteritems(), results):
        result_map[ip] = result

    return result_map


def unsafe(func):
    """ threading-safing unsafe functions """

    def thread_safe_func(*args, **kwargs):
        with thread_safe_lock_dict[func]:
            return func(*args, **kwargs)

    return thread_safe_func


def parse_smc_fru(fru):
    """
    Args:
      fru: fru string in SMC format.
    
    Returns: dictionary with keys product_part_number, chassis_serial,
             product_serial
    
    TODO: enhance to include all keys, and make it a full parser.
    """
    fru_dict = {}
    result = PRODUCT_PART_NUMBER_RE.search(fru)
    if result:
        product_part_number = result.group('result')
    else:
        return fru_dict
    result = CHASSIS_SERIAL_RE.search(fru)
    if result:
        chassis_serial = result.group('result')
    else:
        return fru_dict
    result = PRODUCT_SERIAL_RE.search(fru)
    if result:
        product_serial = result.group('result')
    else:
        return fru_dict
    fru_dict = {'product_part_number': product_part_number, 'chassis_serial': chassis_serial, 
       'product_serial': product_serial}
    return fru_dict


def get_smc_fru_info(node):
    """
    Args:
      node: NodeConfig object
    
    Returns: dictionary with keys product_part_number, chassis_serial,
             product_serial
    """
    cmd = [
     'java',
     '-Djava.library.path=%s' % os.path.dirname(folder_central.get_smc_ipmitool_path()),
     '-jar',
     folder_central.get_smc_ipmitool_path(),
     node.ipmi_ip,
     node.ipmi_user,
     node.ipmi_password,
     'ipmi',
     'fru']
    out, err, ret = system(node, cmd, throw_on_error=False)
    if ret:
        return None
    return parse_smc_fru(out)


def is_valid_block_id(block_id):
    """
    Checks if a block_id is valid.
    
    Args:
      block_id: e.g. 15SM60210064
    
    Returns: True or False
    
    """
    return bool(VALID_BLOCK_ID.match(block_id))


def in_cvm(node, log_on_error=False):
    """
    Checks if node in cvm by checking if
    /etc/nutanix/release_version is present
    
    Args:
      node (Nodeconfig): node
      log_on_error (bool): whether to log errors
    
    Returns:
      True if node is reachable and in cvm. False, otherwise
    
    """
    _, _, ret = ssh(node, node.cvm_ip, [
     'test', '-f', '/etc/nutanix/release_version'], throw_on_error=False, log_on_error=log_on_error)
    if ret:
        return False
    return True


def in_phoenix(node, log_on_error=False, timeout=SSH_TIMEOUT):
    """
    Checks if node is in phoenix by checking if
    /phoenix/layout/layout_finder.py is present
    
    Args:
      node (NodeConfig): node
      log_on_error (bool): whether to log errors
    
    Returns:
      True if node is in phoenix. False, otherwise
    """
    _, _, ret = ssh(node, node.phoenix_ip, [
     'test', '-f', '/phoenix/layout/layout_finder.py'], throw_on_error=False, log_on_error=log_on_error, user='root', timeout=timeout)
    if ret:
        return False
    return True


def read_hardware_config_from_cvm(node):
    """
    Reads the hardware_config.json from cvm if it is up.
    
    Args:
      node: NodeConfig object of the node.
    
    Returns:
      Contents of hardware_config.json if the cvm is up and reachable.
      In case of any errors or cvm is not up, None is returned.
    """
    logger = node.get_logger()
    if not hasattr(node, 'cvm_ip'):
        return
    if not in_cvm(node):
        logger.error('Node with ip %s is not in cvm or is not reachable' % node.cvm_ip)
        return
    hc_path = '/etc/nutanix/hardware_config.json'
    out, _, ret = ssh(node, node.cvm_ip, ['cat', hc_path], throw_on_error=False)
    if not ret:
        try:
            hc = json.loads(out)
            return hc
        except ValueError:
            logger.exception('Failed to parse the contents of %s' % hc_path)
            return

    return


def record_system_information(node):
    logger = node.get_logger()
    if not in_phoenix(node):
        logger.error('Node with ip %s is not in phoenix or is not reachable' % node.phoenix_ip)
        return
    sys_info_cmd = [
     '/phoenix/cli_utils.py', 'system_info']
    out, err, ret = ssh(node, node.phoenix_ip, sys_info_cmd, throw_on_error=False, user='root', timeout=60, escape_cmd=True)
    log_folder = folder_central.get_session_log_folder(session_id=node._session_id)
    system_information_file = os.path.join(log_folder, 'system_information_%s.json' % node.phoenix_ip)
    if not ret:
        with open(system_information_file, 'w') as (fp):
            fp.write(out.strip())
        logger.debug('Recorded system information at %s' % system_information_file)
    return


def read_hardware_config_from_phoenix(node):
    """
    Checks whether a node is booted in to phoenix and if yes, generates and reads
    hardware_config.json from phoenix.
    
    Args:
      node: NodeConfig object of the node.
    
    Returns:
      Contents of hardware_config.json in string format if node is in phoenix
      and no other error occurs. Else, returns None.
    """
    logger = node.get_logger()
    if not in_phoenix(node):
        logger.error('Node with ip %s is not in phoenix or is not reachable' % node.phoenix_ip)
        return
    logger.info('Node with ip %s is in phoenix. Generating hardware_config.json' % node.phoenix_ip)
    layout_cmd = [
     '/usr/bin/python', '/phoenix/layout/layout_finder.py', 'local']
    if getattr(node, 'hardware_attributes_override', {}):
        hw_attrs = json.dumps(node.hardware_attributes_override, separators=(',', ':'))
        layout_cmd.append('hardware_attributes_override=%s' % re.escape(hw_attrs))
    _, err, ret = ssh(node, node.phoenix_ip, layout_cmd, throw_on_error=False, user='root', timeout=60, escape_cmd=True, log_on_error=False)
    if ret:
        logger.error('Failed to generate hardware_config.json. Error:\n%s' % err)
        return
    out, err, ret = ssh(node, node.phoenix_ip, ['cat', 'hardware_config.json'], throw_on_error=False, user='root', log_on_error=False)
    if ret:
        logger.error('Unable to read hardware_config.json from phoenix. Error:\n%s' % err)
        return
    try:
        return json.loads(out)
    except ValueError:
        logger.warn('failed to load hardware_config.json from phoenix: %s', out)

    return


def update_hardware_config_on_cvm(node_config, hardware_config):
    """
    Updates the hardware config on cvm
    
    Args:
      node_config: NodeConfig object of the node.
      hardware_config: HardwareConfig object
    Returns:
      BOOL
    """
    logger = node_config.get_logger()
    if not hasattr(node_config, 'cvm_ip'):
        logger.error('Node config does not have cvm_ip attribute')
        return False
    if not hardware_config:
        logger.error('Invalid hardware config')
        return False
    hardware_config_path = folder_central.get_cvm_hardware_config_path()
    with tempfile.NamedTemporaryFile(suffix='hardware_config.json') as (tf):
        json.dump(hardware_config, tf, sort_keys=True, indent=4, ensure_ascii=False)
        tf.flush()
        _, _, ret = scp(node_config, node_config.cvm_ip, '/tmp', files=[tf.name], log_on_error=True, throw_on_error=False)
        _, _, ret = ssh(node_config, node_config.cvm_ip, [
         'sudo', 'mv',
         '/tmp/%s' % os.path.basename(tf.name), hardware_config_path], throw_on_error=False)
        if ret:
            logger.warn('Failed to update hardware config at %s', node_config.cvm_ip)
            return False
        logger.debug('Successfully updated hardware config at %s', node_config.cvm_ip)
        return True


def read_hardware_config_from_any(node):
    return read_hardware_config_from_cvm(node) or read_hardware_config_from_phoenix(node)


def get_ipv6_link_local_from_mac(mac):
    """
    Converts a MAC address to an ipv6 link-local address.
    
    Args:
      mac: MAC Address in the form in the form xx:xx:xx:xx:xx:xx, where each x
      is a hexadecimal digit. Uppercase letters are ok.
    
    Returns: ipv6 link local address.
    
    """
    pattern = '^' + (':').join(['[a-fA-F0-9]{2}'] * 6) + '$'
    if not re.match(pattern, mac):
        raise StandardError('MAC address in unsupported format: %s' % mac)
    mac = mac.lower()
    parts = mac.split(':')
    parts[0] = '%02x' % (int(parts[0], 16) ^ 2)
    return 'fe80::%s%s:%sff:fe%s:%s%s' % tuple(parts)


def get_foundation_pkg_version_from_nos_tar(nos_package_path):
    """
    Read foundation_version in side nos tarball.
    This usually takes ~8 seconds for 4G nos tarball.
    the structure should be like:
        nutanix_installer_package.tar/
            install/pkg/nutanix-foundation-master-20150527.tar.gz/
          or
            ./install/pkg/nutanix-foundation-master-20150527.tar.gz/
                foundation/foundation_version
    Args:
      nos_package_path: Path to NOS tarball.
    Returns:
      Foundation version if found, else None.
      Example: Returns a string "foundation-4.2.1-cf5f2032", if NOS tarball has
               foundation version 4.2.1 packaged with it.
    """
    for fn in tarfile.open(nos_package_path).getnames():
        if 'install/pkg/nutanix-foundation' in fn:
            foundation_pkg_name = fn
            break
    else:
        return

    default_logger.warn('this `get_foundation_pkg_version_from_nos_tar` might be slow')
    with tarfile.open(nos_package_path) as (nos_tf):
        foundation_fd = nos_tf.extractfile(nos_tf.getmember(foundation_pkg_name))
        with tarfile.open(fileobj=foundation_fd, mode='r:gz') as (f_tf):
            version_fns = [
             'foundation/foundation_version', './foundation/foundation_version']
            for fn in version_fns:
                try:
                    return f_tf.extractfile(f_tf.getmember(fn)).read()
                except KeyError:
                    pass

            else:
                return

    return


def _get_foundation_version_file_handle_from_tar_file_handle(file_handle):
    foundation_version_file = get_packages_path_in_tar(file_handle, path_contains='foundation_version', raise_on_error=False)
    if not foundation_version_file:
        return
    return file_handle.extractfile(foundation_version_file)


def get_foundation_version_from_foundation_archive(foundation_archive):
    """
    Reads foundation_version file from the foundation archive.
    
    Args:
      foundation_archive: full path to foundation_archive.
    
    Returns: Version usually like, "foundation-3.5-1234abcd"
    
    """
    if foundation_archive.endswith('.gz'):
        fp = tarfile.open(foundation_archive, 'r:gz')
    else:
        fp = tarfile.open(foundation_archive, 'r')
    version_file_handle = _get_foundation_version_file_handle_from_tar_file_handle(fp)
    if not version_file_handle:
        raise StandardError('Unable to find foundation_version file in %s' % foundation_archive)
    version_text = version_file_handle.read().strip()
    version_file_handle.close()
    fp.close()
    return version_text


def is_valid_foundation_tar_gz(foundation_archive):
    """
    Checks if foundation_archive is a valid .tar.gz file.
    
    Args:
      foundation_archive: full path to foundation_archive.
    
    Returns:
      True: if it's a foundation archive.
    
    """
    fp = None
    try:
        fp = tarfile.open(foundation_archive, 'r:gz')
        version_file_handle = _get_foundation_version_file_handle_from_tar_file_handle(fp)
        if not version_file_handle:
            return False
        version_file_handle.close()
        return True
    except (KeyError, tarfile.ReadError, IOError):
        default_logger.exception('invalid foundation tarball')
        return False
    finally:
        if fp:
            fp.close()

    return


def get_default_timezones():
    """
    Load timezones from config file
    
    NOTE: the timezone_map contains mappings where multiple names sharing same
          zone, this function will expand to individual entries.
    
        "America/New_York America/Detroit America/Indiana/Petersburg
        America/Indiana/Vincennes America/Indiana/Winamac
        America/Kentucky/Monticello America/Louisville": "Eastern Standard Time",
    
        =>
    
        {"America/New_York": "Eastern Standard Time",
         "America/Detroit": "Eastern Standard Time",
         ...}
    """
    map_file = folder_central.get_foundation_windows_timezone_map_path()
    with open(map_file) as (data_file):
        timezone_map = json.load(data_file)
    for key in list(timezone_map.keys()):
        if ' ' in key:
            win_tz = timezone_map.pop(key)
            for sub_tz in key.split():
                timezone_map[sub_tz] = win_tz

    return timezone_map


def set_timezone(node_config, timezone):
    """
    Set given timezone on the CVM and Host in node_config.
    Args:
      node_config: NodeConfig instance. Must contain cvm_ip attr.
      timezone   : Name of region, example: "Europe/Berlin"
    Returns:
      (True, None) if successful.
      (False, error message) otherwise. error message will contain the
         command which failed, stdout, stderr and ret code.
    Note:
      This function should be called on an unconfigured node only.
    """
    logger = node_config.get_logger()
    cvm_ip = getattr(node_config, 'cvm_ip', None)
    hypervisor_ip = getattr(node_config, 'hypervisor_ip', None)
    hypervisor_type = getattr(node_config, 'hypervisor', None)
    if not cvm_ip:
        return (False, 'cvm_ip is missing in node_config')
    if not hypervisor_ip:
        return (False, 'hypervisor_ip is missing in node_config')
    if not hypervisor_type:
        return (False, 'hypervisor is missing in node_config')

    def set_timezone_helper(node_config, ip, user='nutanix'):
        tz_file = '/usr/share/zoneinfo/' + timezone
        target = '/etc/localtime'
        cmds = [
         [
          'ls', tz_file],
         [
          'sudo', 'ln', '-sf', tz_file, target]]
        for cmd in cmds:
            out, err, ret = ssh(node_config, ip, cmd, throw_on_error=False, log_on_error=False, timeout=10, user=user)
            if ret:
                error = 'A error occured on %s. Failed on command: %s\n' % (ip, cmd)
                error += 'stdout: %s\nstderr: %s\nret code: %s' % (out, err, ret)
                return (
                 False, error)

        return (
         True, None)

    ret, err = set_timezone_helper(node_config, cvm_ip)
    if not ret:
        logger.warn('An error occured while trying to set CVM timezone: %s' % err)
    if hypervisor_type == 'kvm' or hypervisor_type == 'xen':
        ret, err = set_timezone_helper(node_config, hypervisor_ip, user='root')
        if not ret:
            return (ret, err)
    else:
        if hypervisor_type == 'hyperv':
            timezone_map = get_default_timezones()
            windows_timezone = timezone_map.get(timezone, None)
            if windows_timezone:
                command = '/usr/local/nutanix/bin/winsh \'tzutil /s "%s"\'' % windows_timezone
                out, err, ret = ssh(node_config, cvm_ip, [command], throw_on_error=False, log_on_error=True, escape_cmd=True)
                if ret:
                    message = 'Failed to execute command (%s) on HyperV host with error:\n%s' % (
                     command, err)
                    return (
                     False, message)
            else:
                logger.warn('Could not find a HyperV timezone match. Skipping it')
        else:
            if hypervisor_type == 'esx':
                logger.warn("ESXi doesn't support timezones. Skipping it. Will use UTC")
    return (
     True, None)


def update_whitelist_on_cvm(node_config, local_whitelist_file):
    """
    Updates the whitelist on cvm if it is older.
    Args:
      node_config: NodeConfig object for the target node.
      local_whitelist_file: Path to local whitelist file which needs to be
          uploaded to cvm.
    
    Raises:
      StandardError if NodeConfig object does not have cvm_ip in it.
    
    Returns:
      True if whitelist is updated successfully on cvm.
      False otherwise.
    """
    logger = node_config.get_logger()
    if not getattr(node_config, 'cvm_ip', None):
        raise StandardError('Node config does not have cvm_ip attribute')
    if not os.path.exists(local_whitelist_file):
        logger.error('Iso whitelist %s does not exist. Skipping whitelist upload' % local_whitelist_file)
        return False
    cvm_whitelist_path = folder_central.get_iso_whitelist()
    _, _, ret = ssh(node_config, node_config.cvm_ip, ['ls', cvm_whitelist_path], throw_on_error=False)
    if not ret:
        out, _, ret = ssh(node_config, node_config.cvm_ip, [
         'cat', cvm_whitelist_path], throw_on_error=False)
        if ret:
            logger.error("Couldn't read iso whitelist from cvm at %s. Skipping whitelist upload" % node_config.cvm_ip)
            return False
        cvm_whitelist = json.loads(out)
        cvm_version = cvm_whitelist['last_modified']
        with open(local_whitelist_file) as (fd):
            local_whitelist = json.load(fd)
        local_version = local_whitelist['last_modified']
        if cvm_version >= local_version:
            logger.info('Whitelist version on cvm (%s) is same or newer than the local whitelist version (%s). Skipping whitelist upload' % (
             cvm_version, local_version))
            return False
    _, _, ret = scp(node_config, node_config.cvm_ip, cvm_whitelist_path, files=[local_whitelist_file], log_on_error=True, throw_on_error=False)
    if ret:
        logger.error('Failed to upload iso whitelist to cvm at %s' % node_config.cvm_ip)
        return False
    logger.info('Successfully uploaded iso whitelist to cvm at %s' % node_config.cvm_ip)
    return True
    return


def create_fake_nos_tarball(suffix='fake', version='99.0'):
    """
    Creates a fakes nos tarball in nos folder with given suffix and version.
    
    Args:
      suffix: Suffix to be added to the name of the fake nos tarball.
          Tarball name will be of the form nos-<suffix>.tar.
      version: Nos version of the tarball to be created.
    
    Returns:
      Path to the fake nos tarball.
    """
    temp_dir = None
    try:
        temp_dir = tempfile.mkdtemp()
        install_dir = os.path.join(temp_dir, 'install')
        os.makedirs(install_dir)
        manifest_file = os.path.join(install_dir, 'nutanix-packages.json')
        data = {}
        data['release'] = 'el6-release-%s-bd85f22b' % version
        data['packages'] = []
        data['image-type'] = 'PE-image'
        with open(manifest_file, 'w') as (f):
            json.dump(data, f, indent=2)
        nos_dir = folder_central.get_nos_folder()
        nos_tar_name = 'nos-%s.tar' % suffix
        nos = os.path.join(nos_dir, nos_tar_name)
        with contextlib.closing(tarfile.open(nos, 'w')) as (tar):
            tar.add(install_dir, arcname='install')
        return nos
    except:
        default_logger.exception('Failed to create fake nos tarball')
        raise
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

    return


def platform_info():
    return {'machine': platform.machine(), 
       'platform': platform.platform(), 
       'processor': platform.processor(), 
       'python_build': platform.python_build(), 
       'python_version': platform.python_version(), 
       'system': platform.system(), 
       'release': platform.release(), 
       'version': platform.version(), 
       'imaging_context': imaging_context.get_context(), 
       'foundation_version': get_current_foundation_version()}


def generic_ping(ip, retries=3, sleep_time=0.1):
    """
    
    Args:
      ip: ip address to ping
    
    Returns: True if ping works, False otherwise.
    
    """
    while 1:
        if retries:
            default_logger.debug('retries left %s', retries)
            if is_mac():
                cmd = [
                 'ping', '-t', '3', ip]
            else:
                cmd = [
                 'ping', '-w', '3', ip]
            _, _, ret = system(None, cmd, throw_on_error=False, log_on_error=False)
            if not ret:
                return True
            retries -= 1
            time.sleep(sleep_time)
    else:
        return False

    return


try:
    hashlib.md5(usedforsecurity=False)
    insecure_md5 = functools.partial(hashlib.md5, usedforsecurity=False)
except TypeError:
    insecure_md5 = hashlib.md5