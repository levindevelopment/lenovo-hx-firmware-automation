# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/archive_log.py
# Compiled at: 2019-02-15 12:42:10
import glob, json, logging, os, re, shutil, subprocess, tarfile, tempfile, threading, time, gzip, factory_mode, folder_central, foundation_tools
from contextlib import closing
from foundation.portable import is_portable
default_logger = logging.getLogger(__file__)
MAX_LOG_ARCHIVE_SIZE = 15 * 1048576
IP_RE = re.compile('eth(\\d):.*?inet\\s+((?:\\d{1,3}\\.){3}\\d{1,3})/\\d+', flags=re.DOTALL)
factory_name_lock = threading.Lock()
logs = {}

def get_files_to_archive(include_rotated_logs=False):
    """
    Gets the list of files in foundation/log folder to be archived.
    Args:
      include_rotated_logs: If True, previously rotated files will be also added
          to the list of files to be archived. If False, rotated files will not
          be added to the list.
    Returns:
      List of file names in foundation/log folder to be archived.
    """
    result = []
    log_dir = folder_central.get_log_folder()
    for name in os.listdir(log_dir):
        if name.endswith('.archived'):
            continue
        if name.startswith('http.'):
            continue
        if 'archive' in name:
            continue
        if (os.path.isdir(os.path.join(log_dir, name)) or os.path.islink(os.path.join(log_dir, name))) and 'first_node_session' not in name:
            continue
        if '.log.' in name:
            ext = name.split('.')[-1]
            try:
                int(ext)
                if not include_rotated_logs:
                    continue
            except ValueError:
                pass

        result.append(name)

    return result


def get_session_logs_to_archive(session_id):
    """
    Gets the log files specific to a session.
    Args:
      session_id: Id of the session whose logs need to be archived.
    
    Returns:
      List of log file names corresponding to the session.
    """
    result = []
    session_log_dir = folder_central.get_session_log_folder(session_id)
    if not session_log_dir:
        return result
    dir_name = os.path.basename(session_log_dir)
    for name in os.listdir(session_log_dir):
        if not factory_mode.factory_mode() and os.path.isdir(os.path.join(session_log_dir, name)):
            continue
        result.append(name)

    return result


def is_session_already_in_archive(session_id):
    """
    Checks whether the logs for a session with given session id has been
    already archived.
    Args:
      session_id: Id of the session to be checked for.
    
    Returns:
      True if session log files have been already archived.
      False otherwise.
    """
    if factory_mode.factory_mode():
        archive_dir = folder_central.get_factory_log_archive_folder()
    else:
        archive_dir = folder_central.get_log_archive_folder()
        tar_list = glob.glob('%s/%s-*.tar.gz' % (archive_dir, session_id))
        if tar_list:
            return True
    tar_list = glob.glob('%s/*.tar.gz' % archive_dir)
    for tar in tar_list:
        with closing(tarfile.open(tar)) as (t):
            for member in t.getmembers():
                if 'persisted_config.json' in member.name or 'debug.log' in member.name:
                    with closing(t.extractfile(member)) as (f):
                        content = f.read()
                        if session_id in content:
                            return True

    return False


def get_archive_name(do_current=False, prefix='', session_id=None):
    """
    Get archive name based on foundation mode.
    
    Returns:
      archive name
    """
    if do_current:
        name = 'log-current.tar'
    else:
        if factory_mode.factory_mode():
            if prefix == 'orphan' or not os.path.exists(folder_central.get_persisted_config_path(session_id=session_id)):
                return 'factory-orphan-log.tar'
            system_serials = []
            state_path = folder_central.get_states_reached_path(session_id=session_id)
            success_suffix = ''
            if os.path.exists(state_path):
                with open(state_path) as (states_fh):
                    states = json.load(states_fh)
                    if states:
                        success_suffix = 'P'
                        for entity_type in ['nodes', 'clusters']:
                            already_failed = False
                            for phase_list in states.get(entity_type, {}).itervalues():
                                for phase in phase_list:
                                    if phase[1] != 'passed':
                                        success_suffix = 'F'
                                        already_failed = True
                                        break

                                if already_failed:
                                    break

            persisted_config_path = folder_central.get_persisted_config_path(session_id=session_id)
            system_serials = ['unknown']
            if os.path.exists(persisted_config_path):
                with open(persisted_config_path) as (config_fh):
                    config = json.load(config_fh)
                    system_serials = [ block.get('block_id') for block in config.get('blocks', []) ]
            system_serials = map(str, system_serials)
            system_serials = map(str.upper, system_serials)
            if is_portable():
                ip = 'portable'
            else:
                proc = subprocess.Popen(['ip', 'addr', 'show'], stdout=subprocess.PIPE)
                ips, _ = proc.communicate()
                ip = None
                for match in IP_RE.finditer(ips):
                    if not ip:
                        ip = match.group(2)
                    if match.group(1) == '1':
                        ip = match.group(2)
                        break

            name_template = '%s-%s' % (('-').join(system_serials), ip.split('.')[-1])
            with factory_name_lock:
                timestamp = time.strftime('%Y%m%d-%H%M%S')
                time.sleep(1)
            name = '%s-%s-%s.tar' % (name_template, timestamp, success_suffix)
        else:
            name = time.strftime(prefix + 'log-archive-%Y%m%d-%H%M%S.tar')
    return name


def create_tar_archive(tar_file, working_dir, files=None, append_files=False):
    """
    Create a tarball from a given list of files.
    
    Args:
      tar_file: Name of the tarball.
      working_dir: Parent directory of the files which need to be added to the
          tarball.
      files: List of file names to be added to tarball.
      append_files: If False, a new tarball with only the given files will be
          created. If True, the given list of files will be added to an existing
          tarball.
    
    Raises:
      StandardError if any error occurs during archival.
    
    Returns:
      True if the tarball has been created. False otherwise.
    """
    files = files or []
    mode = 'w'
    if append_files:
        mode = 'a'
    try:
        with closing(tarfile.open(tar_file, mode=mode)) as (tar):
            for f in files:
                file_path = os.path.join(working_dir, f)
                if os.path.exists(file_path):
                    tar.add(file_path, arcname=f)

    except:
        default_logger.exception('Exception occurred while creating log archive %s' % tar_file)
        return False

    return True


def archive_logs(do_current=False, prefix='', session_id=None):
    """
    Archive logs to a tgz. Older log archives are deleted to get under
    MAX_LOG_ARCHIVE_SIZE bytes of disk use.
    
    Args:
      do_current: if True, archive name will be "log-current.tar"
      prefix: prefix string of the archive tar name, eg "test-"
    
    Returns:
      path of the archive
    """
    log_dir = folder_central.get_log_folder()
    archive_dir = folder_central.get_log_archive_folder()
    if factory_mode.factory_mode():
        archive_dir = folder_central.get_factory_log_archive_folder()
    name = get_archive_name(do_current, prefix, session_id=session_id)
    tar_path = os.path.join(archive_dir, name)
    files_to_archive = get_files_to_archive()
    ret = create_tar_archive(tar_path, log_dir, files=files_to_archive)
    if not ret:
        default_logger.warn('Failed to create log archive %s. Ignoring error' % tar_path)
        return
    session_log_dir = folder_central.get_session_log_folder(session_id)
    session_logs = get_session_logs_to_archive(session_id)
    if session_logs:
        create_tar_archive(tar_path, session_log_dir, files=session_logs, append_files=True)
    root_path = False
    if not session_id:
        root_path = True
    pc_path = folder_central.get_persisted_config_path(session_id=session_id, root_path=root_path)
    if os.path.exists(pc_path):
        config_path, config_name = os.path.split(pc_path)
        create_tar_archive(tar_path, config_path, files=[config_name], append_files=True)
    states_path = folder_central.get_states_reached_path(session_id=session_id)
    if os.path.exists(states_path):
        file_dir, file_name = os.path.split(states_path)
        create_tar_archive(tar_path, file_dir, files=[file_name], append_files=True)
    foundation_dir = folder_central.get_foundation_dir()
    create_tar_archive(tar_path, foundation_dir, files=['foundation_version'], append_files=True)
    try:
        with gzip.open(tar_path + '.gz', 'wb') as (gzfd):
            with open(tar_path, 'rb') as (tarfd):
                shutil.copyfileobj(tarfd, gzfd)
        os.unlink(tar_path)
    except IOError:
        default_logger.exception('Gzipping log archive failed, ignoring')
        return

    tar_path = tar_path + '.gz'
    foundation_tools.assign_nutanix_owner(tar_path)
    if not factory_mode.factory_mode():
        names = os.listdir(archive_dir)
        names.sort()
        archives = [ os.path.join(archive_dir, name) for name in names ]
        archive_list = [ (archive, os.stat(archive).st_size) for archive in archives ]
        while sum(map(lambda x: x[1], archive_list)) > MAX_LOG_ARCHIVE_SIZE and len(archive_list) > 1:
            if os.path.isfile(archive_list[0][0]):
                os.unlink(archive_list[0][0])
            else:
                shutil.rmtree(archive_list[0][0])
            del archive_list[0]

    default_logger.info('Created log archive %s' % tar_path)
    return tar_path


def collect_log_archives():
    """
    Tar up current set of logs and wrap archived logs into tar file.
    
    Returns:
      A path to the tarball of all log archives.
    """
    archive_logs(do_current=True)
    tmp_dir = folder_central.get_tmp_folder()
    tar_path = tempfile.NamedTemporaryFile(dir=tmp_dir, suffix='_foundation_log.tar').name
    cmd = 'tar cf %s -C %s .' % (
     tar_path, folder_central.get_log_archive_folder())
    r = os.system(cmd)
    if r:
        print "'%s' failed; error ignored." % cmd
        return
    return tar_path


def remove_orphan_logs(ignore_deletion=None):
    """
    Collect and archive orphan log files in log folder.
    When foundation runs as cli or crashed as service, the log_all.log,
    node_*.log and cluster_*.log may be left in log dir however the
    rotate_all_logger is not able to rotate them.
    This function works as archiving and deleting existing logs before
    initializing the simple logger.
    
    Args:
      ignore_deletion: Optional list of files not to be deleted after archiving.
    
    Returns:
      Name of the tarball archive.
    """
    archive_file = archive_logs(prefix='orphan')
    log_dir = folder_central.get_log_folder()
    ignore_deletion_abspath_set = set()
    if ignore_deletion:
        ignore_deletion_abspath_set = set(map(os.path.abspath, ignore_deletion))
    if archive_file:
        print 'Orphan log is archived at', archive_file
        log_files = get_files_to_archive(include_rotated_logs=True)
        for log_file in log_files:
            log_file_path = os.path.join(log_dir, log_file)
            if os.path.abspath(log_file_path) in ignore_deletion_abspath_set:
                continue
            try:
                if os.path.isdir(log_file_path):
                    shutil.rmtree(log_file_path)
                else:
                    if os.path.isfile(log_file_path):
                        os.unlink(log_file_path)
                    else:
                        print 'Skip unknown file type of', log_file
            except Exception as e:
                print 'Exception', e, 'in deleting', log_file

    return archive_file