# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_handoff.py
# Compiled at: 2019-02-15 12:42:10
import config_persistence, folder_central, foundation_tools, glob, iso_whitelist, itertools, json, os, re, session_manager, time, traceback, urllib2
from datetime import datetime
from distutils.version import LooseVersion
from foundation_settings import settings as foundation_settings
from foundation.session_manager import get_global_config, get_last_active_session_id
from imaging_step import ImagingStepNodeTask
from threading import Lock
STATE_IMAGE_NOW = 'This node will be imaged now'
INSTALLATION_TIMEOUT_S = 7200
STATE_WAITING_FOR_REMOTE = 'Waiting for remote foundation'
STATE_UPLOADING_NOS = 'Uploading NOS tarball to the first imaged node'
STATE_UPLOADING_HYP = 'Uploading Hypervisor to the first imaged node'
STATE_HANDOFF = 'Handing off control to the first imaged node'
DEFAULT_TIME_FORMAT = '%Y-%m-%d %H:%M:%S'
SESSION_ID_FORMAT = '%Y%m%d-%H%M%S'
HTTP_ACCESS_FORMAT = '%d/%b/%Y:%H:%M:%S'
DEBUG_LOG_FORMAT = '%Y%m%d %H:%M:%S'
GATHERED_INFO_FILENAME = 'gathered_info.json'
TICK = 5
VERSION_RETRY = 300
IMAGE_DELAY = 30
FIRST_NODE_TIMEOUT_MINS = 75
REDIRECT_LOCK = Lock()

def get_http_port():
    return foundation_settings['http_port']


def set_redirect_status(ready=None, cvm_ip=None, cvm_ipv6=None):
    session_id = get_last_active_session_id()
    global_config = get_global_config(session_id)
    with REDIRECT_LOCK:
        if ready is not None:
            setattr(global_config, 'redirect_now', ready)
        if cvm_ip is not None:
            setattr(global_config, 'redirect_ip', cvm_ip)
        if cvm_ipv6 is not None:
            setattr(global_config, 'redirect_ipv6', cvm_ipv6)
    return


def get_redirect_status():
    try:
        session_id = get_last_active_session_id()
        global_config = get_global_config(session_id)
        with REDIRECT_LOCK:
            redirect_now = getattr(global_config, 'redirect_now', False)
            redirect_ip = getattr(global_config, 'redirect_ip', None)
            redirect_ipv6 = getattr(global_config, 'redirect_ipv6', None)
        return (redirect_now, redirect_ip, redirect_ipv6)
    except StandardError:
        return (
         False, None, None)

    return


class ImagingStepHandoffPrepare(ImagingStepNodeTask):
    """
    Block nodes that have to be imaged after the first node.
    """

    def _imaged_later_message(self):
        node_config = self.config
        return 'This node will be imaged after the node with CVM IP %s' % node_config.first_node_to_image.cvm_ip

    def get_progress_timing(self):
        node_config = self.config
        if not getattr(node_config, 'need_handoff', False):
            return [('', 0.1)]
        if node_config == node_config.first_node_to_image:
            return [(STATE_IMAGE_NOW, 0.1)]
        return [
         (
          self._imaged_later_message(), 40)]

    def run(self):
        node_config = self.config
        logger = self.logger
        if not getattr(node_config, 'need_handoff', False):
            logger.info('%s skipped', __name__)
            return
        if node_config != node_config.first_node_to_image:
            self.set_status(self._imaged_later_message())
            logger.info(self._imaged_later_message())
            for _ in range(FIRST_NODE_TIMEOUT_MINS):
                if getattr(node_config.first_node_to_image, '_exceptions', None):
                    raise StandardError('First node failed imaging')
                time.sleep(60)
            else:
                raise StandardError('Timeout in waiting for %s' % node_config.first_node_to_image.cvm_ip)

        else:
            logger.info('Start imaging node %s', node_config.cvm_ip)
        return


class ImagingStepHandoff(ImagingStepNodeTask):
    """
    The second part of handoff.
    For first_node, copy file and do handoff.
    For the rest nodes, display proper status and block forever.
    """

    def get_remote_version(self):
        try:
            ip = self.config.first_node_to_image.cvm_ip
            port = get_http_port()
            return urllib2.urlopen('http://%s:%s/foundation/version' % (ip, port), timeout=1).read()
        except IOError:
            return

        return

    def handoff(self):
        node_config = self.config
        logger = self.logger
        json_config = config_persistence.get_persisted_config()
        json_config['nos_package'] = self.nos_package_path
        url = 'http://%s:%s/foundation/image_nodes' % (
         node_config.cvm_ip,
         get_http_port())
        logger.info('Handing off to %s:%s' % (
         node_config.cvm_ip, get_http_port()))
        for block in json_config['blocks']:
            for node in block['nodes']:
                if node['cvm_ip'] == node_config.cvm_ip:
                    node['image_now'] = False
                    node['image_successful'] = True
                    node['image_delay'] = IMAGE_DELAY

        req = urllib2.Request(url, json.dumps(json_config), {'Content-Type': 'application/json'})
        try:
            response = urllib2.urlopen(req).read()
            return response
        except urllib2.HTTPError as e:
            if e.getcode() == 500:
                content = e.read()
                logger.error('Failed to handoff imaging to %s, API %s returned an error %s.' % (
                 node_config.cvm_ip, url, content))
            raise StandardError('Failed to post image_nodes request to %s, please check error messages in log.' % url)

    def get_progress_timing(self):
        node_config = self.config
        if not getattr(node_config, 'need_handoff', False):
            return [('', 0.1)]
        if node_config == node_config.first_node_to_image:
            return [
             (
              STATE_WAITING_FOR_REMOTE, 1),
             (
              STATE_UPLOADING_NOS, 1),
             (
              STATE_UPLOADING_HYP, 2),
             (
              STATE_HANDOFF, 0.5)]
        return [
         ('Handoff will not run on this node', 0.1)]

    def compile_session_information(self, sm, previous_log_folders):
        """
         Gather previous sessions' information and imprint onto their logs.
         For each session, we are gathering:
           - Foundation, AOS/NOS, Hypervisor version
           - Success vs. failure in imaging
           - Duration of imaging session
        """
        node_config = self.config
        for _sessionId in previous_log_folders + [node_config._session_id]:
            sessionInfo = {}
            sc = None
            try:
                sc = sm.get_session_by_id(_sessionId)
            except (StandardError, AssertionError):
                continue
            else:
                previous_session = _sessionId != node_config._session_id
                _sessionTime = datetime.fromtimestamp(sc.start_time)
                end_time = '(N/A)'
                if previous_session:
                    end_time = datetime.fromtimestamp(sc.end_time)
                    end_time = end_time.strftime(DEFAULT_TIME_FORMAT)
                _path = os.path.join(folder_central.get_log_folder(), _sessionId)
                _path += '/' + GATHERED_INFO_FILENAME
                if os.path.isfile(_path):
                    continue
                session_duration = '(N/A)'
                if previous_session:
                    _duration = sc.get_runtime_seconds()
                    hours, remainder = divmod(_duration, 3600)
                    minutes, seconds = divmod(remainder, 60)
                    session_duration = '%s hours, %s minutes, %s seconds' % (
                     hours, minutes, seconds)
                session_aborted = sc.config.abort_session
                session_success = sc.has_succeeded()
                session_idle = sc.is_idle_and_failed() or sc.is_idle()
                sessionInfo['session_info'] = {'id': _sessionId, 
                   'start_time': _sessionTime.strftime(DEFAULT_TIME_FORMAT), 
                   'end_time': end_time, 
                   'session_duration': session_duration, 
                   'session_aborted': session_aborted, 
                   'session_success': session_success, 
                   'imaging_successful': session_success, 
                   'session_idle': session_idle}
                version_info = {}
                version_info['foundation'] = foundation_tools.read_foundation_version()
                if node_config.hyp_type in node_config.md5sum_hyp_iso:
                    md5sum = node_config.md5sum_hyp_iso[node_config.hyp_type]
                    whitelist = iso_whitelist.whitelist['iso_whitelist']
                    if md5sum in whitelist:
                        iso_properties = whitelist[md5sum]
                        version = iso_properties['version']
                        version_info['hypervisor'] = {'type': node_config.hyp_type.upper(), 
                           'version': version}
                cvm_ip = node_config.cvm_ip
                nos_version = foundation_tools.get_nos_version_from_cvm(cvm_ip)
                version_info['nos_version'] = nos_version
                sessionInfo['version_information'] = version_info
                sessionInfo['package_information'] = {'nos_package': node_config.nos_package, 
                   'hypervisor_iso': node_config.hypervisor_iso}
                foundation_tools.update_metadata(sessionInfo, _sessionId)
                _path = os.path.join(folder_central.get_log_folder(), _sessionId)
                _path = os.path.join(_path, GATHERED_INFO_FILENAME)
                with open(_path, 'w') as (fp):
                    json.dump(sessionInfo, fp)

        return

    def __transfer_logs(self):
        self.logger.info('Uploading current logs')
        node_config = self.config
        root_log_dir = folder_central.get_log_folder() + '/*'
        archive_log_dir = folder_central.get_log_archive_folder() + '/*'
        session_log_dir = folder_central.get_session_log_folder(node_config._session_id) + '/*'
        fn_base_path = folder_central.get_log_folder() + '/first_node_session/'
        sm = session_manager.get_session_manager()
        previous_log_folders = sm.get_completed_sessions_with_files_on_disk()
        previous_log_folders = [ sc._session_id for sc in previous_log_folders ]
        try:
            self.compile_session_information(sm, previous_log_folders)
        except BaseException as e:
            self.logger.warning('Could not compile session information: %s' % traceback.format_exc())

        glob_path = [
         root_log_dir, session_log_dir, archive_log_dir]
        _log_base_path = folder_central.get_log_folder() + '/'
        for _folder in previous_log_folders:
            glob_path += _log_base_path + _folder + '/*'

        search_path = itertools.chain.from_iterable((glob.iglob(pattern) for pattern in glob_path))
        session_id_regex = re.compile('[0-9]+-[0-9]+-[0-9]+')
        for _file in search_path:
            if os.path.isdir(_file):
                continue
            remote_file_path = fn_base_path + os.path.basename(_file)
            if 'logs/foundation/%s/' % node_config._session_id in _file:
                remote_file_path = fn_base_path + '%s/%s' % (
                 node_config._session_id, os.path.basename(_file))
            else:
                if 'archive' in _file:
                    remote_file_path = fn_base_path + 'archive/%s' % os.path.basename(_file)
                else:
                    if folder_central.get_log_folder() in _file:
                        try:
                            log_session_id = session_id_regex.findall(_file)[0]
                        except IndexError:
                            self.logger.warning('Invalid log path: %s' % _file)
                            continue

                        remote_file_path = fn_base_path + '%s/%s' % (
                         log_session_id, os.path.basename(_file))
            foundation_tools.upload(local_file=_file, remote_file=remote_file_path, target_config=node_config, verify_existence=False, throw_on_error=True)

        foundation_out = '/home/nutanix/data/logs/foundation.out'
        foundation_tools.upload(local_file=foundation_out, remote_file='%s.%s' % (foundation_out,
         node_config.cvm_ip), target_config=node_config, verify_existence=False, throw_on_error=True)

    def transfer_logs(self):
        try:
            self.__transfer_logs()
        except Exception as e:
            self.logger.warning('Log transfer error: %s', traceback.format_exc())

    def upgrade_foundation(self):
        """
        Upgrade foundation on remote node using current node's installation.
        """
        remote_version = self.get_remote_version()
        my_version = foundation_tools.get_current_foundation_version()
        if LooseVersion(my_version) > LooseVersion(remote_version):
            self.logger.info('Upgrading foundation to %s before handoff.' % my_version)
            foundation_tar = foundation_tools.get_foundation_tar()
            remote_foundation_path = os.path.join('/home/nutanix', os.path.basename(foundation_tar))
            self.logger.debug('Copying over %s.' % foundation_tar)
            try:
                foundation_tools.scp(self.config, self.config.cvm_ip, remote_foundation_path, foundation_tar, timeout=300)
            except foundation_tools.SCPException as e:
                raise StandardError('Failed to copy foundation image to remote CVM.')
            else:
                self.logger.debug('Starting foundation upgrade.')
                foundation_upgrade_cmd = [
                 '/home/nutanix/foundation/bin/foundation_upgrade', '-t',
                 remote_foundation_path, '-a', 'true']
                try:
                    foundation_tools.ssh(self.config, self.config.cvm_ip, foundation_upgrade_cmd)
                    self.logger.debug('Foundation upgrade successful.')
                except StandardError:
                    raise StandardError('Failed to upgrade foundation on the remote node.')

                try:
                    os.unlink(foundation_tar)
                except OSError:
                    pass

            foundation_tools.ssh(self.config, self.config.cvm_ip, [
             'rm', remote_foundation_path], throw_on_error=False)

    def wait_for_remote_node_to_be_up(self):
        node_config = self.config
        logger = self.logger
        logger.info('Connecting to remote foundation at %s', node_config.first_node_to_image.cvm_ip)
        self.set_status(STATE_WAITING_FOR_REMOTE)
        for retry in range(0, VERSION_RETRY, TICK):
            remote_version = self.get_remote_version()
            if remote_version:
                logger.info('Connected to remote foundation, version is %s', remote_version)
                break
            else:
                logger.debug('[%ss/%ss] Remote foundation is not responding, retrying', retry, VERSION_RETRY)
                time.sleep(TICK)
        else:
            raise StandardError('Failed to connect to remote foundation')

    def run(self):
        node_config = self.config
        logger = self.logger
        is_unit = getattr(node_config, 'is_unit', False)
        if not getattr(node_config, 'need_handoff', False):
            logger.info('%s skipped', __name__)
            return
        if node_config != node_config.first_node_to_image:
            logger.info('I am not the first node to be imaged')
            return
        self.wait_for_remote_node_to_be_up()
        self.upgrade_foundation()
        self.wait_for_remote_node_to_be_up()
        if os.path.exists(folder_central.get_iso_whitelist()):
            logger.info('Uploading iso_whitelist')
            url = 'http://%s:%s/foundation/get_whitelist' % (
             node_config.cvm_ip, get_http_port())
            newly_deployed_version = None
            for _ in range(3):
                try:
                    response = urllib2.urlopen(url).read()
                    newly_deployed_whitelist = json.loads(response)
                    newly_deployed_version = newly_deployed_whitelist['last_modified']
                    break
                except urllib2.HTTPError as e:
                    content = e.read()
                    logger.error('Failed to load the existing whitelist from %s with error:\n%s' % (
                     node_config.cvm_ip, str(content)))

            else:
                raise StandardError('Failed to read whitelist version on newly imaged node. Check logs for errors')

            with open(folder_central.get_iso_whitelist()) as (fh):
                json_data = json.load(fh)
            current_version = json_data['last_modified']
            logger.debug('Current whitelist version: %s, newly deployed whitelist version: %s' % (
             current_version, newly_deployed_version))
            if newly_deployed_version > current_version:
                logger.info('Existing whitelist version is higher. Skipping whitelist upload')
            else:
                url = 'http://%s:%s/foundation/update_whitelist' % (
                 node_config.cvm_ip, get_http_port())
                for _ in range(3):
                    try:
                        req = urllib2.Request(url, data=json.dumps(json_data), headers={'Content-Type': 'application/json'})
                        response = urllib2.urlopen(req).read()
                        break
                    except urllib2.HTTPError as e:
                        content = e.read()
                        logger.error('Got HTTP error while uploading whitelist using url %s, HTTP response:\n%s' % (
                         url, str(content)))

                else:
                    raise StandardError('Failed to upload whitelist during handoff. Please check logs for details')

        self.set_status(STATE_UPLOADING_NOS)
        if node_config.nos_package:
            self.nos_package_path = node_config.nos_package
            logger.info('Uploading NOS')
            if self.nos_package_path.endswith('.gz'):
                self.nos_package_path = self.nos_package_path[:-3]
            remote_nos_path = foundation_tools.upload(installer_type='nos', local_file=self.nos_package_path, remote_file=None, target_config=node_config, verify_existence=False, throw_on_error=True)
            if not remote_nos_path:
                raise StandardError('Failed to upload nos.')
            self.nos_package_path = remote_nos_path
        else:
            logger.info("Skipped uploading AOS because it's not required for this imaging session.")
            self.nos_package_path = None
        self.set_status(STATE_UPLOADING_HYP)
        self.installer_iso = node_config.hypervisor_iso
        if getattr(node_config, 'kvm_from_nos', False):
            if 'kvm' in self.installer_iso.keys():
                self.installer_iso['kvm'] = ''
        else:
            if getattr(node_config, 'kvm_rpm', False):
                self.installer_iso['kvm'] = node_config.kvm_rpm
        for installer_type, installer_path in self.installer_iso.items():
            if installer_type == 'kvm' and getattr(node_config, 'kvm_from_nos', False):
                logger.info('Skipping upload of KVM iso prepared from NOS')
                continue
            if not os.path.exists(installer_path):
                continue
            logger.info('Uploading ISO %s, %s', installer_type, installer_path)
            remote_hyp_path = foundation_tools.upload(installer_type=installer_type, local_file=installer_path, remote_file=None, target_config=node_config, verify_existence=False, throw_on_error=True)
            if not remote_hyp_path:
                raise StandardError('Failed to upload hypervisor.')
            self.installer_iso[installer_type] = remote_hyp_path

        if os.path.exists(folder_central.get_phoenix_override_path()):
            logger.info('Uploading phoenix override.')
            foundation_tools.upload(local_file=folder_central.get_phoenix_override_path(), remote_file=None, target_config=node_config, verify_existence=False, throw_on_error=True)
        self.transfer_logs()
        logger.info('Ready to handoff.')
        if not is_unit:
            print 'Please go to http://%s:%s/gui to continue monitor progress.' % (
             node_config.cvm_ip, get_http_port())
        self.handoff()
        set_redirect_status(ready=True, cvm_ip=node_config.cvm_ip)
        self.set_status(STATE_HANDOFF)
        if not is_unit:
            time.sleep(300)
            raise StandardError('Timeout in waiting for remote foundation(%s) start imaging.' % node_config.cvm_ip)
        return