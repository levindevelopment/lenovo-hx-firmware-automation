# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/session_manager.py
# Compiled at: 2019-02-15 12:42:10
import logging, os, shutil, threading, time, archive_log, folder_central, foundation_tools as tools, imaging_context
from simple_logger import delete_latest_session_log_link, FoundationFileHandler
RESERVED_WORKFLOWS_SESSIONID_MAP = {'CLI': '007'}
IGNORED_SESSION_ID = '0' * 8
MAX_ACTIVE_SESSIONS = 20
ARCH_THRESHOLD = 20
DUP_VALIDATION_LOCK = threading.Lock()
last_active_session_id = None
last_created_session_id = None
session_index = 1
shared_files_config = {}
SHARED_FILES_LOCK = threading.Lock()
THREAD_SID_ATTR = 'foundation_session_id'
LATEST_LOG_LINK = 'last_session_log'
LATEST_LOG_LINK_LOCK = threading.Lock()
logger = logging.getLogger(__file__)

class Singleton(type):
    _instances = {}
    _instance_lock = threading.Lock()

    def __call__(cls, *args, **kwargs):
        with Singleton._instance_lock:
            if cls not in cls._instances:
                cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class SessionConfig(object):
    """
    Class object for each session instance.
    """
    SESSION_IDLE, SESSION_IDLE_AND_FAILED, SESSION_ACTIVE, SESSION_SUCCESS, SESSION_FAIL = range(5)
    ARCH_NOT_DONE, ARCH_DONE_FILES_PRESENT, ARCH_DONE_FILES_DELETED, ARCH_DELETED = range(4)
    ARCH_STATES = [ARCH_NOT_DONE, ARCH_DONE_FILES_PRESENT,
     ARCH_DONE_FILES_DELETED, ARCH_DELETED]

    def __init__(self, session_id):
        self._session_id = session_id
        self.config = None
        self.start_time = None
        self.end_time = None
        self._state = SessionConfig.SESSION_IDLE
        self._archive_status = SessionConfig.ARCH_NOT_DONE
        self.archive_name = None
        return

    def set_start_time(self):
        """
        Sets the start time of the session.
        """
        self.start_time = time.time()

    def set_end_time(self):
        """
        Sets the end time of the session.
        """
        self.end_time = time.time()

    def set_success(self):
        """
        Marks the session as succeeded.
        """
        if self._state == SessionConfig.SESSION_SUCCESS:
            return
        self._state = SessionConfig.SESSION_SUCCESS
        self.set_end_time()

    def set_fail_idle_session(self):
        """
        Mark an idle session as failed. Such a session will not have any progress
        output. This is required to archive the logs made by such a session during
        parsing and validation.
        """
        if self._state == SessionConfig.SESSION_IDLE_AND_FAILED:
            return
        if self._state != SessionConfig.SESSION_IDLE:
            logger.warning('Trying to set a non idle session as idle and failed')
            return
        self._state = SessionConfig.SESSION_IDLE_AND_FAILED
        self.set_end_time()

    def set_fail(self):
        """
        Marks the session as failed.
        """
        if self._state == SessionConfig.SESSION_FAIL:
            return
        self._state = SessionConfig.SESSION_FAIL
        self.set_end_time()

    def set_active(self):
        """
        Marks the session as active.
        """
        global last_active_session_id
        if self._state == SessionConfig.SESSION_ACTIVE:
            return
        self._state = SessionConfig.SESSION_ACTIVE
        last_active_session_id = self._session_id
        self.set_start_time()

    def set_config(self, config):
        """
        Sets the config object to be tracked by this session.
        Args:
          config: GlobalConfig object.
        
        Returns:
          None
        """
        self.config = config
        self.config._session_id = self._session_id
        self.config._parent = None
        return

    def is_idle(self):
        """
        Returns True if this is an idle session which has failed.
        Otherwise, False is returned.
        """
        return self._state == SessionConfig.SESSION_IDLE

    def is_idle_and_failed(self):
        """
        Returns True if this is an idle session which has failed.
        Otherwise, False is returned.
        """
        return self._state == SessionConfig.SESSION_IDLE_AND_FAILED

    def is_active(self):
        """
        Returns True if session is active. False otherwise.
        """
        return self._state == SessionConfig.SESSION_ACTIVE

    def has_succeeded(self):
        """
        Returns True if session has succeeded. False otherwise.
        """
        return self._state == SessionConfig.SESSION_SUCCESS

    def has_failed(self):
        """
        Returns True if session has failed. False otherwise.
        """
        return self._state == SessionConfig.SESSION_FAIL

    def get_runtime_seconds(self):
        """
        Returns the time (in seconds) taken for the session to finish execution.
        """
        return self.end_time - self.start_time

    def set_archive_status(self, status):
        """
        Sets the current archival status of the session.
        Args:
          status: Archival status of the session. Must be one of ARCH_STATES list.
        Returns:
          None
        """
        assert status in SessionConfig.ARCH_STATES, "'%s' is not a valid archival state" % status
        self._archive_status = status

    def has_files(self):
        """
        Checks whether the session specific files are present on disk, based on
        archival state.
        Returns:
          True if files are present. False otherwise.
        """
        return self._archive_status in [SessionConfig.ARCH_NOT_DONE,
         SessionConfig.ARCH_DONE_FILES_PRESENT]

    def is_archived_and_deleted(self):
        """
        Checks whether session specific files have been deleted after archival.
        Returns:
          True if files are not present, but archive is available.
          False otherwise.
        """
        return self._archive_status == SessionConfig.ARCH_DONE_FILES_DELETED

    def delete_session_files(self, raise_on_error=False):
        """
        Deletes all logs and temporary files related to a session.
        Args:
          raise_on_error: If True, any error that occurs while deleting the
              session related folders will be raised. Otherwise, error is ignored.
        Raises:
          OSError if there is any failure while trying to delete the folder.
        Returns:
          True if files are all deleted. False if it fails to delete any file.
          Function will return a value only if raise_on_error is False and no
          exception is raised.
        """
        try:
            log_dir = folder_central.get_session_log_folder(self._session_id)
            if os.path.isdir(log_dir):
                shutil.rmtree(log_dir)
            sessions_folder = folder_central.get_sessions_folder(self._session_id)
            if os.path.isdir(sessions_folder):
                shutil.rmtree(sessions_folder)
            delete_latest_session_log_link()
        except OSError:
            logger.error('Exception while deleting files related to session with id %s' % self._session_id)
            if raise_on_error:
                raise
            return False

        return True

    def _close_log_handlers(self):
        global_config = self.config
        loggers = map(lambda config: config.get_logger(), getattr(global_config, 'nodes', []) + getattr(global_config, 'clusters', []))
        session_module = 'foundation.session.%s' % self._session_id
        loggers.append(logging.getLogger(session_module))
        loggers.append(global_config.get_logger())
        for logger in loggers:
            for handler in list(logger.handlers):
                if isinstance(handler, FoundationFileHandler):
                    logger.removeHandler(handler)
                    handler.close()
                logger.propagate = True

    def archive_logs(self):
        """
        Archives the log files correpsonding to the session.
        """
        if self._archive_status == SessionConfig.ARCH_NOT_DONE:
            self._close_log_handlers()
            session_folder = folder_central.get_session_log_folder(self._session_id)
            if os.path.isdir(session_folder):
                self.archive_name = archive_log.archive_logs(session_id=self._session_id, prefix=self._session_id + '-')
            self.set_archive_status(SessionConfig.ARCH_DONE_FILES_PRESENT)

    def archive_and_delete_files(self):
        """
        Archive the session logs and then delete the logs and temporary files.
        """
        self.archive_logs()
        if self._archive_status == SessionConfig.ARCH_DONE_FILES_PRESENT:
            ret = self.delete_session_files()
            if ret:
                self.set_archive_status(SessionConfig.ARCH_DONE_FILES_DELETED)


class SessionManager(object):
    """
    Singleton class which manages all sessions in the system.
    """
    __metaclass__ = Singleton
    _session_configs = []
    _sessions_lock = threading.Lock()

    def create_session(self, reserved_session_type=None):
        """
        Creates a new session.
        Args:
          reserved_session_type: Type of this session. Can be None or one of
              RESERVED_WORKFLOWS_SESSIONID_MAP.keys(). If reserved_session_type
              is None, a general session is created. If reserved_session_type is a
              key in RESERVED_WORKFLOWS_SESSIONID_MAP, then a reserved session is
              created. A reserved session will be started only if no other session
              is running. Once this session becomes active, no other session will
              be allowed to run.
        
        Returns:
          Session id of the newly created session.
        
        Raises:
          StandardError if a reserved session is in progress or when
          reserved_session_type is invalid or if MAX_ACTIVE_SESSIONS number of
          sessions are already active.
        """
        global last_created_session_id
        global session_index
        from config_manager import GlobalConfig
        with self._sessions_lock:
            active_scs = filter(lambda sc: sc.is_active(), self._session_configs)
            if len(active_scs) >= MAX_ACTIVE_SESSIONS:
                raise StandardError('Foundation has reached the active sessions limit of %d and cannot start a new session now' % MAX_ACTIVE_SESSIONS)
            active_sids = [ sc._session_id for sc in active_scs ]
            session_ids = [ sc._session_id for sc in self._session_configs ]
            for sid in RESERVED_WORKFLOWS_SESSIONID_MAP.values():
                if sid in active_sids:
                    raise StandardError('Reserved session (%s) is in progress. Foundation cannot start another session now' % sid)

            if reserved_session_type:
                if reserved_session_type not in RESERVED_WORKFLOWS_SESSIONID_MAP:
                    raise StandardError('Unsupported reserved_session_type. reserved_session_type must be one of %s' % RESERVED_WORKFLOWS_SESSIONID_MAP.keys())
                session_id = RESERVED_WORKFLOWS_SESSIONID_MAP[reserved_session_type]
                if active_sids:
                    raise StandardError('%d imaging sessions are currently active. Cannot start a reserved session (%s) now' % (
                     len(active_sids), reserved_session_type))
                reserved_sc = filter(lambda sc: sc._session_id == session_id, self._session_configs)
                if reserved_sc:
                    self._session_configs.remove(reserved_sc[0])
            while True:
                if not reserved_session_type:
                    session_id = time.strftime('%Y%m%d-%H%M%S' + '-%d' % session_index)
                    if session_id in RESERVED_WORKFLOWS_SESSIONID_MAP.values() + [
                     IGNORED_SESSION_ID]:
                        continue
                if session_id not in session_ids:
                    break

            session_index += 1
            session_config = SessionConfig(session_id)
            session_config.config = GlobalConfig(parent=None)
            session_config.config._session_id = session_id
            session_config.config.abort_session = False
            session_config.config._session_config = session_config
            set_session_id(session_id)
            self._session_configs.append(session_config)
            last_created_session_id = session_id
        return session_id

    def get_session_by_id(self, session_id):
        """
        Retrieve the SessionConfig instance for the session corresponding to
        an input sesison id.
        Args:
          session_id: Id of the required session.
        
        Returns:
          SessionConfig instance corresponding to the input session id. If provided
          session id is invalid, None is returned.
        """
        with self._sessions_lock:
            for sc in self._session_configs:
                if sc._session_id == session_id:
                    return sc

            return
        return

    def get_config_for_session_id(self, session_id):
        """
        Retrieves the GlobalConfig object of a session.
        Args:
          session_id: Id of the session.
        
        Raises:
          StandardError if invalid session id is provided.
        
        Returns:
          GlobalConfig object of the session.
        """
        sc = self.get_session_by_id(session_id)
        if sc:
            return sc.config
        raise StandardError('Invalid session id: %s' % session_id)

    def get_active_session_ids(self):
        """
        Returns the list of active session ids.
        """
        with self._sessions_lock:
            sc_list = filter(lambda sc: sc.is_active(), self._session_configs)
            return [ sc._session_id for sc in sc_list ]

    def get_successful_session_ids(self):
        """
        Returns the list of successfully completed sessions ids.
        """
        with self._sessions_lock:
            sc_list = filter(lambda sc: sc.has_succeeded(), self._session_configs)
            return [ sc._session_id for sc in sc_list ]

    def get_failed_session_ids(self):
        """
        Returns the list of failed session ids.
        """
        with self._sessions_lock:
            sc_list = filter(lambda sc: sc.has_failed(), self._session_configs)
            return [ sc._session_id for sc in sc_list ]

    def get_all_session_ids(self):
        """
        Returns the list of all session ids.
        """
        with self._sessions_lock:
            return [ sc._session_id for sc in self._session_configs ]

    def get_active_configs(self):
        """
        Returns the list of config objects for all active sessions.
        """
        with self._sessions_lock:
            active_sessions = filter(lambda sc: sc.is_active(), self._session_configs)
            return [ sc.config for sc in active_sessions ]

    def abort_session(self, session_id):
        """
        Aborts an active session.
        Args:
          session_id: Id of the session which needs to be aborted.
        
        Returns:
          None
        
        Raises:
          StandardError if session id is invalid or if the session is already
          in aborted state or not active.
        """
        sc = self.get_session_by_id(session_id)
        if not sc:
            raise StandardError('Invalid session id: %s' % session_id)
        with self._sessions_lock:
            gc = sc.config
            if gc.abort_session:
                raise StandardError("Session with id '%s' is already in aborted state" % session_id)
            if not sc.is_active():
                raise StandardError("Session with id '%s' is not active. Only active sessions can be aborted" % session_id)
            logger = gc.get_logger()
            gc.abort_session = True
            logger.info("Marking session with id '%s' as aborted" % session_id)
            sc.set_fail()

    def mark_idle_session_as_failed(self, session_id):
        """
        Marks an idle session as failed.
        Args:
          session_id: Id of the session which is idle.
        
        Raises:
          StandardError if the session id provided is not found.
          AssertionError if the session id provided is not idle.
        
        Returns:
          None
        """
        with self._sessions_lock:
            session_config = None
            for sc in self._session_configs:
                if sc._session_id == session_id:
                    session_config = sc
                    break

            if not session_config:
                raise StandardError('Invalid session id (%s) provided' % session_id)
            if not session_config.is_idle():
                raise StandardError('Session id (%s) does not belong to an idle session' % session_id)
            session_config.set_fail_idle_session()
        return

    def mark_session_as_succeeded(self, session_id):
        """
        Marks a session as succeeded.
        Args:
          session_id: Id of the session.
        
        Raises:
          StandardError if the session id provided is not found.
          AssertionError if the session id provided is not active.
        
        Returns:
          None
        """
        with self._sessions_lock:
            session_config = None
            for sc in self._session_configs:
                if sc._session_id == session_id:
                    session_config = sc
                    break

            if not session_config:
                raise StandardError('Invalid session id (%s) provided' % session_id)
            if session_config.has_failed():
                return
            if not session_config.is_active():
                raise StandardError('Cannot mark a non-active session as succeeded')
            session_config.set_success()
        return

    def mark_session_as_failed(self, session_id):
        """
        Marks a session as failed.
        Args:
          session_id: Id of the session.
        
        Raises:
          StandardError if the session id provided is not found.
          AssertionError if the session id provided is not active.
        
        Returns:
          None
        """
        with self._sessions_lock:
            session_config = None
            for sc in self._session_configs:
                if sc._session_id == session_id:
                    session_config = sc
                    break

            if not session_config:
                raise StandardError('Invalid session id (%s) provided' % session_id)
            if session_config.has_failed():
                return
            if not session_config.is_active():
                raise StandardError('Cannot mark a non-active session as failed')
            session_config.set_fail()
        return

    def get_completed_sessions_with_files_on_disk(self):
        """
        Returns a list of session configs whose files are still present on disk.
        """
        completed_sc_list = []
        with self._sessions_lock:
            for sc in self._session_configs:
                if (sc.has_succeeded() or sc.has_failed()) and sc.has_files():
                    completed_sc_list.append(sc)

        return completed_sc_list

    def get_idle_and_failed_sessions(self):
        """
        Returns a list of session configs for the idle sessions which have failed.
        """
        sc_list = []
        with self._sessions_lock:
            for sc in self._session_configs:
                if sc.is_idle_and_failed():
                    sc_list.append(sc)

        return sc_list

    def get_archived_sessions_without_files_on_disk(self):
        """
        Returns a list of session configs whose files have been deleted after
        archival.
        """
        sc_list = []
        with self._sessions_lock:
            sc_list += filter(lambda sc: sc.is_archived_and_deleted(), self._session_configs)
        return sc_list

    def cleanup_untracked_session_folders(self):
        """
        If Foundation service is killed or restarted there can be left over
        sessions folder from previous Foundation service. Clean it up if any folder
        is not part of currently tracked sessions list.
        """
        log_dir = folder_central.get_log_folder()
        reserved_dirs = ['archive', 'factory_archive']
        with self._sessions_lock:
            session_ids = [ sc._session_id for sc in self._session_configs ]
            for name in os.listdir(log_dir):
                full_path = os.path.join(log_dir, name)
                if not os.path.isdir(full_path):
                    continue
                if os.path.islink(full_path):
                    continue
                if name in reserved_dirs:
                    continue
                if name in session_ids:
                    continue
                if not archive_log.is_session_already_in_archive(name):
                    archive_log.archive_logs(prefix=name + '-', session_id=name)
                shutil.rmtree(full_path)

            sessions_dir = folder_central.get_sessions_root_folder()
            for name in os.listdir(sessions_dir):
                full_path = os.path.join(sessions_dir, name)
                if name in session_ids:
                    continue
                if os.path.isdir(full_path):
                    shutil.rmtree(full_path)

            if not session_ids:
                delete_latest_session_log_link()

    def archive_and_delete_old_session_logs(self):
        """
        Archives and deletes session files. Always files of last ARCH_THRESHOLD
        sessions are kept in log folder without archiving. It also cleans up
        untracked session files and shared files.
        """
        sm = get_session_manager()
        sessions_using_disk = sm.get_completed_sessions_with_files_on_disk()
        sessions_using_disk += sm.get_idle_and_failed_sessions()
        if len(sessions_using_disk) >= ARCH_THRESHOLD:
            sorted_sc_list = sorted(sessions_using_disk, key=lambda x: x.end_time)
            archive_count = len(sessions_using_disk) - ARCH_THRESHOLD
            sorted_sc_list = sorted_sc_list[:archive_count]
            for sc in sorted_sc_list:
                sc.archive_and_delete_files()

        self.cleanup_untracked_session_folders()
        cleanup_shared_files()


global_session_manager = SessionManager()

def reset_session_manager():
    """
    Resets session manager. Existing sessions will no longer be available.
    """
    global global_session_manager
    global last_active_session_id
    global_session_manager._session_configs = []
    last_active_session_id = None
    set_session_id(None)
    return


def get_session_manager():
    """
    Returns the SessionManager instance.
    """
    return global_session_manager


def get_last_active_session_id():
    """
    Returns the last active session id. This can be used as default session id
    for rest APIs which do not get a session id as input.
    """
    return last_active_session_id


def clear_last_active_session_id():
    """
    Clears the last active session id.
    """
    global last_active_session_id
    last_active_session_id = None
    return


def get_new_session_id():
    """
    Creates a new session.
    
    Returns:
      Session id of the newly created session.
    """
    sm = get_session_manager()
    session_id = sm.create_session()
    return session_id


def get_new_reserved_session_id(reserved_session_type):
    """
    Creates a new reserved session.
    Args:
      reserved_session_type: Type of the reserved session to be created. Must be
          one of RESERVED_WORKFLOWS_SESSIONID_MAP.keys(). When a valid type is
          provided, it will be created only if no other session is running. Once
          this session becomes active, no other session will be allowed to run.
    
    Returns:
      Session id of the newly created reserved session.
    """
    sm = get_session_manager()
    session_id = sm.create_session(reserved_session_type=reserved_session_type)
    return session_id


def get_session_by_id(session_id):
    """
    Retrieves the SessionConfig instance corresponding to given session id.
    Args:
      session_id: Id of the session.
    
    Returns:
      SessionConfig instance of the session.
    """
    sm = get_session_manager()
    return sm.get_session_by_id(session_id)


def mark_session_success(session_id):
    """
    Marks a session as successfully completed.
    Args:
      session_id: Id of the completed session.
    
    Returns:
      None
    """
    sm = get_session_manager()
    sm.mark_session_as_succeeded(session_id)
    tools.update_metadata({'session_success': True, 
       'idle_session': False}, session_id)


def mark_session_failure(session_id):
    """
    Marks a session as failed.
    Args:
      session_id: Id of the completed session.
    
    Returns:
      None
    """
    sm = get_session_manager()
    sm.mark_session_as_failed(session_id)
    tools.update_metadata({'session_success': False, 
       'idle_session': False}, session_id)


def mark_idle_session_failure(session_id):
    """
    Marks a session as failed.
    Args:
      session_id: Id of the idle session which failed.
    
    Returns:
      None
    """
    sm = get_session_manager()
    sm.mark_idle_session_as_failed(session_id)
    tools.update_metadata({'session_success': False, 
       'idle_session': True}, session_id)


def get_global_config(session_id=None):
    """
    Retrieves the GlobalConfig object corresponding to the provided session id.
    
    Args:
      session_id: Id of the session. If the thread making this request has the
          session_id in it, then this is not required.
    
    Returns:
      GlobalConfig object corresponding to the session.
    
    Raises:
      StandardError if session id is invalid or if session id of the thread
      couldn't be determined.
    """
    if not session_id:
        session_id = get_session_id()
        if not session_id:
            raise StandardError("Couldn't find current session id. Provide a valid session id")
    sm = get_session_manager()
    global_config = sm.get_config_for_session_id(session_id)
    if not global_config:
        raise StandardError('Invalid session provided')
    return global_config


def get_all_session_ids_by_category():
    """
    Returns a dictionary of active, completed and failed session ids.
    """
    sm = get_session_manager()
    failed_sids = sm.get_failed_session_ids()
    completed_sids = sm.get_successful_session_ids()
    active_sids = sm.get_active_session_ids()
    type_sid_map = {'active_sessions': active_sids, 
       'succeeded_sessions': completed_sids, 
       'failed_sessions': failed_sids}
    return type_sid_map


def set_session_active(session_id):
    """
    Marks a session as active.
    Args:
      session_id: Id of the session.
    
    Raises:
      StandardError if an invalid session id is provided or if the number of
      active sessions has reached MAX_ACTIVE_SESSIONS limit.
    
    Returns:
      None
    """
    sm = get_session_manager()
    sc = get_session_by_id(session_id)
    if not sc:
        raise StandardError('Invalid session id: %s' % session_id)
    active_sids = sm.get_active_session_ids()
    if len(active_sids) >= MAX_ACTIVE_SESSIONS:
        raise StandardError('Foundation has reached the active sessions limit of %d and cannot start a new active session now' % MAX_ACTIVE_SESSIONS)
    sc.set_active()


def get_session_id():
    """
    Returns the session id of the current thread if it is set. Otherwise None
    is returned.
    """
    return getattr(threading.currentThread(), THREAD_SID_ATTR, None)


def set_session_id(session_id, thread=None):
    """
    Sets the session id of the current thread.
    Args:
      session_id: Session id to be set.
      thread: Thread object whose session id needs to be set. If None, session id
          of current thread is set.
    """
    t = thread or threading.currentThread()
    setattr(t, THREAD_SID_ATTR, session_id)


def get_unique_node_attribute():
    """
    Returns the attribute which can be used to uniquely identify a node.
    Returns:
      Attribute name which can uniquely identify a node.
    """
    if imaging_context.get_context() == imaging_context.FIELD_VM:
        return 'phoenix_ip'
    return 'ipmi_ip'


def validate_nodes_to_be_imaged(global_config):
    """
    This function validates whether nodes in an input imaging config are being
    imaged in any other session.
    Args:
      global_config: GlobalConfig object of the incoming imaging request.
    
    Returns:
      Tuple (False, <error_message>) if validation fails, i.e. one or more nodes
          in input imaging config are being imaged in some session.
      Tuple (True, None) is validation succeeds.
    """
    from config_manager import NodeConfig
    from config_manager import GlobalConfig
    sm = get_session_manager()
    if imaging_context.get_context() == imaging_context.FIELD_VM:
        unique_attr = get_unique_node_attribute()
        ips = [ getattr(node, unique_attr) for node in global_config.nodes ]
        foundation_ip = tools.get_interface_ip()
        if foundation_ip not in ips:
            gc_temp = GlobalConfig()
            nc_temp = NodeConfig(parent=gc_temp)
            gc_temp._session_id = IGNORED_SESSION_ID
            nc_temp.cvm_ip = foundation_ip
            status, attr, ip, sid = are_nodes_in_any_active_session(gc_temp)
            if status:
                msg = 'Node with %s %s is being imaged in session with id %s' % (
                 attr, ip, sid)
                return (
                 False, msg)
            status, attr, ip, sid = are_nodes_in_any_active_session(global_config)
            if status:
                msg = 'Node with %s %s is being imaged in session with id %s' % (
                 attr, ip, sid)
                return (
                 False, msg)
            return (True, None)
        active_gcs = sm.get_active_configs()
        active_sessions = [ gc._session_id for gc in active_gcs ]
        if not active_sessions or len(active_sessions) == 1 and global_config._session_id in active_sessions:
            return (
             True, None)
        return (
         False, 'Current node is managing other imaging sessions')
    status, attr, ip, sid = are_nodes_in_any_active_session(global_config)
    if status:
        msg = 'Node with %s %s is being imaged in session with id %s' % (
         attr, ip, sid)
        return (
         False, msg)
    return (True, None)


def are_nodes_in_any_active_session(global_config):
    """
    Checks whether any node node in the given GlobalConfig is part of
    any active imaging session.
    Args:
      global_config: GlobalConfig object which needs to be validated against
          existing sessions.
    
    Returns:
      If any node is being imaged, it will return the following tuple.
      (True, unique attribute of the node, ip of the node, id of the
       session in which this node is currently being imaged)
      Tuple (False, unique attribute of the node, None, None) is returned
      otherwise.
    """
    unique_attr = get_unique_node_attribute()
    ips = [ getattr(node, unique_attr, '') for node in global_config.nodes ]
    sm = get_session_manager()
    gcs = sm.get_active_configs()
    for gc in gcs:
        if gc._session_id == global_config._session_id or gc._session_id == IGNORED_SESSION_ID:
            continue
        for node in getattr(gc, 'nodes', []):
            ip = getattr(node, unique_attr, None)
            if ip in ips:
                return (True, unique_attr, ip, gc._session_id)

    return (
     False, unique_attr, None, None)


def is_session_possible(global_config, set_active=True):
    """
    This function verifies whether Foundation should accept an incoming imaging
    request. It verifies that the nodes in input config are not being imaged in
    any other session and whether enough disk space is available to start a new
    session. If enough disk space is not available, this function will archive
    old session files and try to make more disk space.
    Args:
      global_config: GlobalConfig object of the incoming imaging request.
    
    Returns:
      Tuple (False, <error_message>) if imaging is not possible.
      Tuple (True, None) is returned otherwise.
    """
    try:
        sm = get_session_manager()
        with DUP_VALIDATION_LOCK:
            status, err = validate_nodes_to_be_imaged(global_config)
            if not status:
                return (status, err)
            is_imaging = any(map(lambda n: getattr(n, 'image_now', False), getattr(global_config, 'nodes', [])))
            if is_imaging:
                ret, msg, available_space = tools.check_disk_space(hypervisors=getattr(global_config, 'hypervisor_iso', {}), nos=getattr(global_config, 'nos_package', None))
                if ret == 1:
                    return (False, msg)
                if ret == 2:
                    logger.warning('Session_id: %s\nWarning: %s\nAvailable space: %d\nFoundation will try to free up space by archiving and deleting old sessions' % (
                     global_config._session_id, msg, available_space))
                    sm.archive_and_delete_old_session_logs()
                    ret, msg, available_space = tools.check_disk_space(hypervisors=getattr(global_config, 'hypervisor_iso', {}), nos=getattr(global_config, 'nos_package', None))
                    if ret in (1, 2):
                        raise StandardError("Foundation vm is running out of space. Foundation couldn't free up enough space on the vm. Manually remove unwanted files and retry")
            sessions_using_disk = sm.get_completed_sessions_with_files_on_disk()
            sessions_using_disk += sm.get_idle_and_failed_sessions()
            if len(sessions_using_disk) >= ARCH_THRESHOLD:
                sm.archive_and_delete_old_session_logs()
            if set_active:
                set_session_active(global_config._session_id)
    except StandardError as e:
        logger.exception('session is not possible')
        return (
         False, str(e))

    return (
     True, None)


def add_shared_file(file_path, cache_hash):
    """
    Adds a new file to the list of shared files across sessions. The caller
    must acquire SHARED_FILES_LOCK before creating/starting to use this file
    for the first time.
    Args:
      file_path: Full path of the shared file.
      cache_hash: Cache key used in CacheManager which return this file.
    Raises:
      StandardError if session id cannot be determined from the thread.
    Returns:
      None
    """
    global shared_files_config
    if not os.path.exists(file_path):
        return
    if file_path not in shared_files_config:
        shared_files_config[file_path] = {}
        shared_files_config[file_path]['session_ids'] = []
    session_id = get_session_id()
    if not session_id:
        raise StandardError("Couldn't find session id from thread")
    shared_files_config[file_path]['cache_hash'] = cache_hash
    if session_id not in shared_files_config[file_path]['session_ids']:
        shared_files_config[file_path]['session_ids'].append(session_id)


def cleanup_shared_files():
    """
    Deletes shared files which are no longer being used by any session.
    """
    from config_manager import CacheManager
    sm = get_session_manager()
    with SHARED_FILES_LOCK:
        deleted_files = []
        for shared_file, data in shared_files_config.iteritems():
            sid_list = data['session_ids']
            completed_sids = []
            for sid in sid_list:
                sc = sm.get_session_by_id(sid)
                if not sc:
                    completed_sids.append(sid)
                    continue
                if sc.has_succeeded() or sc.has_failed():
                    completed_sids.append(sid)

            for sid in completed_sids:
                sid_list.remove(sid)

            if not sid_list:
                if os.path.isfile(shared_file):
                    os.remove(shared_file)
                else:
                    if os.path.isdir(shared_file):
                        shutil.rmtree(shared_file)
                logger.debug('Deleted shared file (%s)' % shared_file)
                cache_hash = data['cache_hash']
                CacheManager.remove_cache_entry(cache_hash)
                logger.debug('Removed cache entry (%s)' % cache_hash)
                deleted_files.append(shared_file)

        for shared_file in deleted_files:
            del shared_files_config[shared_file]