# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/simple_logger.py
# Compiled at: 2019-02-15 12:42:10
import collections, logging, os, platform, threading, warnings
from logging.handlers import RotatingFileHandler, SysLogHandler
import folder_central, foundation_tools
CONSOLE_FORMAT = '%(asctime)s %(name)+5s: %(message)s'
RSYSLOG_FORMAT = '%(asctime)s %(foundation_ip)s %(name)s %(levelname)s %(message)s'
LOGALL_FORMAT = '%(asctime)s %(threadName)s %(module)s.%(funcName)s:%(lineno)d %(levelname)s: %(message)s'
FILELOG_FORMAT = '%(asctime)s %(levelname)s %(message)s'
DEFAULT_FORMAT = '%(asctime)s %(name)s %(levelname)s %(message)s'
ROOT_FORMAT = DEFAULT_FORMAT
DATEFMT = '%Y%m%d %H:%M:%S'
RSYSLOG_PORT = 514
MAX_BACKUP = 1
sessions_lock = collections.defaultdict(threading.RLock)

def get_current_session():
    from foundation import session_manager
    t = threading.currentThread()
    session_id = session_manager.get_session_id()
    if not (session_id and isinstance(session_id, basestring)):
        raise AssertionError('Session id is not a string')
    return session_id


def get_file_handler(fn, format=FILELOG_FORMAT, level=logging.DEBUG):
    fh = FoundationFileHandler(fn, backupCount=MAX_BACKUP, delay=True)
    fh.setLevel(level)
    fh.setFormatter(logging.Formatter(format, datefmt=DATEFMT))
    return fh


def get_rsyslog_handler(address, format=RSYSLOG_FORMAT, level=logging.DEBUG):
    port = RSYSLOG_PORT
    if ':' in address:
        ip_port = address.split(':')
        ip = ip_port[0]
        port = int(ip_port[1])
    else:
        ip = address
    handler = SysLogHandler((ip, port))
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter(format, datefmt=DATEFMT))
    handler.addFilter(FoundationIPFilter())
    return handler


class NullHandler(logging.Handler):
    """Null logging handler."""

    def handle(self, record):
        pass

    def emit(self, record):
        pass

    def createLock(self):
        self.lock = None
        return


class FoundationIPFilter(logging.Filter):
    """
    Filter for SysLogHandler to add foundation ip as unique identifer for log
    source.
    """
    foundation_ip = None

    def _get_foundation_ip(self):
        """
        Find our external IP.
        """
        if not self.foundation_ip:
            self.foundation_ip = '127.0.0.1'
            try:
                self.foundation_ip = foundation_tools.get_my_ip('1.2.3.4', 0)
            except IOError:
                pass

        return self.foundation_ip

    def filter(self, record):
        record.foundation_ip = self._get_foundation_ip()
        return True


def is_handler_present(cls, record_name):
    logger = logging.getLogger(record_name)
    for handler in logger.handlers:
        if isinstance(handler, cls):
            return True

    return False


def delete_latest_session_log_link():
    """
    Delete the latest session log link if its target does not exist.
    """
    from session_manager import LATEST_LOG_LINK, LATEST_LOG_LINK_LOCK
    root_log_dir = folder_central.get_log_folder()
    latest_log_link = os.path.join(root_log_dir, LATEST_LOG_LINK)
    with LATEST_LOG_LINK_LOCK:
        if os.path.islink(latest_log_link):
            real_path = os.path.realpath(latest_log_link)
            if not os.path.exists(real_path):
                os.unlink(latest_log_link)


class FoundationSessionFilter(logging.Filter):
    """
    Filters out the session-specific messages from debug.log in root log folder.
    """

    def filter(self, record):
        """
        Log only if the thread does not belong to any session.
        """
        if not get_current_session():
            return True
        return False


class FoundationFileHandler(RotatingFileHandler, object):
    """
    Custom File Handler to be used by Foundation.
    """

    def __init__(self, *args, **kwargs):
        super(FoundationFileHandler, self).__init__(*args, **kwargs)

    def handle(self, record):
        session_id = get_current_session()
        if session_id:
            s_lock = sessions_lock[session_id]
            names = record.name.split('.')
            with s_lock:
                if record.name.startswith('foundation.session') and len(names) > 3:
                    if not is_handler_present(FoundationFileHandler, record.name):
                        return
        if self.filter(record):
            self.acquire()
            try:
                self.emit(record)
            finally:
                self.release()


class SessionLogHandler(logging.Handler, object):
    """
    Log handler for foundation.session module.
    """

    def __init__(self, *args, **kwargs):
        super(SessionLogHandler, self).__init__(*args, **kwargs)

    def emit(self, record):
        pass

    def init_debug(self, session_module):
        """
        Initialize the debug.log for a session.
        Args:
          session_module: Name of the session module.
          Ex: foundation.session.<session_id>
        """
        from session_manager import last_created_session_id, LATEST_LOG_LINK, LATEST_LOG_LINK_LOCK
        session_id = get_current_session()
        logger = logging.getLogger(session_module)
        log_dir = folder_central.get_session_log_folder(session_id)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        if session_id == last_created_session_id:
            with LATEST_LOG_LINK_LOCK:
                root_log_dir = folder_central.get_log_folder()
                latest_log_link = os.path.join(root_log_dir, LATEST_LOG_LINK)
                if os.path.exists(latest_log_link):
                    os.unlink(latest_log_link)
                if platform.system() != 'Windows':
                    os.symlink(log_dir, latest_log_link)
                else:
                    warnings.warn('skip symlinking latest log dir on Windows')
        log_filename = os.path.join(log_dir, 'debug.log')
        fh = get_file_handler(log_filename)
        logger.addHandler(fh)

    def create_module_handler(self, record):
        """
        Creates a new log file for a module within a session.
        Args:
          record: Log record which initiated the request.
        """
        session_id = get_current_session()
        names = record.name.split('.')
        module_name = ('.').join(names[3:])
        logger = logging.getLogger(record.name)
        log_dir = folder_central.get_session_log_folder(session_id)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        log_filename = os.path.join(log_dir, module_name + '.log')
        logger.propagate = True
        fh = get_file_handler(log_filename)
        logger.addHandler(fh)
        logging.getLogger('console').debug('Log from %s is logged at %s' % (
         record.name, log_filename))

    def handle(self, record):
        """
        Custom handler for foundation.session.
        Args:
          record: Log record to be handled.
        """
        names = record.name.split('.')
        if len(names) < 3:
            return
        session_id = names[2]
        session_module = ('.').join(names[:3])
        new_module = None
        if len(names) > 3:
            new_module = ('.').join(names[3:])
        logger = logging.getLogger(record.name)
        s_lock = sessions_lock[session_id]
        handle = False
        with s_lock:
            if not is_handler_present(FoundationFileHandler, session_module):
                self.init_debug(session_module)
            if new_module and not is_handler_present(FoundationFileHandler, record.name):
                self.create_module_handler(record)
                handle = True
        if handle:
            logger.handle(record)
        return


class FoundationLogHandler(logging.Handler, object):
    """
    Log handler for foundation log module.
    """

    def __init__(self, *args, **kwargs):
        self.log_dir = kwargs.pop('log_dir')
        super(FoundationLogHandler, self).__init__(*args, **kwargs)

    def emit(self, record):
        pass

    def handoff_session_logs(self, record):
        """
        Hands off the log record to session handler.
        Args:
          record: Log record to be handed off.
        """
        session_id = get_current_session()
        assert session_id != None
        names = record.name.split('.')
        if len(names) < 2:
            return
        module = ('.').join(names[1:])
        record.name = 'foundation.session.%s.%s' % (session_id, module)
        logger = logging.getLogger(record.name)
        logger.handle(record)
        return

    def handle_non_session_logs(self, record):
        """
        Handles log not belonging to any session.
        Args:
          record: Log record to be handled.
        """
        names = record.name.split('.')
        if len(names) < 2:
            return
        logger = logging.getLogger(record.name)
        for handler in logger.handlers:
            if isinstance(handler, FoundationFileHandler):
                break
        else:
            module = ('.').join(names[1:])
            log_filename = os.path.join(self.log_dir, module + '.log')
            logger.propagate = False
            fh = get_file_handler(log_filename)
            logger.addHandler(fh)
            logger.handle(record)

    def handle(self, record):
        """
        Custom handler for foundation module.
        """
        if record.name.startswith('foundation.session'):
            return
        session_id = get_current_session()
        if session_id:
            self.handoff_session_logs(record)
        else:
            self.handle_non_session_logs(record)


class SmartFileLoggerHandler(logging.Handler, object):
    """
    Root log handler.
    """

    def __init__(self, *args, **kwargs):
        self.log_dir = kwargs.pop('log_dir')
        super(SmartFileLoggerHandler, self).__init__(*args, **kwargs)

    def emit(self, record):
        pass

    def handoff_session_log(self, record):
        """
        Hands of log record to session handler.
        Args:
          record: Log record to be handled.
        """
        names = record.name.split('.')
        session_id = get_current_session()
        record.name = 'foundation.session.%s' % session_id
        logger = logging.getLogger(record.name)
        logger.handle(record)

    def handle(self, record):
        """
        Custom handler for root module.
        Args:
          record: Log record to be handled.
        """
        names = record.name.split('.')
        if names[0] == 'foundation':
            return
        session_id = get_current_session()
        if session_id:
            self.handoff_session_log(record)


def add_handler(log_root, cls, log_dir=None):
    """
    Adds a handler to a log module.
    Args:
      log_root: Log module.
      cls: Handler class to be added to log_root module.
      log_dir: Log directory for the handler.
    """
    console = logging.getLogger('console')
    if log_root:
        root_logger = logging.getLogger(log_root)
    else:
        root_logger = logging.getLogger()
    root_logger.propagate = False
    for handler in root_logger.handlers:
        if isinstance(handler, cls):
            console.debug('%s is already configured for %s' % (
             cls, log_root))
            break
    else:
        console.debug('Configuring %s for %s' % (cls, log_root))
        if cls == SmartFileLoggerHandler:
            handler = SmartFileLoggerHandler(log_dir=log_dir)
        else:
            if cls == FoundationLogHandler:
                handler = FoundationLogHandler(log_dir=log_dir)
            else:
                if cls == SessionLogHandler:
                    handler = SessionLogHandler()
            root_logger.addHandler(handler)


def rotate_all_logger(log_root='foundation'):
    """
    Rotate all child loggers at log_root.
    The rotated log filename will be like xxx.log.1
    """
    root_logger = logging.getLogger()
    console = logging.getLogger('console')
    logging._acquireLock()
    items = list(root_logger.manager.loggerDict.items())
    console.info('Rollover existing logs')
    for log_key, logger in items:
        if isinstance(logger, logging.PlaceHolder):
            continue
        for handler in logger.handlers:
            if isinstance(handler, FoundationFileHandler):
                if hasattr(handler, 'stream') and handler.stream:
                    console.debug('Rollover %s:%s', log_key, logger)
                    try:
                        handler.doRollover()
                    except OSError:
                        console.exception('Exception in rollover %s, this is not expected.Please report this information to developer team.', log_key)
                        handler.stream = 'w'
                        handler.stream = handler._open()

    logging._releaseLock()


def remove_all_file_handler(remove_smart_log_handler=False):
    """
    Remove the smart routing handlers and all rotating file handlers.
    the 'deinit' function
    """
    console = logging.getLogger('console')
    root_logger = logging.getLogger()
    logging._acquireLock()
    items = list(root_logger.manager.loggerDict.items())
    for log_key, logger in items:
        if isinstance(logger, logging.PlaceHolder):
            continue
        handlers = list(logger.handlers)
        for handler in handlers:
            if isinstance(handler, FoundationFileHandler):
                console.debug('Removing handler %s from %s', handler, log_key)
                logger.propagate = True
                logger.removeHandler(handler)
                try:
                    handler.close()
                except OSError:
                    pass

            if remove_smart_log_handler and (isinstance(handler, FoundationLogHandler) or isinstance(handler, SessionLogHandler)):
                console.debug('Removing handler %s from %s', handler, log_key)
                logger.propagate = True
                logger.removeHandler(handler)

    root_handlers = list(root_logger.handlers)
    for handler in root_handlers:
        if isinstance(handler, FoundationFileHandler) or remove_smart_log_handler and isinstance(handler, SmartFileLoggerHandler):
            console.debug('Removing handler %s from root' % handler)
            root_logger.removeHandler(handler)

    logging._releaseLock()


def setup_loggers(log_root='foundation', log_all=None, rsyslog=None, console=True, debug=False):
    """
    Must be called before any logging activity.
    The 'init' function.
    
    Parameters:
      log_all: str, path to a file that stores every log.
      rsyslog: str, remote syslog server address, in the format of IP<:PORT>.
      console: bool, if True, enable console logging.
    """
    log_dir = folder_central.get_log_folder()
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    if len(root_logger.handlers) == 0:
        if debug:
            logging.basicConfig(format=CONSOLE_FORMAT, level=logging.DEBUG)
        else:
            root_logger.addHandler(NullHandler())
        root_logger.info('Root logger configured')
    if log_all:
        handler = FoundationFileHandler(log_all, backupCount=MAX_BACKUP, delay=True)
        handler.setFormatter(logging.Formatter(LOGALL_FORMAT))
        handler.setLevel(logging.DEBUG)
        handler.addFilter(FoundationSessionFilter())
        root_logger.addHandler(handler)
        root_logger.info('All logs will be stored at %s', log_all)
    if rsyslog:
        rsyslog_handler = get_rsyslog_handler(rsyslog)
        root_logger.addHandler(rsyslog_handler)
        root_logger.info('All logs will be sent to %s', rsyslog)
    if console:
        console_logger = logging.getLogger('console')
        if len(console_logger.handlers) == 0:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter(CONSOLE_FORMAT))
            handler.setLevel(logging.DEBUG)
            console_logger.addHandler(handler)
            console_logger.info('Console logger is configured')
    add_handler(None, SmartFileLoggerHandler, log_dir=log_dir)
    add_handler('foundation', FoundationLogHandler, log_dir=log_dir)
    add_handler('foundation.session', SessionLogHandler)
    logging.getLogger('paramiko.transport').setLevel(logging.INFO)
    return