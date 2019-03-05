# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/decorators.py
# Compiled at: 2019-02-15 12:42:10
import cherrypy, time, logging
from functools import wraps, partial
from foundation import session_manager
from foundation.config_persistence import post_imaging_result, clear_keys
from foundation.imaging_step_cluster_init import ImagingStepClusterInit
TIMEOUT_FOR_REMOTE_CLUSTER_TO_BE_UP = 3600

def wait_for_cluster_creation(func):
    """
    This decorator can be used by any thread to wait on a given
    cluster's creation event. The name of target cluster to wait for, must be
    specified in self.config.target_cluster_name
    
    Once func() is called, decorator will first wait for target cluster to be
    created, if succesful will call the func and if unsuccesful, raise a
    StandardError.
    
    """

    @wraps(func)
    def wrap_method(self):
        logger = self.logger
        target_cluster_name = self.config.target_cluster_name
        target_cluster = None
        for cluster in self.config.get_root().clusters:
            if cluster.cluster_name == target_cluster_name:
                target_cluster = cluster
                break
        else:
            raise StandardError('target_cluster_name is missing in global_config')

        cluster_init_task = None
        for task in target_cluster.tasks:
            if isinstance(task, ImagingStepClusterInit):
                cluster_init_task = task
                break
        else:
            raise StandardError('Unable to find cluster init task for %s' % target_cluster_name)

        start_time = time.time()
        timeout = TIMEOUT_FOR_REMOTE_CLUSTER_TO_BE_UP
        is_timedout = False
        while not cluster_init_task.is_done() and not is_timedout:
            time_elapsed = int(time.time() - start_time)
            is_timedout = time_elapsed > timeout
            logger.info('[%s/%ss] Waiting for target cluster %s to be created' % (
             time_elapsed, int(timeout), target_cluster_name))
            time.sleep(60)

        if cluster_init_task.get_state() != 'FINISHED':
            raise StandardError('Target cluster %s was not created successfully within the timeout' % target_cluster_name)
        func(self)
        return

    return wrap_method


def persist_config_on_failure(func):
    """
    Decorator to persist config on failure.
    """

    @wraps(func)
    def wrap_method(self):
        if not self.config.image_now:
            self.logger.info('%s skipped' % str(self))
            return
        wrapper = partial(post_imaging_result, self.config.node_id)
        try:
            func(self)
        except:
            self.logger.exception('Exception in %s' % str(self))
            wrapper(False)
            raise

    return wrap_method


def save_post_params(func):
    """
    Decorator to save post params sent to a REST API.
    """

    @wraps(func)
    def wrap_method(*args, **kwargs):
        logger = logging.getLogger('foundation.api')
        json = getattr(cherrypy.request, 'json', None)
        if json:
            logger.debug('%s called with' % func.__name__)
            logger.debug(clear_keys(json, ['ipmi_password']))
        return func(*args, **kwargs)

    return wrap_method


def fail_session_on_error(func):
    """
    Marks current session as failed in case of any error.
    """

    @wraps(func)
    def wrap_method(*args, **kwargs):
        ret = None
        try:
            ret = func(*args, **kwargs)
        except:
            api_logger = logging.getLogger('foundation.api')
            session_id = session_manager.get_session_id()
            if session_id:
                sm = session_manager.get_session_manager()
                session_config = sm.get_session_by_id(session_id)
                if session_config.is_idle():
                    api_logger.info('Marking idle session %s as failed', session_id)
                    sm.mark_idle_session_as_failed(session_id)
                elif session_config.is_active():
                    api_logger.info('Marking active session %s as failed', session_id)
                    sm.mark_session_as_failed(session_id)
            raise

        return ret

    return wrap_method