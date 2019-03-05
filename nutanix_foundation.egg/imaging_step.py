# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step.py
# Compiled at: 2019-02-15 12:42:10
import glob, itertools, threading, config_manager, foundation_tools, folder_central, logging, session_manager
MAX_BOOT_PROCS = 30
BOOT_SEMA = threading.Semaphore(MAX_BOOT_PROCS)
DEFAULT_LOGGER = logging.getLogger(__file__)

class GraphNode(object):

    def __init__(self):
        self._dependencies = set()
        self._state = 'pending'

    def _iall_deps(self, include_self=True):
        """
        iter of all current dependencies of `self` (recursively)
        """
        deps = []
        if include_self:
            deps = [
             self]
        return itertools.chain(deps, *map(lambda dep: dep._iall_deps(), self._dependencies))

    def set_dependencies(self, depends):
        self._dependencies.update(set(depends))


class ImagingStepTask(GraphNode):
    """
    ImagingStepTask(Config), the base class of all tasks.
    
    Useful attributes:
      config: the config object
    Useful functions:
      set_status: update current status
      get_progress_timing: provide custom progress counting
      get_finished_message: provide user friendly status message on finished
    """
    event = threading.Event()
    config_type = config_manager.BaseConfig

    def __init__(self, config=None):
        super(ImagingStepTask, self).__init__()
        self.config = config
        self._state = 'PENDING'
        self._state_lock = threading.Lock()
        self._status_str = None
        self._exception = None
        self.config.tasks.append(self)
        return

    def __repr__(self):
        return '<%s(%s) @%s>' % (self.__class__.__name__,
         self.config, hex(id(self))[-4:])

    def _dependency_configs(self):
        """
        configs to use for calculating dependencies
        
        Returns:
          a set of NodeConfig
        
        NOTE:
        the default impl is
         - a NodeConfig depends on itself
         - a ClusterConfig or GlobalConfig depends on all it's nodes
        
        You may want to override this method for custom dependency calculation.
        """
        task_config = self.config
        if task_config._is_leaf:
            return set([task_config])
        return set(task_config.nodes)

    def _all_dependencies_done(self):
        return all(map(lambda d: d.is_done(), self._dependencies))

    def _dependencies_in_state(self, state):
        return sum([ 1 for dep in self._dependencies if dep.get_state() == state ])

    def is_done(self):
        """ State will not change, don't schedule me again. """
        with self._state_lock:
            return self._state in ('FINISHED', 'NR', 'FAILED')

    def is_ready(self):
        """ Ready to be scheduled. """
        with self._state_lock:
            return self._state == 'PENDING' and self._all_dependencies_done()

    def get_state(self):
        with self._state_lock:
            return self._state

    def set_state(self, state):
        DEFAULT_LOGGER.debug('Setting state of %s from %s to %s', self, self._state, state)
        assert state in ('FINISHED', 'NR', 'FAILED', 'PENDING', 'RUNNING'), 'Tried to set an invalid state "%s"' % state
        with self._state_lock:
            self._state = state
            ImagingStepTask.event.set()

    def _run(self):
        """
        This function defines the running policy.
        
        Each task will be scheduled when all its dependencies states are known.
        A state is known when its state is not in ("PENDING" or "RUNNING").
        
        The default behavior is
          all("FINISHED") ->  invoke self.run()
          any("FAILED" or "NR") -> mark as NR and skip
        
        Override this to customize running policies, such as run regardless of
        dependencies states.
        """
        session_manager.set_session_id(self.config._session_id)
        logger = self.config.get_logger()
        if self.get_state() != 'PENDING':
            logger.error('%s is done(%s), should not be scheduled again', self, self.get_state())
            assert False, 'Task %s is scheduled in unexpected state(%s)' % (
             self, self.get_state())
        else:
            if self._dependencies_in_state('FINISHED') == len(self._dependencies):
                try:
                    self.set_state('RUNNING')
                    logger.info('Running %s', self)
                    self.run()
                    self.set_state('FINISHED')
                    logger.info('Completed %s', self)
                except Exception as e:
                    logger.exception('Exception in running %s', self)
                    self.set_state('FAILED')
                    self._exception = e
                    self.config._exceptions.append(e)
                    try:
                        self.on_failed(e)
                    except:
                        pass

            else:
                if self._dependencies_in_state('FAILED') or self._dependencies_in_state('NR'):
                    self.set_state('NR')
                    message = 'Skipping %s because dependencies not met' % self
                    failed_deps = [ dep for dep in self._dependencies if dep.get_state() == 'FAILED'
                                  ]
                    if failed_deps:
                        message += ', failed tasks: %s' % failed_deps
                    logger.warn(message)
                else:
                    assert False, 'Task %s is scheduled with unexpected dependenciesstates %s' % (
                     self,
                     map(lambda dep: dep.get_state(), self._dependencies))

    def get_progress(self):
        """
        User friendly status/progress reporter
        
        Returns:
          (status_str, progress as percentage, estimated total time)
        
          eg. "Installing Hypervisor", 12.0, 600
        """
        timing = self.get_progress_timing()
        assert timing, 'get_progress_timing should not be empty'
        total_time = sum(map(lambda x: x[1], timing))
        assert total_time, 'total time cannot be zero'
        state = self.get_state()
        if state == 'PENDING':
            return ('Pending', 0, total_time)
        if state == 'NR':
            return ('Not Run', 0, total_time)
        if state == 'FINISHED':
            return (self.get_finished_message(), 100.0, total_time)
        if state in ('RUNNING', 'FAILED'):
            used_time = 0.0
            for status, t in timing:
                if status == self._status_str or not self._status_str:
                    break
                used_time += t

            percent = used_time * 100.0 / total_time
            status_str = self._status_str if self._status_str else 'Running'
            if state == ['FAILED']:
                status_str = 'Fatal at %s' % status_str
            return (status_str, percent, total_time)
        assert False, 'get_progress called with unexpected state(%s)' % state

    def _is_backward(self, status_str):
        """ Check if status_str is before current status """
        status_list = map(lambda x: x[0], self.get_progress_timing())
        curr_status = self._status_str
        curr_status_index = status_list.index(curr_status) if curr_status else -1
        next_status_index = status_list.index(status_str)
        return next_status_index < curr_status_index

    def set_status(self, status_str):
        assert status_str in map(lambda x: x[0], self.get_progress_timing()), '%s is not a valid status' % status_str
        if self._is_backward(status_str):
            logger = self.config.get_logger()
            logger.warn('Task %s is trying to set a backward status (%s), ignoring', self, status_str)
            return
        self._status_str = status_str

    def run(self):
        raise NotImplementedError

    def on_failed(self, exception):
        """
        Override this function to handle failures.
        
        Returns: (The retry logic is Not Implemented yet)
          True  scheduler will invoke .run()
          False scheduler will mark this task as failure
        """
        return False

    def get_progress_timing(self):
        """
        Override this function to provide more user friendly status messages.
        
        Returns:
          list of status and how much time will spend in that status in minutes.
        
          eg. [("Untaring", 5),
               ("Booting", 1)]
        
        """
        return [
         (
          'Running task %s' % self.__class__.__name__, 1)]

    def get_finished_message(self):
        """
        Override this function to provide more user friendly status messages to
        show after current imaging task is done.
        """
        return 'Finished task %s' % self.__class__.__name__

    @classmethod
    def is_compatible_config(cls, config):
        """
        Check this config is compatible with current task.
        
        Returns:
          True: compatible and this task will be inited with Task(config)
          False: incompatible, and this task will be not inited
        
        Raises:
          StandardError: serious error to prevent the imaging to be started.
          (Maybe we can move some validation to this function to reduce the LOC of
           the huge validation function).
        """
        return isinstance(config, cls.config_type) and cls.is_compatible(config)

    @classmethod
    def is_compatible(cls, config):
        """
        Override this function to provide custom skipping logic.
        
        This function will be invoked from is_compatible_config, ImagingStepXXXTask
        should/must override to skip initing on incompatible config.
        """
        return True


class ImagingStepNodeTask(ImagingStepTask):
    """
    ImagingStepNodeTask will only depend on its own previous task.
    """
    config_type = config_manager.NodeConfig

    def __init__(self, *args, **kwargs):
        super(ImagingStepNodeTask, self).__init__(*args, **kwargs)
        self.logger = self.config.get_logger()

    def set_fatal_event(self, message=None):
        prefix = str(self.config.cvm_ip)
        self.config._events.handle_event(prefix, 'fatal', message)

    def wait_for_event(self, event_name, *args, **kwargs):
        """
        Wait for http callback event.
        
        see full docstr at EventManager.wait_for_event
        
        Parameter:
          event_name: string, the name of event to wait for
        
        Returns:
          event object
        
        Raises:
          EventTimeoutException on timeout
          StandardError on fatal callback
        """
        prefix = str(self.config.node_id)
        events = [event_name, 'fatal']
        ret_event_name, event = self.config._events.wait_for_event(prefix, events, *args, **kwargs)
        if ret_event_name == 'fatal':
            raise StandardError('Received %s in waiting for event %s: %s' % (
             ret_event_name, event_name, event.message))
        return event

    def call_cached(self, function, *args, **kwargs):
        """
        Call a function with cache manager.
        
        If a function is called with same arguments multiple times, the function
        will be executed only once. All subsequent calls will have the cached
        value returned. The cache manager is thread-safe.
        
        Parameter:
          function: the function to be cached
          arg, kwargs: arguments passed to function
        
        Returns:
          same as the function returns
        """
        return self.config._cache.get(function, *args, **kwargs)


class ImagingStepNodeGroupTask(ImagingStepTask):
    """
    ImagingStepNodeGroupTask will depends on all previous tasks in this group.
    """
    config_type = config_manager.NodeGroupConfig


class ImagingStepClusterTask(ImagingStepNodeGroupTask):
    """
    ImagingStepClusterTask will depends on all previous tasks in this cluster.
    """
    config_type = config_manager.ClusterConfig

    def __init__(self, *args, **kwargs):
        super(ImagingStepClusterTask, self).__init__(*args, **kwargs)
        self.logger = self.config.get_logger()


class ImagingStepGlobalTask(ImagingStepTask):
    """
    ImagingStepGlobalTask will depends on all previous tasks.
    """
    config_type = config_manager.GlobalConfig

    def __init__(self, *args, **kwargs):
        super(ImagingStepGlobalTask, self).__init__(*args, **kwargs)
        self.logger = self.config.get_logger()


class AlwaysRunTaskMixin(object):
    """
    Mixin providing the AlwaysRun policy, which will always be scheduled when
    it's dependencies in state NR, FAILED or FINISHED.
    """

    def is_dependency_failed(self):
        """
        Determine if some dependency was failed.
        """
        return self._dependencies_in_state('NR') or self._dependencies_in_state('FAILED')

    def _run(self):
        """
        This function defines the running policy.
        
        The "always run" behavior is
          Before execution:
            * -> invoke self.run()
          After execution:
            any("FAILED" or "NR") -> mark as "FAILED"
        """
        session_manager.set_session_id(self.config._session_id)
        logger = self.config.get_logger()
        is_failed = self.is_dependency_failed()
        if self.get_state() != 'PENDING':
            logger.error('%s is done(%s), should not be scheduled again', self, self.get_state())
            assert False, 'Task %s is scheduled in unexpected state(%s)' % (
             self, self.get_state())
        else:
            self.set_state('RUNNING')
            try:
                DEFAULT_LOGGER.info('Running %s', self)
                self.run()
                if is_failed:
                    logger.warn('Task finished successfully, inherenting failure from dependencies')
                    raise StandardError('Some dependency was failed')
                self.set_state('FINISHED')
                DEFAULT_LOGGER.info('Completed %s', self)
            except Exception as e:
                logger.exception('Exception in running %s', self)
                self.set_state('FAILED')
                self._exception = e
                self.config._exceptions.append(e)
                try:
                    self.on_failed(e)
                except:
                    pass


class ImagingStepClusterAlwaysRunTask(AlwaysRunTaskMixin, ImagingStepClusterTask):
    """
    This is a subclass of ImagingStepClusterTask.
    
    This step will always run and ignore the status of all previous tasks
    in this cluster, and set itself to FAILED if any dependency task failed.
    """
    _dont_abort_me_on_fail_please = True
    config_type = config_manager.ClusterConfig


class ImagingStepGlobalAlwaysRunTask(AlwaysRunTaskMixin, ImagingStepGlobalTask):
    """
    The AlwaysRun variation of ImagingStepGlobalTask
    
    This task type works well for a barrier to synchronize between multiple
    nodes or clusters.
    """
    pass


class ImagingStepGlobalNoAbortTask(ImagingStepGlobalAlwaysRunTask):
    """
    The AlwaysRun + no_abort variation of ImagingStepGlobalTask
    
    ImagingStepGlobalAlwaysRunNoAbortTask is too Java
    
    Note:
    This is mainly for factory integration, which requires foundation to
    execute certain task once per imaging session. Since foundation is treating
    each node as a single cluster, the ImagingStepClusterAlwaysRunTask doesn't
    work well anymore.
    """
    _dont_abort_me_on_fail_please = True


class ExtraDepsMixin(object):
    """
    This is a Mixin for steps requires custom dependency
    
    Override the extra_dep_config_filter to depend on other nodes.
    """

    def extra_dep_config_filter(self, config):
        return False

    def _dependency_configs(self):
        gc = self.config.get_root()
        ext_configs = set(filter(self.extra_dep_config_filter, gc.nodes))
        return super(ExtraDepsMixin, self)._dependency_configs() | ext_configs


def cleanup(node_configs):
    """
    Cleanup called before and possibly after imaging. This intentionally breaks
    OO boundaries because this cleanup routine cleans up after ALL imaging
    steps. Putting this code in the individual derived classes would be
    largely redundant and also suffers from the issue that the derived classes
    are only instantiated when the imaging step is selected. In other words,
    cruft from an imaging step of a previous run may well continue to sit
    on the disk without this routine if the step doesn't get selected again.
    """
    foundation_tools.system(node_configs[0], ['sudo',
     '/etc/init.d/nfs', 'stop'], throw_on_error=False)
    temp_files = glob.glob(folder_central.get_tmp_folder() + '/*')
    foundation_tools.system(node_configs[0], ['rm', '-rf'] + temp_files, throw_on_error=False, log_on_error=False)
    foundation_tools.system(node_configs[0], ['sudo',
     '/etc/init.d/nfs', 'start'], throw_on_error=False)