# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/config_manager.py
# Compiled at: 2019-02-15 12:42:10
import collections, itertools, logging, threading, time

class BaseConfig(object):
    """
    Base class for config management.
    """
    _parent = None
    _children = []
    _config = {}

    def __init__(self, *args, **kwargs):
        self._config = {}
        self._parent = kwargs.pop('parent', None)
        self._children = kwargs.pop('children', [])
        self._exceptions = []
        if self._parent:
            self._parent._join(self)
        self.tasks = []
        return

    def __getattr__(self, key):
        for obj in self.__class__.mro():
            if key in obj.__dict__:
                attr = obj.__dict__[key]
                if isinstance(attr, property):
                    return attr.fget(self)

        if key in self._config:
            return self._config[key]
        try:
            return getattr(self._parent, key)
        except AttributeError:
            raise AttributeError('%r object has no attribute %r' % (
             self.__class__.__name__, key))

    def __setattr__(self, key, value):
        if key in dir(self):
            super(BaseConfig, self).__setattr__(key, value)
        else:
            self._config[key] = value

    def _join(self, node):
        self._children.append(node)

    def keys(self):
        keys = self._config.keys()
        if self._parent:
            keys.extend(self._parent.keys())
        return list(set(keys))

    def get_root(self):
        if self._parent:
            return self._parent.get_root()
        return self

    def set_parent(self, parent):
        assert not self._parent, 'Parent already set'
        self._parent = parent
        if self._parent:
            self._parent._join(self)

    def set_status_via_callback(self, status_str):
        for task in self.tasks:
            if task.get_state() == 'RUNNING' and status_str in map(lambda x: x[0], task.get_progress_timing()):
                task.set_status(status_str)

    def append_message(self, msg):
        """
        Append a string message to the _exceptions list which will be part of the
        progress API and report to end user.
        
        Note: all raised exceptions are already add to this list by ntm.
        """
        self._exceptions.append(StandardError(msg))


class NodeGroupConfig(BaseConfig):

    @property
    def _items_iter(self):
        return itertools.chain(self._children, *map(lambda child: child._items_iter, self._children))

    @property
    def _items(self):
        return list(self._items_iter)

    @property
    def _is_leaf(self):
        return len(self._children) == 0

    @property
    def phoenix_netmask(self):
        netmask = getattr(self, '_phoenix_netmask', None) or getattr(self, 'cvm_netmask', None) or getattr(self, 'hypervisor_netmask', None)
        assert netmask, 'Unable to find a phoenix netmask'
        return netmask

    @phoenix_netmask.setter
    def phoenix_netmask(self, netmask):
        self._phoenix_netmask = netmask

    @property
    def phoenix_gateway(self):
        gateway = getattr(self, '_phoenix_gateway', '') or getattr(self, 'cvm_gateway', '') or getattr(self, 'hypervisor_gateway', '')
        return gateway

    @phoenix_gateway.setter
    def phoenix_gateway(self, gateway):
        self._phoenix_gateway = gateway


class GlobalConfig(NodeGroupConfig):
    """
    GlobalConfig is the root of a config tree
    
    It doesn't have any _parent, and provides a global cache and event manager
    for the entire tree.
    """
    _cache = None

    def __init__(self, *args, **kwargs):
        super(GlobalConfig, self).__init__(*args, **kwargs)
        self._parent = None
        self._cache = CacheManager()
        self._events = EventManager()
        return

    def get_logger(self):
        if hasattr(self, '_session_id'):
            logger_name = 'foundation.session.%s.global' % self._session_id
        else:
            logger_name = 'foundation.node_log.global'
        return logging.getLogger(logger_name)

    @property
    def clusters(self):
        return filter(lambda item: isinstance(item, ClusterConfig), self._items)

    @property
    def nodes(self):
        return filter(lambda item: isinstance(item, NodeConfig), self._items)


class NodeConfig(NodeGroupConfig):
    """
    NodeConfig is a special type of NodeGroupConfig which doesn't have any
    children and it represents the node itself.
    """

    def __repr__(self):
        return '<%s(%s) @%s>' % (self.__class__.__name__,
         self.node_id, hex(id(self))[-4:])

    def get_logger(self):
        node_name = self.node_id
        if hasattr(self, '_session_id'):
            logger_name = 'foundation.session.%s.node_%s' % (
             self._session_id, node_name)
        else:
            logger_name = 'foundation.node_log.node_%s' % node_name
        return logging.getLogger(logger_name)

    def _join(self, node):
        assert False, '%s cannot have any child member' % self

    @property
    def nodes(self):
        return []

    @property
    def phoenix_ip(self):
        ip = getattr(self, '_phoenix_ip', None) or getattr(self, 'cvm_ip', None) or getattr(self, 'hypervisor_ip', None)
        assert ip, 'Unable to find a phoenix ip'
        return ip

    @phoenix_ip.setter
    def phoenix_ip(self, ip):
        self._phoenix_ip = ip

    @property
    def node_id(self):
        try:
            return self.phoenix_ip
        except AssertionError:
            return 'default_node'


class ClusterConfig(NodeGroupConfig):

    def __repr__(self):
        return '<%s(%s) @%s>' % (self.__class__.__name__,
         getattr(self, 'cluster_name', '?'), hex(id(self))[-4:])

    def get_logger(self):
        cluster_name = getattr(self, 'cluster_name', 'default_cluster')
        if hasattr(self, '_session_id'):
            logger_name = 'foundation.session.%s.cluster_%s' % (
             self._session_id, cluster_name)
        else:
            logger_name = 'foundation.cluster_log.cluster_%s' % cluster_name
        return logging.getLogger(logger_name)

    @property
    def cluster_members(self):
        return self._children

    @property
    def nodes(self):
        return self._children

    @property
    def phoenix_netmask(self):
        raise AssertionError('Invalid property for cluster')

    @property
    def phoenix_gateway(self):
        raise AssertionError('Invalid property for cluster')

    def _join(self, node):
        assert isinstance(node, NodeConfig), '%s can only take %s as child, but given %s' % (
         self, NodeConfig, node)
        super(ClusterConfig, self)._join(node)


class CacheManager(object):
    _lock = threading.RLock()
    _cache = dict()
    _cache_lock = collections.defaultdict(threading.RLock)
    _cache_hash_template = '%s_%s_%s'

    @staticmethod
    def _arg_filter(args, kwargs, _filter):
        """
        Filter args by index, kwargs by name in _filter
        """
        filtered_args = tuple([ arg for index, arg in enumerate(args) if index not in _filter ])
        filtered_kwargs = dict([ (key, value) for key, value in sorted(kwargs.items()) if key not in _filter
                               ])
        return (
         filtered_args, filtered_kwargs)

    @staticmethod
    def reset():
        """
        Clear all cache entries.
        """
        with CacheManager._lock:
            CacheManager._cache = dict()
            CacheManager._cache_lock = collections.defaultdict(threading.RLock)

    @staticmethod
    def get_cache_hash_for_function_call(function, *args, **kwargs):
        """
        Returns the cache hash corresponding to a function call.
        """
        ignored_args = kwargs.pop('ignored_args', [])
        filtered_args, filtered_kwargs = CacheManager._arg_filter(args, kwargs, ignored_args)
        cache_hash = CacheManager._cache_hash_template % (
         function, filtered_args, filtered_kwargs)
        return cache_hash

    @staticmethod
    def remove_cache_entry(cache_hash):
        """
        Removes a cache entry from CacheManager's cache dictionary.
        Args:
          cache_hash: Hash key for a cache entry.
        
        Returns:
          None
        """
        logger = logging.getLogger('CacheManager')
        with CacheManager._lock:
            cache_lock = CacheManager._cache_lock[cache_hash]
        with cache_lock:
            if cache_hash in CacheManager._cache:
                del CacheManager._cache[cache_hash]
                logger.debug('Removed cache hash: %s' % cache_hash)
            else:
                logger.debug('Cache hash (%s) not found in CacheManager' % cache_hash)

    @staticmethod
    def get(function, *args, **kwargs):
        """
        Get a cached result of a function call.
        
        Args:
          function: the function to be invoked
          args, kwargs: the args to be passed to function
        
        Returns:
          whatever the function(args, kwargs) returns
        
        Optional args:
          ignored_args: arguments that should not be used in hash key
        
        Limitation:
          Current implementation doesn't allow passing "ignored_args" as a keyword
          argument to the cached function.
        
        The result will be cached, if a function is called with same parameters,
        the cached result will be returned with invoke the function again.
        """
        ignored_args = kwargs.pop('ignored_args', [])
        logger = logging.getLogger('CacheManager')
        filtered_args, filtered_kwargs = CacheManager._arg_filter(args, kwargs, ignored_args)
        cache_hash = CacheManager._cache_hash_template % (
         function, filtered_args, filtered_kwargs)
        cache_lock = None
        with CacheManager._lock:
            cache_lock = CacheManager._cache_lock[cache_hash]
        with cache_lock:
            if cache_hash not in CacheManager._cache:
                logger.debug('Cache MISS: key(%s)', cache_hash)
                try:
                    result = function(*args, **kwargs)
                    CacheManager._cache[cache_hash] = result
                except:
                    logger.exception('Exception in running %s(%s, %s)', function, args, kwargs)
                    raise

            else:
                logger.debug('Cache HIT: key(%s)', cache_hash)
            return CacheManager._cache[cache_hash]
        return

    @staticmethod
    def cached(ignored_args=None):
        """
        Decorator to make a function cacheable.
        
        Args:
          ignored_args: arguments that should be ignored in computing hash key
                        this argument will not be passed to the wrapped function.
        
        eg.
          @CacheManager.cached(["config"])
          def system(config, cmds):
            ...
        """
        ignored_args = ignored_args or []

        def wrap(func):

            def wrapped_func(*args, **kwargs):
                if 'ignored_args' not in kwargs:
                    kwargs['ignored_args'] = ignored_args
                return CacheManager.get(func, *args, **kwargs)

            return wrapped_func

        return wrap


class EventTimeoutException(StandardError):
    pass


class EventWithMessage(threading._Event):
    """
    EventWithMessage, Event with an optional message.
    """

    def __init__(self, *args, **kwargs):
        super(EventWithMessage, self).__init__(*args, **kwargs)
        self.message = None
        self.created = time.time()
        self.updated = None
        return

    def set(self, message=None):
        self.message = message
        self.updated = time.time()
        return super(EventWithMessage, self).set()

    def get_message(self):
        return self.message


class EventManager(object):

    def __init__(self):
        self._lock = threading.RLock()
        self._event_dict = collections.defaultdict(EventWithMessage)

    @staticmethod
    def key_for_event(prefix, event_name):
        return '%s|%s' % (prefix, event_name)

    def get(self, prefix, event_name):
        key = EventManager.key_for_event(prefix, event_name)
        with self._lock:
            return self._event_dict[key]

    def handle_event(self, prefix, event_name, message=''):
        self.get(prefix, event_name).set(message)

    def wait_for_event(self, prefix, event_names, timeout=None, poll_interval=1.0, hb_timeout=None, hb_callback=None):
        """
        Wait for http callback event.
        
        Parameter:
          event_name: a list of event strings
                           or a single event string
          timeout: timeout in waiting for events if specified
                   None: wait forever
          poll_interval: the poll interval, set a larger value if your
                         have too many events to wait
        
          hb_timeout: timeout for each heartbeat
                      None: disable heartbeat wait
                      eg. some long running program will callback every 5 seconds,
                          then this value should be 10
          hb_callback: callback function will be called once this function entered
                       the "waiting for beartbeat" state
                       eg. hb_callback=lambda event: log.info("waiting for HB")
        
        How heartbeat works
          This function will wait for any event in event_names to be set in the
          limited time defined by `timeout`. When the deadline is reached, and
          `hb_timeout` is not None, this function will continue waiting for the
          "info" event, which is usually from the remote log.
          And optional `hb_callback` function can be provided, and it will be
          invoked on the first heartbeat.
        
        Returns:
          a tuple of event_name and event object
        
        Raises:
          EventTimeoutException
        """
        start = time.time()
        is_hb_callback_invoked = False
        deadline = None if timeout is None else start + timeout
        while 1:
            if deadline is None or time.time() <= deadline:
                for event_name in event_names:
                    event = self.get(prefix, event_name)
                    event.wait(poll_interval / len(event_names))
                    if event.is_set():
                        return (event_name, event)
                    if hb_timeout is not None and deadline is not None:
                        if deadline - time.time() < hb_timeout:
                            hb_event = self.get(prefix, 'info')
                            if hb_event.is_set():
                                if hb_event.updated + hb_timeout > deadline:
                                    deadline = hb_event.updated + hb_timeout
                                    if not is_hb_callback_invoked:
                                        hb_callback(event)
                                        is_hb_callback_invoked = True

        else:
            raise EventTimeoutException('Timeout (%ss) in waiting for events %s' % (timeout, event_names))

        return