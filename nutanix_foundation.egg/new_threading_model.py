# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/new_threading_model.py
# Compiled at: 2019-02-15 12:42:10
import collections, json, logging, threading, time, session_manager
from foundation.consts import Action
from foundation.imaging_step import ImagingStepNodeTask, ImagingStepClusterTask, ImagingStepTask, ImagingStepGlobalTask
logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)

def debug(mode=True):
    logger.setLevel(logging.DEBUG)


TASK_TYPES = [
 ImagingStepNodeTask,
 ImagingStepClusterTask,
 ImagingStepGlobalTask]

def is_compatible(imaging_task_class, config):
    """
    Check if all configs are compatible with the config_type required by
    imaging_task_class.
    """
    return imaging_task_class.is_compatible_config(config)


def has_dep(task1, task2):
    return task1._dependency_configs().intersection(task2._dependency_configs())


def generate_deps(task, graph):
    """
    Compute dependencies for task, from graph
    
    The dependency is defined as following
     - assume we have a task list of [Task1, Task2]
       let ngc1 = NodeGroupConfig(node_set1), task1 = Task1(ngc1)
       let ngc2 = NodeGroupConfig(node_set2), task2 = Task1(ngc2)
       then task2 depends on task1 if
         intersection(node_set1, node_set2) != []
    """
    assert isinstance(task, ImagingStepTask), 'task must be an instance of ImagingStepTask, was: %s' % task
    dep_tasks = set()
    for prev_task in graph:
        assert isinstance(prev_task, ImagingStepTask), 'item should be an object of %s but was %s' % (ImagingStepTask,
         prev_task)
        if has_dep(task, prev_task):
            for cur_dep in list(dep_tasks):
                cur_dep_deps = set(cur_dep._iall_deps())
                prev_task_deps = set(prev_task._iall_deps())
                if cur_dep_deps.issuperset(prev_task_deps):
                    break
                elif prev_task_deps.issuperset(cur_dep_deps):
                    dep_tasks.remove(cur_dep)
            else:
                dep_tasks.add(prev_task)

    logger.debug('found %s/%s dependencies for task %s, and they are \n  ==> %s', len(dep_tasks), len(graph), task, dep_tasks)
    return dep_tasks


def is_task_class(task_class):
    return any(map(lambda base_class: issubclass(task_class, base_class), TASK_TYPES))


def generate_graph(global_config, imaging_task_class, prev_graph=None):
    """
    Generate a dependency graph from
     - global_config
     - global_config.nodes
     - global_config.clusters
     - imaging_task_class
    """
    if prev_graph is None:
        prev_graph = []
    logger.debug('Creating graph nodes for %s and %s', global_config, imaging_task_class)
    if isinstance(imaging_task_class, (list, tuple)):
        logger.debug('Sequential dependency: %s', imaging_task_class)
        seq_new_tasks = []
        for task_class in imaging_task_class:
            new_tasks = generate_graph(global_config, task_class, prev_graph + seq_new_tasks)
            seq_new_tasks.extend(new_tasks)

        return seq_new_tasks
    if isinstance(imaging_task_class, (set, frozenset)):
        logger.debug('Parallel dependency: %s', imaging_task_class)
        para_new_tasks = []
        for task_class in imaging_task_class:
            new_tasks = generate_graph(global_config, task_class, prev_graph)
            para_new_tasks.extend(new_tasks)

        return para_new_tasks
    if type(imaging_task_class) is type and is_task_class(imaging_task_class):
        logger.debug('Create task objects: %s', imaging_task_class)
        all_configs = [
         global_config] + global_config.nodes + global_config.clusters
        valid_configs = filter(lambda config: is_compatible(imaging_task_class, config), all_configs)
        tasks = map(lambda config: imaging_task_class(config), valid_configs)
        map(lambda task: task.set_dependencies(generate_deps(task, prev_graph)), tasks)
        return list(tasks)
    assert False, 'unsupported input %s, %s, %s' % (
     global_config, imaging_task_class, prev_graph)
    return


def flat_tasks(graph):
    """
    the graph is flat now, so noop here
    """
    return graph


def dictfy_tasks(graph):
    """
    Transform a graph to a mapping of [node][TaskClass] => task object
    
    Parameter:
      graph: a dependency graph
    
    Returns:
      a dict in the format of {node_config: {Task: Task(node_config)}}
    """
    result = collections.defaultdict(dict)
    for item in flat_tasks(graph):
        if isinstance(item, ImagingStepNodeTask):
            result[item.config][type(item)] = item
        elif isinstance(item, ImagingStepClusterTask):
            for node in getattr(item.config, 'cluster_members', []):
                result[node][type(item)] = item

        elif isinstance(item, ImagingStepGlobalTask):
            for node in getattr(item.config, 'nodes', []):
                result[node][type(item)] = item

        else:
            raise NotImplementedError('Unknown type %s' % type(item))

    return result


def abort_execution(global_config, reason):
    """
    Abort the execution of a global_config
    """
    global_config.abort_session = True
    for node in global_config.nodes:
        global_config._events.handle_event(node.cvm_ip, 'fatal', reason)


def serial_executor(dependency_graph):
    """
    Execute tasks in a dependency graph one by one.
    """
    while not all(map(lambda t: t.is_done(), flat_tasks(dependency_graph))):
        batch = []
        for task in flat_tasks(dependency_graph):
            if task.is_ready():
                batch.append(task)
                break

        logger.debug('Running task in batch %s', batch)
        batch_threads = map(lambda t: threading.Thread(target=t._run), batch)
        map(lambda thrd: thrd.start(), batch_threads)
        map(lambda thrd: thrd.join(), batch_threads)


def parallel_executor(dependency_graph, global_config):
    """
    Execute tasks in a dependency graph by parallel topological sorting.
    
    On global_config.abort_session = True, this executor will:
      - stop scheduling new threads/tasks
      - set all tasks in PENDING state NR
    """
    threads = []
    sched_tasks = set()
    while not all(map(lambda t: t.is_done(), flat_tasks(dependency_graph))):
        batch = []
        batch_threads = []
        is_abort_set = getattr(global_config, 'abort_session', False)
        action_on_fail = getattr(global_config, 'action_on_fail', None)
        for task in flat_tasks(dependency_graph):
            if is_abort_set and task.get_state() == 'PENDING' and not getattr(task, '_dont_abort_me_on_fail_please', None):
                logger.warn('Aborting execution: %s', task)
                task.set_state('NR')
                continue
            if action_on_fail == 'abort' and task.get_state() == 'FAILED':
                logger.warn('Abort execution')
                abort_execution(global_config, 'Aborted due to task failure')
            if task.is_ready() and task not in sched_tasks:
                batch.append(task)
                sched_tasks.add(task)

        if batch:
            logger.info('Scheduling tasks in parallel %s', batch)
            batch_threads = map(lambda t: threading.Thread(target=t._run), batch)
            map(lambda thrd: thrd.setDaemon(True), batch_threads)
            map(lambda thrd: thrd.start(), batch_threads)
            threads.extend(batch_threads)
        ImagingStepTask.event.wait()
        ImagingStepTask.event.clear()

    map(lambda thrd: thrd.join(), threads)
    return


def task_to_name(task):
    if isinstance(task, ImagingStepNodeTask):
        return '%s_%s' % (task.__class__.__name__, task.config.cvm_ip)
    if isinstance(task, ImagingStepClusterTask):
        return '%s_%s' % (task.__class__.__name__, len(task.config))
    raise NotImplementedError


def save_graph_states(result, fn):
    state_json = {}
    for task in set(flat_tasks(result)):
        task_name = task_to_name(task)
        state_json[task_name] = task.get_state()

    json.dump(state_json, open(fn, 'w'), sort_keys=False, indent=2)


def load_graph_states(result, fn, retry=False):
    """
    Load state from json,
    change NR/FAILED to PENDING if retry==True.
    """
    state_json = json.load(open(fn, 'r'))
    for task in set(flat_tasks(result)):
        task_name = task_to_name(task)
        task.set_state(state_json[task_name])


def is_running(session_id=None):
    gc = session_manager.get_global_config(session_id=session_id)
    graph = getattr(gc, 'graph', None)
    if not graph:
        return False
    for task in flat_tasks(graph):
        if not task.is_done():
            return True

    return False


def get_ndone_nerror(global_config):
    n_done, n_error = (0, 0)
    graph = getattr(global_config, 'graph', None)
    if not graph:
        return (n_done, n_error)
    flat_graph = list(flat_tasks(graph))
    for node in global_config.nodes:
        node_tasks = list(filter(lambda t: t.config == node, flat_graph))
        for task in node_tasks:
            logger.debug('done and error> %s: %s', task, task.get_state())

        if all(map(lambda t: t.get_state() == 'FINISHED', node_tasks)):
            n_done += 1
        elif any(map(lambda t: t.get_state() in ('FAILED', 'NR'), node_tasks)):
            n_error += 1

    return (n_done, n_error)


def get_task_progress_in_state(tasks, states=None):
    """ Filter tasks by states """
    states = states or []
    return map(lambda t: (
     t, t.get_progress()), filter(lambda t: t.get_state() in states, tasks))


def get_status_from_tasks(config, tasks):
    """
    Compute the status message and progress of a config object from tasks.
    
    Returns:
      a dict of
        {
          "status": "Some status, another status",
          "messages": ["something went wrong", "again?"],
          "percent_complete": 12.00,
          "time_total": 100,                       # in minutes
          "time_elapsed": 12,                      # in minutes
        }
    """
    progress = 0
    time_elapsed = 0
    time_total = 0.1
    status = 'Idle'
    if tasks:
        tp_all = map(lambda t: (t, t.get_progress()), tasks)
        tp_done = get_task_progress_in_state(tasks, ['RUNNING', 'FINISHED', 'NR', 'FAILED'])
        tp_current = get_task_progress_in_state(tasks, ['RUNNING', 'FAILED'])
        tp_finished = get_task_progress_in_state(tasks, ['FINISHED'])
        if tp_current:
            status = (', ').join(sorted(map(lambda (t, p): '%s' % p[0], tp_current)))
            node_fatal = any(filter(lambda t: t.get_state() in ('FAILED', ), tasks))
            if node_fatal:
                status = 'fatal: ' + status
        else:
            if len(tp_all) == len(tp_finished):
                status = 'All operations completed successfully'
            else:
                if len(tp_finished) == 0:
                    status = 'Idle'
                else:
                    if len(tp_finished):
                        last_task_progress = tp_finished[-1]
                        last_task = last_task_progress[0]
                        status = last_task.get_finished_message()
                    else:
                        status = 'Unknown'
        time_total = sum(map(lambda (t, p): p[2], tp_all))
        time_elapsed = sum(map(lambda (t, p): p[1] / 100 * p[2], tp_done))
        progress = 100.0 * time_elapsed / time_total
        progress = round(progress * 100) / 100
        if status == 'Idle':
            if tp_done:
                status = tp_done[-1][1][0]
    else:
        progress = 100
        status = 'All operations completed successfully'
    if getattr(config, 'abort_session', False):
        if getattr(config, 'imaging_stopped', True):
            status = 'Aborted: ' + status
        else:
            status = 'Aborting: ' + status
    messages = []
    for exception in getattr(config, '_exceptions', []):
        messages.append(str(exception))

    result = dict(status=status, messages=messages, percent_complete=progress, time_elapsed=time_elapsed, time_total=time_total)
    return result


def get_progress(session_id=None):
    """
    Calculate the progress of current running imaging session.
    
    Returns:
      see foundation API doc "/foundation/progress"
    """
    gc = session_manager.get_global_config(session_id=session_id)
    graph = getattr(gc, 'graph', None)
    result = {}
    result['session_id'] = getattr(gc, '_session_id', None)
    result['imaging_stopped'] = not is_running(session_id=session_id)
    result['action'] = getattr(gc, 'action', '')
    result['aggregate_percent_complete'] = 0
    result['nodes'] = []
    result['clusters'] = []
    result['results'] = getattr(gc, 'results', None)
    result['abort_session'] = getattr(gc, 'abort_session', False)
    if not graph:
        return result
    node_task_map = collections.defaultdict(list)
    cluster_task_map = collections.defaultdict(list)
    flat_graph = list(flat_tasks(graph))
    for task in flat_graph:
        if isinstance(task, ImagingStepNodeTask):
            node_task_map[task.config].append(task)
        elif isinstance(task, ImagingStepClusterTask):
            cluster_task_map[task.config].append(task)
        elif isinstance(task, ImagingStepGlobalTask):
            pass
        else:
            raise StandardError('Unknown task type %s', task)

    time_elapsed = 0
    time_total = 0
    for node_config, tasks in node_task_map.items():
        status_dict = get_status_from_tasks(node_config, tasks)
        time_elapsed += status_dict['time_elapsed']
        time_total += status_dict['time_total']
        if hasattr(node_config, 'hypervisor_ip'):
            status_dict['hypervisor_ip'] = node_config.hypervisor_ip
        if hasattr(node_config, 'cvm_ip'):
            status_dict['cvm_ip'] = node_config.cvm_ip
        if node_config.action == Action.BOOT_PHOENIX:
            status_dict['phoenix_ip'] = node_config.phoenix_ip
        result['nodes'].append(status_dict)

    for cluster_config, tasks in cluster_task_map.items():
        status_dict = get_status_from_tasks(cluster_config, tasks)
        time_elapsed += status_dict['time_elapsed']
        time_total += status_dict['time_total']
        cluster_name = cluster_config.cluster_name
        if getattr(cluster_config, 'cluster_name_unicode', None):
            cluster_name = cluster_config.cluster_name_unicode
        status_dict['cluster_members'] = map(lambda config: config.cvm_ip, cluster_config.cluster_members)
        status_dict['cluster_name'] = cluster_name
        result['clusters'].append(status_dict)

    if time_total:
        aggregate_percent = time_elapsed * 100 / time_total
        aggregate_percent = round(aggregate_percent * 100) / 100
    else:
        aggregate_percent = -1
    result['aggregate_percent_complete'] = aggregate_percent
    return result


def generate_states_reached():
    """
    Dump backward compatible states_reached.json file.
    """
    gc = session_manager.get_global_config()
    graph = getattr(gc, 'graph', None)
    state_dict = {'nodes': {}, 'clusters': {}}
    if graph:
        flat_graph = list(flat_tasks(graph))
        for task in flat_graph:
            key = None
            if isinstance(task, ImagingStepNodeTask):
                key = 'nodes'
            else:
                if isinstance(task, ImagingStepClusterTask):
                    key = 'clusters'
                else:
                    if isinstance(task, ImagingStepGlobalTask):
                        continue
                    else:
                        raise StandardError('Unknown task type %s', task)
            config_name = repr(task.config)
            state_name = repr(task)
            if task.get_state() == 'FINISHED':
                state_pass = 'passed' if 1 else task.get_state()
                if config_name not in state_dict[key]:
                    state_dict[key][config_name] = []
                state_dict[key][config_name].append((state_name, state_pass))

    return state_dict


def dump_states_reached_json(states_reached_path):
    """
    Dump backward compatible states_reached.json file.
    """
    state_dict = generate_states_reached()
    with open(states_reached_path, 'w') as (fp):
        json.dump(state_dict, fp, indent=2)


state2color = {'PENDING': 'white', 
   'READY': 'yellow', 
   'RUNNING': 'green', 
   'FINISHED': 'gold', 
   'FAILED': 'red', 
   'NR': 'grey'}

def plot(result, prefix='output', index=0, label=''):
    try:
        import pydot
    except ImportError:
        print 'No pydot, skip'
        return

    node_graph = {}
    graph = pydot.Dot(graph_type='digraph', label=label)

    def get_node(task):
        if task not in node_graph:
            node_graph[task] = pydot.Node(str(task), style='filled', fillcolor=state2color[task._state])
            graph.add_node(node_graph[task])
        return node_graph[task]

    for task in flat_tasks(result):
        node_a = get_node(task)
        for dep in task._depends:
            node_b = get_node(dep)
            graph.add_edge(pydot.Edge(node_b, node_a))

    graph.write_png('%s-%04d.png' % (prefix, index))


def execute_and_plot(worker, result, prefix='output', _plot=True):
    logger.info('execute_and_plot started')
    worker_thrd = threading.Thread(target=worker, args=(result,))
    plot_index = 0
    if _plot:
        plot(result, prefix=prefix, index=plot_index, label='%s % 5.1fs' % (prefix, plot_index * 0.1))
    worker_thrd.start()
    while worker_thrd.is_alive():
        plot_index += 1
        if _plot:
            plot(result, prefix=prefix, index=plot_index, label='%s % 5.1fs' % (prefix, plot_index * 0.1))
        time.sleep(0.1)

    plot_index += 1
    if _plot:
        plot(result, prefix=prefix, index=plot_index, label='%s % 5.1fs' % (prefix, plot_index * 0.1))
    logger.info('execute_and_plot Done')