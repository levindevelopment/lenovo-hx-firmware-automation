# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/installer.py
# Compiled at: 2019-02-15 12:42:10
import time, pprint, logging, os, threading
from collections import defaultdict
import config_persistence, features, folder_central, foundation_tools, imaging_context, new_threading_model as ntm, simple_logger, session_manager
from config_manager import NodeConfig, ClusterConfig
from consts import Action
from imaging_step_handoff import ImagingStepHandoffPrepare, ImagingStepHandoff
from imaging_step_prepare_nos import GetNosVersion
from imaging_step_prepare_vendor import ImagingStepPrepareVendorFactory
from imaging_step_init import ImagingStepInitFactory
from imaging_step_type_detection import ImagingStepTypeDetection
from imaging_step_pre_install import ImagingStepPreInstall
from imaging_step_phoenix import ImagingStepPhoenix
from imaging_step_hypervisor import InstallHypervisorFactory
from imaging_step_cluster_init import ImagingStepClusterInit
from imaging_step_init_ipmi import ImagingStepInitIPMI
from imaging_step_init_cvm import ImagingStepInitCVM
from imaging_step_misc_hw_checks import ImagingStepMiscHWChecks
from imaging_step_fru_check import ImagingStepFruCheck, ImagingStepFruCheckBarrier
from imaging_step_factory_selcheck import ImagingStepFactorySELCheckPre, ImagingStepFactorySELCheckPost, ImagingStepFactorySELCheckBarrier
from imaging_step_disk_check import ImagingStepDiskCheck
from imaging_step_cluster_destroy import ImagingStepClusterDestroy
from imaging_step_factory_deconfigure import ImagingStepFactoryDeconfigureFactory
from imaging_step_prepare_dell import ImagingStepPrepareDell
from imaging_step_setup_replication import ImagingStepSetupReplication
from imaging_step_xen import ImagingStepXenJoinPool
from imaging_step_validation import ImagingStepValidation
from imaging_step_configuration_update import ImagingStepConfigurationUpdate
from imaging_step_ncc import ImagingStepNcc
from imaging_step_syscheck import ImagingStepSyscheck
from imaging_step_time_check import ImagingStepTimeCheck
from foundation.imaging_step_flex import ImagingStepFlexStart
from foundation.imaging_step_flex import ImagingStepFlexReport
from foundation.imaging_step_factory_bioscfg import ImagingStepBiosCfgUpdate, ImagingStepBiosCfgBarrier, ImagingStepBiosCfgVerify
from foundation.imaging_step_cokeva import ImagingStepCokevaStart, ImagingStepCokevaReport
from foundation.imaging_step_factory_mail import ImagingStepFactoryMail
from foundation.imaging_step_smc import ImagingStepSMCStart, ImagingStepSMCReport
from foundation.imaging_step_compute_only import ImagingStepComputeOnly
from foundation.imaging_step_factory_erase import ImagingStepDiskErase
from foundation import config_validator
from foundation.shared_functions import AUTOMATION_FRAMEWORK_KEY
from network_validation import ValidationStepDisableDupArp, ValidationStepGetBackplaneIPs, ValidationStepGetIp, ValidationStepArpScan, ValidationStepConfigIp, ValidationStepBarrier, ValidationStepPingAll, validate_and_initialize
from imaging_step_update_fc import ImagingStepUpdateFC
PROGRESS_INTERVAL_S = 20
BOOT_PHOENIX_TASKS = [
 ImagingStepTypeDetection,
 frozenset([ImagingStepInitIPMI, ImagingStepInitCVM])]
IMAGING_TASKS_IPMI = [
 ImagingStepValidation,
 GetNosVersion,
 ImagingStepTypeDetection,
 ImagingStepPrepareDell,
 ImagingStepPrepareVendorFactory,
 frozenset([ImagingStepInitIPMI, ImagingStepInitCVM]),
 ImagingStepMiscHWChecks,
 ImagingStepPreInstall,
 frozenset([ImagingStepPhoenix, InstallHypervisorFactory]),
 ImagingStepXenJoinPool,
 ImagingStepConfigurationUpdate,
 ImagingStepClusterInit,
 ImagingStepNcc,
 ImagingStepSyscheck,
 ImagingStepComputeOnly,
 ImagingStepClusterDestroy]
IMAGING_TASKS_CVM = [
 ImagingStepValidation,
 ImagingStepHandoffPrepare,
 GetNosVersion,
 ImagingStepTypeDetection,
 ImagingStepInitFactory,
 ImagingStepMiscHWChecks,
 ImagingStepPreInstall,
 frozenset([ImagingStepPhoenix, InstallHypervisorFactory]),
 ImagingStepHandoff,
 ImagingStepXenJoinPool,
 ImagingStepConfigurationUpdate,
 ImagingStepClusterInit,
 ImagingStepSetupReplication,
 ImagingStepNcc,
 ImagingStepSyscheck,
 ImagingStepComputeOnly,
 ImagingStepClusterDestroy]
IMAGING_TASKS_FACTORY = [
 ImagingStepCokevaStart,
 ImagingStepFlexStart,
 ImagingStepSMCStart,
 ImagingStepFruCheck,
 ImagingStepFruCheckBarrier,
 ImagingStepBiosCfgUpdate,
 ImagingStepBiosCfgBarrier,
 ImagingStepValidation,
 GetNosVersion,
 ImagingStepTypeDetection,
 ImagingStepInitFactory,
 ImagingStepFactorySELCheckPre,
 ImagingStepFactorySELCheckBarrier,
 ImagingStepMiscHWChecks,
 ImagingStepPreInstall,
 ImagingStepTimeCheck,
 frozenset([ImagingStepPhoenix, InstallHypervisorFactory]),
 ImagingStepBiosCfgVerify,
 ImagingStepDiskCheck,
 ImagingStepClusterInit,
 ImagingStepNcc,
 ImagingStepSyscheck,
 ImagingStepFactorySELCheckPost,
 ImagingStepFactorySELCheckBarrier,
 ImagingStepClusterDestroy,
 ImagingStepDiskErase,
 ImagingStepFactoryDeconfigureFactory,
 ImagingStepFlexReport,
 ImagingStepCokevaReport,
 ImagingStepSMCReport,
 ImagingStepFactoryMail]
VALIDATION_TASKS_FC = [
 ValidationStepDisableDupArp,
 ValidationStepGetIp,
 ValidationStepArpScan,
 ValidationStepConfigIp,
 ValidationStepBarrier,
 ValidationStepPingAll,
 ImagingStepUpdateFC]
CONTEXT_TASKS_MAP = {imaging_context.FIELD_IPMI: IMAGING_TASKS_IPMI, 
   imaging_context.FIELD_VM: IMAGING_TASKS_CVM, 
   imaging_context.FACTORY: IMAGING_TASKS_FACTORY}
DEFAULT_LOGGER = logging.getLogger(__file__)

def run_imaging_tasks(global_config):
    """
    Execute a imaging graph with executor.
    
    Parameter:
      global_config: a global_config with .graph attribute
    
    Returns:
      number of nodes imaged, failed
    
    Other possible executors:
      serial executor: ntm.serial_executor(graph)
    """
    DEFAULT_LOGGER.info('Session id: %s' % global_config._session_id)
    DEFAULT_LOGGER.info('Executing imaging graph')
    graph = global_config.graph
    ntm.parallel_executor(graph, global_config)
    DEFAULT_LOGGER.info('Imaging graph Executed')
    return ntm.get_ndone_nerror(global_config)


def generate_imaging_graph(global_config, action=Action.IMAGING):
    """
    Generate dependency graph for imaging.
    
    Parameter:
      global_config: a GlobalConfig object with .cluster attribute
      action: the action for progress API
    
    Returns:
      the generated dependency graph
    
    NOTE: Caller is responsible to make sure no imaging session is running.
    """
    if action == Action.IMAGING:
        context = imaging_context.get_context()
        if getattr(global_config, 'fc_workflow', False):
            validate_and_initialize(global_config)
            global_config.results = defaultdict(list)
            imaging_tasks = VALIDATION_TASKS_FC + IMAGING_TASKS_CVM
        elif getattr(global_config, 'foundation_central', False):
            from foundation.foundation_central import progress_workflow
            imaging_tasks = IMAGING_TASKS_CVM
            fc_progress_thread = threading.Thread(target=progress_workflow, args=(
             global_config._session_id,))
            fc_progress_thread.daemon = True
            fc_progress_thread.start()
        else:
            assert context in CONTEXT_TASKS_MAP, 'Unknown imaging context %s' % context
            imaging_tasks = CONTEXT_TASKS_MAP[context]
    else:
        if action == Action.BOOT_PHOENIX:
            imaging_tasks = BOOT_PHOENIX_TASKS
        else:
            raise StandardError('Invalid action %s specified' % action)
    graph = ntm.generate_graph(global_config, imaging_tasks)
    DEFAULT_LOGGER.debug('Clusters are: %s\nNodes are: %s', global_config.clusters, global_config.nodes)
    DEFAULT_LOGGER.debug('Graph is:\n%s', pprint.pformat(graph))
    global_config.graph = graph
    global_config.action = action
    return graph


def do_imaging_threaded_worker(global_config):
    try:
        ret = run_imaging_tasks(global_config)
        if ret[1]:
            session_manager.mark_session_failure(global_config._session_id)
        else:
            session_manager.mark_session_success(global_config._session_id)
        if features.is_enabled(features.QA_SKIP_WHITELIST_ONCE):
            logging.warn("Disabling the 'QA_SKIP_WHITELIST_ONCE' feature, restart foundation to enable it again")
            features.disable(features.QA_SKIP_WHITELIST_ONCE)
        return ret
    except:
        DEFAULT_LOGGER.exception('imaging failed')
        config_persistence.fail_all_remaining_work()
        session_manager.mark_session_failure(global_config._session_id)
        return (-999, -999)
    finally:
        states_reached_path = folder_central.get_states_reached_path()
        ntm.dump_states_reached_json(states_reached_path)
        session_id = global_config._session_id
        foundation_tools.update_metadata({'final_persisted_config': config_persistence.get_persisted_config()}, session_id)
        global_config._session_config.archive_logs()
        upload_logs(global_config)
        automation = getattr(global_config, AUTOMATION_FRAMEWORK_KEY, {})
        if automation:
            nos_package = getattr(global_config, 'fake_nos_package', '')
            if os.path.exists(nos_package):
                os.remove(nos_package)


def do_imaging_threaded(global_config):
    """
    Start imaging thread in background.
    
    Caller is responsible to make sure no imaging session is running.
    """
    imaging_thread = threading.Thread(target=do_imaging_threaded_worker, args=(
     global_config,))
    session_manager.set_session_id(global_config._session_id, thread=imaging_thread)
    imaging_thread.daemon = True
    global_config.imaging_thread = imaging_thread
    imaging_thread.start()
    return imaging_thread


def do_imaging(global_config):
    """
    Short cut of generate graph, and call run_imaging_tasks.
    """
    generate_imaging_graph(global_config)
    return do_imaging_threaded_worker(global_config)


def cli_monitor_progress(session_id):
    logger = logging.getLogger('console')
    logger.info('Installation in progress. Will report aggregate node status every %d seconds', PROGRESS_INTERVAL_S)
    gc = session_manager.get_global_config(session_id=session_id)
    last_report = 0
    last_progress = -1
    while True:
        progress = ntm.get_progress(session_id=session_id)
        summary = {}
        for item in progress['nodes'] + progress['clusters']:
            status = item['status']
            summary[status] = summary.get(status, 0) + 1

        parts = [ '%s: %d' % (state, count) for state, count in summary.iteritems() ]
        if time.time() - last_report > PROGRESS_INTERVAL_S or last_progress != progress['aggregate_percent_complete']:
            logger.info('Imaging progress %0.2f%%: %s', progress['aggregate_percent_complete'], (', ').join(parts))
            last_report = time.time()
            last_progress = progress['aggregate_percent_complete']
        if progress['imaging_stopped']:
            if gc.nodes:
                for config in gc.nodes + gc.clusters:
                    if not isinstance(config, (NodeConfig, ClusterConfig)):
                        continue
                    exceptions = getattr(config, '_exceptions', [])
                    if exceptions:
                        exceptions_str = ('; ').join(map(str, exceptions))
                        logger.error('%s: FAIL, Reason: %s', config, exceptions_str)
                    else:
                        logger.info('%s: PASS', config)

            logger.info('Imaging stopped')
            break
        else:
            time.sleep(1)


def cli_imaging(global_config):
    """
    Entry point of cli imaging.
    """
    simple_logger.rotate_all_logger()
    logger = logging.getLogger('console')
    session_manager.set_session_active(global_config._session_id)
    try:
        logger.info('Validating Config')
        config_validator.common_validations(global_config, quick=True)
        generate_imaging_graph(global_config)
        imaging_thread = do_imaging_threaded(global_config)
        cli_monitor_progress(global_config._session_id)
        imaging_thread.join()
    except Exception:
        logger.exception('Imaging failed, exception follows')
        config_persistence.fail_all_remaining_work()

    n_done, n_error = ntm.get_ndone_nerror(global_config)
    if n_error:
        logger.error('Imaging failed on %d nodes', n_error)
    return n_error


def upload_logs(global_config):
    """
    Uploads logs after they are archived from fvm to cvm.
    """
    if global_config.action != Action.IMAGING:
        DEFAULT_LOGGER.debug('Only imaging logs need to be uploaded to CVM')
        return
    if imaging_context.get_context() != imaging_context.FIELD_IPMI:
        DEFAULT_LOGGER.debug('Log files need to be uploaded to CVM only forfield foundation')
        return
    for node in global_config.nodes:
        try:
            session_path = os.path.join('/home/nutanix/data/logs/foundation', global_config._session_id)
            cmd = ['mkdir ' + session_path]
            foundation_tools.ssh(None, node.cvm_ip, cmd)
            files = os.listdir(os.path.join('/home/nutanix/foundation/log', global_config._session_id))
            DEFAULT_LOGGER.debug('Copying Files: ' + str(files))
            files = [ os.path.join('/home/nutanix/foundation/log', global_config._session_id) + '/' + file for file in files
                    ]
            foundation_tools.scp(None, node.cvm_ip, session_path, files)
        except Exception as e:
            DEFAULT_LOGGER.debug('Uploading failed: ' + str(e))

    return