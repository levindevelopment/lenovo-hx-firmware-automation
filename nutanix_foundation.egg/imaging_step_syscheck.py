# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_syscheck.py
# Compiled at: 2019-02-15 12:42:10
import os, foundation_tools, folder_central
from foundation import imaging_context
from imaging_step import ImagingStepClusterTask
from metis.context import MetisContext
from metis.element import MetisTask
STATE_SYSCHECK = 'Running syscheck'
STATE_SYSCHECK_DONE = 'Syscheck execution completed'
BASE_RUNTIME = 5
DEFAULT_NODE_COUNT = 5
RUNTIME_PER_NODE = 1
EXPECTED_RUNTIME = BASE_RUNTIME + RUNTIME_PER_NODE * DEFAULT_NODE_COUNT

class ImagingStepSyscheck(ImagingStepClusterTask):

    @classmethod
    def is_compatible(cls, config):
        """
        Run syscheck only if user asks to do it.
        """
        return getattr(config, 'run_syscheck', False)

    def get_progress_timing(self):
        return [
         (
          STATE_SYSCHECK, EXPECTED_RUNTIME)]

    def get_finished_message(self):
        return STATE_SYSCHECK_DONE

    def run(self):
        cluster_config = self.config
        logger = self.logger
        cluster_name = cluster_config.cluster_name
        cluster_members = cluster_config.cluster_members
        cluster_svms = map(lambda node: node.cvm_ip, cluster_members)
        expected_runtime = BASE_RUNTIME + len(cluster_members) * RUNTIME_PER_NODE
        timeout = expected_runtime * 4 * 60
        self.set_status(STATE_SYSCHECK)
        some_cvm_ip = cluster_svms[0]
        nos_version = foundation_tools.get_nos_version_from_cvm(some_cvm_ip, cluster_config)
        if nos_version < [4, 1, 3]:
            logger.info("syscheck isn't installed by default prior to NOS 4.1.3. Please install and run syscheck manually. Sorry for the inconvenience.")
            return
        options = {'checks': [
                    'check_disk', 'check_net']}
        if imaging_context.get_context() == imaging_context.FACTORY:
            options['checks'] = ['check_disk']
        logger.info('Starting syscheck. This will take approximately %d minutes...' % expected_runtime)
        context = MetisContext()
        context.set_save_root(os.path.join(folder_central.get_session_log_folder(cluster_config._session_id), 'syscheck'))
        context.set_svm_addrs(cluster_svms)
        syscheck = MetisTask(cluster_name, 'syscheck', options=options, set_global=context.to_struct(), timeout=timeout, cleanup_must_succeed=True)
        syscheck.add_callback_logger(lambda m: logger.info(m), format='%(levelname)s: %(message)s')
        outcome = syscheck.run()
        syscheck.close_log_handlers()
        logger.info('syscheck produced the following results:\n%s' % str(outcome))
        if not outcome.is_success():
            raise StandardError('syscheck failed on cluster %s' % cluster_name)