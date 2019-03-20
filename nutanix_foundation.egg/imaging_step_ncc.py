# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_ncc.py
# Compiled at: 2019-02-15 12:42:10
import os, folder_central, foundation_tools
from foundation import imaging_context
from imaging_step import ImagingStepClusterTask
from metis.context import MetisContext
from metis.element import MetisTask
STATE_NCC = 'Running NCC'
STATE_NCC_DONE = 'Cluster creation and testing complete'
EXPECTED_RUNTIME = 10
TIMEOUT = EXPECTED_RUNTIME * 4 * 60

class ImagingStepNcc(ImagingStepClusterTask):

    @classmethod
    def is_compatible(cls, config):
        """
        Run ncc only if user asks to do it.
        """
        return getattr(config, 'run_ncc', False)

    def get_progress_timing(self):
        return [
         (
          STATE_NCC, EXPECTED_RUNTIME)]

    def get_finished_message(self):
        return STATE_NCC_DONE

    def run(self):
        cluster_config = self.config
        logger = self.logger
        cluster_name = cluster_config.cluster_name
        cluster_members = cluster_config.cluster_members
        cluster_svms = map(lambda node: node.cvm_ip, cluster_members)
        self.set_status(STATE_NCC)
        some_cvm_ip = cluster_svms[0]
        nos_version = foundation_tools.get_nos_version_from_cvm(some_cvm_ip, cluster_config)
        if nos_version < [4, 0]:
            logger.info("NCC isn't installed by default prior to NOS 4.0. Please install and run NCC manually. Sorry for the inconvenience")
            return
        options = {}
        if imaging_context.get_context() == imaging_context.FACTORY:
            ncc_version = foundation_tools.get_ncc_version_from_cvm(some_cvm_ip, cluster_config)
            if ncc_version >= [2, 3]:
                options = {'passthrough_args': ['--factory_test_mode=1']}
        logger.info('Starting NCC. This will take approximately %d minutes...' % EXPECTED_RUNTIME)
        context = MetisContext()
        context.set_save_root(os.path.join(folder_central.get_session_log_folder(cluster_config._session_id), 'ncc'))
        context.set_svm_addrs(cluster_svms)
        ncc = MetisTask(cluster_name, 'ncc', options=options, set_global=context.to_struct(), timeout=TIMEOUT, cleanup_must_succeed=True)
        ncc.add_callback_logger(lambda m: logger.info(m), format='%(message)s')
        outcome = ncc.run()
        ncc.close_log_handlers()
        logger.info('NCC produced the following results:\n' + str(outcome))
        if not outcome.is_success():
            raise StandardError('NCC failed on cluster %s' % cluster_name)