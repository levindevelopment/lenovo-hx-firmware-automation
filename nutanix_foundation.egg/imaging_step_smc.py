# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_smc.py
# Compiled at: 2019-02-15 12:42:10
from xml.sax.saxutils import escape
from foundation import factory_smc as smc
from foundation import new_threading_model as ntm
from foundation.imaging_step import ImagingStepClusterTask
from foundation.imaging_step import ImagingStepClusterAlwaysRunTask
from foundation.imaging_step_fru_check import CLUSTER_ID_KEY
from foundation.factory_mode import get_station_id
from foundation.factory_smc import post_uut_imaging_result
STATE_START = 'Sending START to SMC Factory API'
STATE_REPORT = 'Sending Report to SMC Factory API'
PASS = 'PASS'
FAIL = 'FAIL'

def collect_info(node_config):
    """
    Returns:
      sn, model, cluster_id, nos_version
    """
    fru_dict = getattr(node_config, 'fru_dict', {})
    return (
     node_config.node_serial,
     fru_dict.get('Model', 'N/A'),
     fru_dict.get(CLUSTER_ID_KEY, '0'),
     getattr(node_config, 'nos_version', 'N/A'))


class ImagingStepSMCStart(ImagingStepClusterTask):
    """
    Send 'START' to SMC Factory API
    """

    @classmethod
    def is_compatible(cls, config):
        return smc.is_in_smc_prod_factory()

    def get_progress_timing(self):
        return [
         (
          STATE_START, 1)]

    def run(self):
        cluster_config = self.config
        node_configs = cluster_config.cluster_members
        node_config = node_configs[0]
        logger = self.logger
        sn, model, cluster_id, nos_version = collect_info(node_config)
        logger.info('Sending START to SMC Factory API for %s %s', sn, model)
        post_uut_imaging_result(sn, model, cluster_id, nos_version, 'START', logger=logger)


class ImagingStepSMCReport(ImagingStepClusterAlwaysRunTask):
    """
    Send 'PASS' or 'FAIL' to SMC Factory API
    """

    @classmethod
    def is_compatible(cls, config):
        return smc.is_in_smc_prod_factory()

    def get_progress_timing(self):
        return [
         (
          STATE_REPORT, 1)]

    def run(self):
        cluster_config = self.config
        node_configs = cluster_config.cluster_members
        node_config = node_configs[0]
        logger = self.logger
        sn, model, cluster_id, nos_version = collect_info(node_config)
        result = PASS
        desc = 'N/A'
        task_dict = ntm.dictfy_tasks(node_config.graph)
        tasks = []
        for config, task_class_objs in task_dict.items():
            if config in [node_config, cluster_config]:
                tasks.extend(task_class_objs.values())

        is_aborted = getattr(node_config, 'abort_session', False)
        failed_tasks = filter(lambda t: t.get_state() == 'FAILED', tasks)
        station_id = get_station_id()
        if is_aborted or failed_tasks:
            result = FAIL
            if not failed_tasks:
                desc = station_id + ': aborted imaging by failures from other nodes'
            else:
                exceptions = node_config._exceptions + cluster_config._exceptions
                fail_description = (', ').join(map(lambda e: type(e).__name__ + ':' + str(e), exceptions))
                fail_description = fail_description[:480]
                desc = station_id + ': ' + escape(fail_description)
            logger.debug('Imaging %s for this node: %s', result, desc)
        logger.info('Reporting %s to SMC Factory API for %s %s', result, sn, model)
        post_uut_imaging_result(sn, model, cluster_id, nos_version, result, desc, logger=logger)