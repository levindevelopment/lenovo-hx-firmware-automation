# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_flex.py
# Compiled at: 2019-02-15 12:42:10
import datetime, logging, os, lxml.etree as etree
from collections import defaultdict
from cgi import escape
from suds.client import Client, WebFault
from foundation import folder_central
from foundation import factory_mode
from foundation.factory_mode import what_is_my_block_id, RE_GOLD
from foundation.factory_mode import get_station_id
from foundation.factory_netsuite import netsuite_lookup_order_info
from foundation import foundation_settings
from foundation import new_threading_model as ntm
from foundation.imaging_step import ImagingStepGlobalNoAbortTask
from foundation.session_manager import get_session_manager
from foundation.imaging_step_fru_check import CLUSTER_ID_KEY
DEFAULT_LOGGER = logging.getLogger(__name__)
IFCFG_CONF = '/etc/sysconfig/network-scripts/ifcfg-eth1'
TESTER = 'admin'
BASE_API_URL = 'http://10.20.33.140/nutanix/fftester20.asmx?wsdl'
STATE_START = 'Starting Flex'
STATE_STOP = 'Reporting Flex'
settings = foundation_settings.get_settings()
if 'FLEX_BASE_API' in settings:
    BASE_API_URL = settings['FLEX_BASE_API']
    assert BASE_API_URL, 'Invalid API: %s' % BASE_API_URL

def is_in_flex_factory():
    factory_config = factory_mode.get_config()
    if factory_config.get('factory_type') == factory_mode.FACTORY_FLEX:
        return True
    return False


def flex_lookup_order_info(block_id):
    so_num, line_id = flex_report_start(block_id)
    return netsuite_lookup_order_info(so_num, line_id)


def flex_report_start(block_id, logger=DEFAULT_LOGGER):
    client = Client(BASE_API_URL)
    station_id = get_station_id()
    logger.debug('Reporting to flex from station: %s', station_id)
    result = client.service.GetUnitInfo(block_id, '?', station_id, TESTER)
    if result.GetUnitInfoResult != 0:
        raise StandardError('Failed in reporting: block %s' % block_id)
    root = etree.fromstring(result.strUnitInfo)
    so_num = root.xpath("//UnitData[Name='SalesOrder']/Value/text()")
    logger.info('Sales Order Number: %s', so_num[0])
    line_id = root.xpath("//UnitData[Name='SalesOrderPosition']/Value/text()")
    logger.info('Sales Order Line ID: %s', line_id[0])
    return (
     so_num[0], int(line_id[0]))


class ImagingStepFlexStart(ImagingStepGlobalNoAbortTask):

    @classmethod
    def is_compatible(cls, config):
        return is_in_flex_factory()

    def get_progress_timing(self):
        return [
         (
          STATE_START, 1)]

    def run(self):
        global_config = self.config
        nodes = global_config.nodes
        logger = self.logger
        block_ids = map(what_is_my_block_id, nodes)
        block_ids = filter(lambda block_id: block_id is not None, block_ids)
        block_ids = set(block_ids)
        logger.info('Reporting START record for %s blocks: %s', len(block_ids), (',').join(block_ids))
        any_failure = 0
        for block_id in block_ids:
            try:
                flex_report_start(block_id, logger)
            except WebFault:
                logger.exception('failed to report START record for block %s', block_id)
                any_failure += 1

        if any_failure:
            raise StandardError('failed to report START record for %s blocks' % any_failure)


BLOCK_TEMPLATE = ('\n<BATCH xmlns="http://www.flextronics.com/fts/sfs/res"\n       COMPATIBLE_REV="1.0" SYNTAX_REV="1.2" TIMESTAMP="{timestamp}">\n  <FACTORY FIXTURE="" LINE="" NAME="NONE" SHIFT="" TESTER="{tester}" USER="" />\n  <PRODUCT CUSTOMER="" FAMILY="" NAME="" REVISION="" />\n  <REFS CAL_REF="" CFG_REF=""\n        FTS_REF="/u2/utssrc/family/NUTANIX/testrel/NUTANIX_bhujschm"\n        INSTR_REF=""\n     LIM_REF="/u2/utssrc/family/NUTANIX/testrel/NUTANIX_bhujschm/data/fullconf"\n        SEQ_REF="" />\n  <PANEL COMMENT="" ID="unknown" RUNMODE="Production" STATUS="{status}"\n         TESTTIME="{test_time}" TIMESTAMP="{timestamp}" WAITTIME="0.00">\n    <DUT COMMENT="{comment}" ID="{block_id}" PANEL="0" SOCKET="0"\n         STATUS="{status}" TESTTIME="{test_time}" TIMESTAMP="{timestamp}">\n         {group}\n    </DUT>\n  </PANEL>\n</BATCH>').strip()
GROUP_PASS_TEMPLATE = '\n      <GROUP GROUPINDEX="{group_index}" LOOPINDEX="-1" MODULETIME="0"\n         NAME="System" RESOURCE="GROUP1" STATUS="{status}" STEPGROUP="9990.8"\n         TIMESTAMP="{timestamp}" TOTALTIME="0" TYPE="GENEALOGY">\n        <TEST DATATYPE="ATTRIBUTE" DESCRIPTION="system" HILIM="" LOLIM=""\n              NAME="serial_number" RULE="NONE" STATUS="{status}" TARGET=""\n              UNIT="" VALUE="{block_id}" />\n          {nodes}\n       </GROUP>\n'
GROUP_FAIL_TEMPLATE = '\n      <GROUP GROUPINDEX="0" LOOPINDEX="-1" MODULETIME="0" NAME="NUTANIX"\n             RESOURCE="GROUP0" STATUS="{status}" STEPGROUP=""\n             TIMESTAMP="{timestamp}" TOTALTIME="0" TYPE="Imaging">\n        <GROUP GROUPINDEX="0000000000" LOOPINDEX="-1" MODULETIME="0"\n               NAME="System" RESOURCE="GROUP1" STATUS="{status}"\n               STEPGROUP="" TIMESTAMP="{timestamp}" TOTALTIME="0"\n               TYPE="Imaging">\n          <TEST DATATYPE="ATTRIBUTE" DESCRIPTION="" HILIM="" LOLIM=""\n                NAME="{name}" RULE="NONE" STATUS="{status}" TARGET=""\n                UNIT="" VALUE="NUTANIX" />\n        </GROUP>\n      </GROUP>\n'
NODE_TEMPLATE = ('\n<GROUP GROUPINDEX="{group_index}" LOOPINDEX="-1" MODULETIME="0" NAME="node"\n       RESOURCE="GROUP2" STATUS="{status}" STEPGROUP="9990.8"\n       TIMESTAMP="{timestamp}" TOTALTIME="0" TYPE="GENEALOGY">\n  {tests}\n</GROUP>').strip()
TEST_TEMPLATE = ('\n<TEST DATATYPE="ATTRIBUTE" DESCRIPTION="node" HILIM="" LOLIM=""\n      NAME="{name}" RULE="NONE" STATUS="{status}" TARGET="" UNIT=""\n      VALUE="{value}" />\n').strip()
TESTS_MAPPING = [
 ('Serial_Number', 'node_serial'),
 ('Position', 'node_position'),
 ('ClusterID', 'cluster_id'),
 ('AOSVersion', 'nos_version')]
GROUPINDEX_BASE = 1100001
GROUPINDEX_LEN = len('0001100001')
PASS = 'Passed'
FAIL = 'Failed'

def generate_flex_xml_report(block_id, nodes, end_datetime, run_time):
    """
    Generate a xml report from nodes.
    
    Args:
      block_id: str, block id
      nodes: list, list of NodeConfig objs
      end_datetime: time, time of when imaging is stopped
      run_time: int, seconds of imaging time
    Returns:
      the report xml as str
    """
    station_id = get_station_id()
    timestamp = end_datetime.strftime('%Y-%m-%d %H:%M:%S')
    task_dict = ntm.dictfy_tasks(nodes[0].graph)
    tasks = []
    for config, task_class_objs in task_dict.items():
        if config in nodes:
            tasks.extend(task_class_objs.values())

    is_aborted = getattr(nodes[0], 'abort_session', False)
    failed_tasks = filter(lambda t: t.get_state() == 'FAILED', tasks)
    block_status = FAIL if failed_tasks or is_aborted else PASS
    block_commment = ''
    block_group = GROUPINDEX_BASE
    if block_status == FAIL:
        clusters = list(set(map(lambda nc: nc._parent, nodes)))
        block_exceptions = reduce(lambda l1, l2: l1 + l2, map(lambda c: c._exceptions, nodes + clusters))
        fail_description = (', ').join(map(lambda e: type(e).__name__ + ':' + str(e), block_exceptions))
        if len(fail_description) > 800:
            fail_description = fail_description[:790] + '..truncated'
        if is_aborted and not fail_description:
            fail_description = 'aborted imaging by failures from other nodes'
        fail_description = fail_description.replace('<', ' ').replace('>', ' ')
        block_commment = escape(fail_description, quote=True)
        failed_tasks_names = (',').join(sorted(set(map(lambda t: t.__class__.__name__, failed_tasks))))
        group_xml = GROUP_FAIL_TEMPLATE.format(timestamp=timestamp, name=failed_tasks_names, status=block_status)
    else:
        nodes_xml = []
        node_group = block_group + 1
        for node in nodes:
            if node._exceptions:
                node_status = FAIL if 1 else PASS
                is_in_gold_block = RE_GOLD.search(node.block_id)
                tests_xml = []
                for k, v in TESTS_MAPPING:
                    value = getattr(node, v, None)
                    if v == 'cluster_id' and not value:
                        value = node.fru_dict[CLUSTER_ID_KEY]
                    if v == 'node_position' and is_in_gold_block:
                        value = 'A'
                    tests_xml.append(TEST_TEMPLATE.format(name=k, status=node_status, value=value))

                node_xml = NODE_TEMPLATE.format(group_index=str(node_group).zfill(GROUPINDEX_LEN), status=node_status, timestamp=timestamp, tests=('\n').join(tests_xml))
                nodes_xml.append(node_xml)
                node_group += 1

        group_xml = GROUP_PASS_TEMPLATE.format(group_index=str(block_group).zfill(GROUPINDEX_LEN), status=block_status, timestamp=timestamp, block_id=block_id, nodes=('\n').join(nodes_xml))
    block_xml = BLOCK_TEMPLATE.format(timestamp=timestamp, tester=station_id, status=block_status, test_time=run_time, block_id=block_id, comment=block_commment, group=group_xml)
    return block_xml


def post_flex_xml_report(xml_str):
    client = Client(BASE_API_URL)
    return client.service.SaveResult(xml_str, '1')


class ImagingStepFlexReport(ImagingStepGlobalNoAbortTask):
    """
    Generate XML report and post to Flex for current cluster.
    
    Note: factory does single-node-cluster imaging and this method will report
          all nodes that sharing same block id, even they are in different
          clusters. So this task doesn't really run at cluster level, instead
          it's more like "block" level.
    """

    @classmethod
    def is_compatible(cls, config):
        return is_in_flex_factory()

    def get_progress_timing(self):
        return [
         (
          STATE_STOP, 1)]

    def run(self):
        global_config = self.config
        nodes = global_config.nodes
        logger = self.logger
        block_id_node_mapping = defaultdict(set)
        session_id = nodes[0]._session_id
        sm = get_session_manager()
        start_time = sm.get_session_by_id(session_id).start_time
        start_datetime = datetime.datetime.fromtimestamp(start_time)
        now = datetime.datetime.now()
        run_time = (now - start_datetime).seconds
        log_dir = folder_central.get_session_log_folder(session_id)
        for node in nodes:
            real_block_id = what_is_my_block_id(node)
            if real_block_id is None:
                logger.debug('Skipping gold node: %s', node)
                continue
            block_id_node_mapping[real_block_id].add(node)

        any_failure = 0
        for block_id, block_nodes in block_id_node_mapping.items():
            logger.info('Generating Flex XMLResultText for block: %s, %d node(s)', block_id, len(nodes))
            xml_str = generate_flex_xml_report(block_id, list(block_nodes), now, run_time)
            flex_xml_fn = os.path.join(log_dir, 'flex_%s_%s.xml' % (
             block_id, start_datetime.strftime('%Y%m%d_%H%M%S')))
            logger.info('Dumping Flex XMLResultText for block: %s to %s', block_id, flex_xml_fn)
            with open(flex_xml_fn, 'w') as (flex_xml_fp):
                flex_xml_fp.write(xml_str)
            logger.info('Posting Flex XMLResultText for block: %s', block_id)
            try:
                post_flex_xml_report(xml_str)
            except WebFault:
                logger.exception('failed to report XMLResultText for block: %s', block_id)
                any_failure += 1

        if any_failure:
            raise StandardError('Failed to post XMLResultText of %s blocks', any_failure)
        else:
            logger.info('Posted XMLResultText of %s blocks to Flex', len(block_id_node_mapping))
        return