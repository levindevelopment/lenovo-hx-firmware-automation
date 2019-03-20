# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_cokeva.py
# Compiled at: 2019-02-15 12:42:10
import datetime, glob, logging, lxml.etree as etree, threading
from collections import defaultdict
from contextlib import contextmanager
from cgi import escape
from foundation import foundation_settings
from foundation import factory_mode
from foundation.factory_mode import what_is_my_block_id
from foundation.imaging_step import ImagingStepClusterAlwaysRunTask
from foundation.imaging_step import ImagingStepClusterTask
from foundation.session_manager import get_session_manager
from foundation.imaging_step_fru_check import CLUSTER_ID_KEY
DEFAULT_LOGGER = logging.getLogger(__name__)
COKEVA_FILE_LOCK = threading.Lock()
STATE_START = 'Starting Cokeva'
STATE_STOP = 'Reporting Cokeva'
PASS = 'PASS'
FAIL = 'FAIL'
TS_FMT = '%Y-%m-%d %H:%M'
TESTS_MAPPING = [
 ('Serial_Number', 'node_serial'),
 ('Position', 'node_position'),
 ('ClusterID', 'cluster_id'),
 ('AOSVersion', 'nos_version')]
COKEVA_PATH = '/export/MAGIC'
settings = foundation_settings.get_settings()
if 'COKEVA_PATH' in settings:
    COKEVA_PATH = settings['COKEVA_PATH']
    assert COKEVA_PATH, 'Invalid cokeva path: %s' % COKEVA_PATH

def is_in_cokeva_factory():
    factory_config = factory_mode.get_config()
    if factory_config.get('factory_type') == factory_mode.FACTORY_COKEVA:
        return True
    return False


def get_xml_file_for_block(block_id):
    pattern = COKEVA_PATH + '/%s_*.xml' % block_id
    xmls = glob.glob(pattern)
    if not xmls:
        return
    if len(xmls) > 1:
        DEFAULT_LOGGER.error('found multiple xml files matching %s', pattern)
        return
    return xmls[0]
    return


@contextmanager
def cokeva_xml_context(block_id, write_back=True):
    xml_file = get_xml_file_for_block(block_id)
    if not xml_file:
        raise StandardError('No xml file foundation matching %s' % block_id)
    with COKEVA_FILE_LOCK:
        parser = etree.XMLParser(remove_blank_text=True)
        xml_tree = etree.parse(open(xml_file), parser=parser)
        yield xml_tree
        if write_back:
            with open(xml_file, 'w') as (xml_fd):
                xml_tree.write(xml_fd, encoding='UTF-8', pretty_print=True, standalone=True)


def cokeva_start(block_id, logger=DEFAULT_LOGGER):
    with cokeva_xml_context(block_id, write_back=False):
        pass


class ImagingStepCokevaStart(ImagingStepClusterTask):

    @classmethod
    def is_compatible(cls, config):
        return is_in_cokeva_factory()

    def get_progress_timing(self):
        return [
         (
          STATE_START, 1)]

    def run(self):
        cluster_config = self.config
        node_configs = cluster_config.cluster_members
        logger = self.logger
        block_ids = map(what_is_my_block_id, node_configs)
        block_ids = filter(lambda block_id: block_id is not None, block_ids)
        block_ids = set(block_ids)
        logger.info('Checking xml for %s blocks', len(block_ids))
        for block_id in block_ids:
            logger.info('Checking cokeva xml file: started imaging on block %s', block_id)
            cokeva_start(block_id, logger)

        logger.info('Checked all blocks')


def generate_cokeva_xml_report(block_id, nodes, start_time, end_time):
    """
    Modify imaging result for block_id/nodes.
    
    Args:
      block_id: str, block id
      nodes: list, list of NodeConfig objs
      start_time: datetime, time when imaging is started
      end_time: datetime, when imaging is stopped
    """
    with cokeva_xml_context(block_id, write_back=True) as (root):
        for node in nodes:
            exceptions = node._exceptions + node._parent._exceptions
            if exceptions:
                img_result = FAIL if 1 else PASS
                failure_code = (',').join(map(lambda e: str(e), exceptions))
                if len(failure_code) > 80:
                    failure_code = failure_code[:68] + '..truncated'
                if not failure_code:
                    failure_code = 'N/A'
                failure_code = escape(failure_code, quote=True)
                cluster_id = getattr(node, 'cluster_id', None)
                if not cluster_id:
                    cluster_id = getattr(node, 'fru_dict', {}).get(CLUSTER_ID_KEY)
                fields = {'IMG_RESULT': img_result, 
                   'IMG_START_TIME': start_time.strftime(TS_FMT), 
                   'IMG_END_TIME': end_time.strftime(TS_FMT), 
                   'IMG_FAILURE_CODE': failure_code, 
                   'CLUSTER_ID': cluster_id, 
                   'AOS_VERSION': getattr(node, 'nos_version', 'N/A')}
                if node.node_serial == block_id:
                    elem = root.xpath('/NODE')[0]
                else:
                    pos = node.node_position
                    elem = root.xpath("/SYSTEM/NODE[POSITION = '%s']" % pos)[0]
                for k, v in fields.items():
                    logger = node.get_logger()
                    logger.debug('Cokeva XML, Set %s/%s: %s => %s', block_id, node.node_serial, k, v)
                    elem.xpath('%s' % k)[0].text = v

    return


class ImagingStepCokevaReport(ImagingStepClusterAlwaysRunTask):

    @classmethod
    def is_compatible(cls, config):
        return is_in_cokeva_factory()

    def get_progress_timing(self):
        return [
         (
          STATE_STOP, 1)]

    def run(self):
        cluster_config = self.config
        node_configs = cluster_config.cluster_members
        logger = self.logger
        block_id_node_mapping = defaultdict(set)
        session_id = node_configs[0]._session_id
        sm = get_session_manager()
        start_time = sm.get_session_by_id(session_id).start_time
        start_time = datetime.datetime.fromtimestamp(start_time)
        now = datetime.datetime.now()
        for node in node_configs:
            real_block_id = what_is_my_block_id(node)
            if real_block_id is None:
                logger.debug('Skipping gold node: %s', node)
                continue
            block_id_node_mapping[real_block_id].add(node)

        for block_id, nodes in block_id_node_mapping.items():
            logger.info('Generating Cokeva XML for block: %s, %d node(s)', block_id, len(nodes))
            generate_cokeva_xml_report(block_id, nodes, start_time, now)
            logger.info('Generated Cokeva XML for block: %s', block_id)

        logger.info('Generated Cokeva XML of %s blocks', len(block_id_node_mapping))
        return