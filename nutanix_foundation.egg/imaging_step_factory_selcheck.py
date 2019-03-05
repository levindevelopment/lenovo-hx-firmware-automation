# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_factory_selcheck.py
# Compiled at: 2019-02-15 12:42:10
import csv, os, string, tempfile, folder_central, foundation_tools
from imaging_step import ImagingStepNodeTask, ImagingStepClusterTask
STATE_CHECKING_SEL = 'Checking System Event Log'
STATE_SEL_CHECK_COMPLETE = 'SEL check complete'
STATE_CHECKING_SEL_PRE = 'Pre-imaging ' + STATE_CHECKING_SEL
STATE_SEL_CHECK_COMPLETE_PRE = 'Pre-imaging ' + STATE_SEL_CHECK_COMPLETE
STATE_CHECKING_SEL_POST = 'Post-imaging ' + STATE_CHECKING_SEL
STATE_SEL_CHECK_COMPLETE_POST = 'Post-imaging ' + STATE_SEL_CHECK_COMPLETE
SUBSTRING_MATCH = 1
WORD_MATCH = 2
SEL_CHECK_TIMEOUT_S = 600
SEL_BLACK_LIST = [
 (
  'ecc', SUBSTRING_MATCH),
 (
  'critical', SUBSTRING_MATCH),
 (
  'caterr', SUBSTRING_MATCH),
 (
  'fail', SUBSTRING_MATCH),
 (
  'error', SUBSTRING_MATCH),
 (
  'intrusion', SUBSTRING_MATCH),
 (
  'non-recoverable', SUBSTRING_MATCH),
 (
  'ierr', SUBSTRING_MATCH)]

def _read_system_event_log(ipmi_ip, ipmi_user, ipmi_password):
    with tempfile.NamedTemporaryFile() as (fh):
        file_path = fh.name
        dirname = os.path.dirname(folder_central.get_smc_ipmitool_path())
        cmd = ['java', '-Djava.library.path=%s' % dirname, '-jar',
         folder_central.get_smc_ipmitool_path(), ipmi_ip, ipmi_user,
         ipmi_password, 'sel', 'csv', file_path]
        foundation_tools.system(None, cmd, throw_on_error=True, log_on_error=False, timeout=SEL_CHECK_TIMEOUT_S)
        rows = []
        with open(file_path, 'rb') as (csv_file):
            reader = csv.reader(csv_file)
            for row in reader:
                rows.append(row)

        return rows
    return


def _get_event_description_from_sel_record(log_record):
    return (' ').join(log_record[-2:])


def _clear_system_event_log(ipmi_ip, ipmi_user, ipmi_password):
    dirname = os.path.dirname(folder_central.get_smc_ipmitool_path())
    cmd = ['java', '-Djava.library.path=%s' % dirname, '-jar',
     folder_central.get_smc_ipmitool_path(), ipmi_ip, ipmi_user, ipmi_password,
     'sel', 'clear']
    foundation_tools.system(None, cmd, throw_on_error=True, log_on_error=False, timeout=SEL_CHECK_TIMEOUT_S)
    return


class ImagingStepFactorySELCheckBase(ImagingStepNodeTask):

    def __init__(self, *args, **kwargs):
        super(ImagingStepFactorySELCheckBase, self).__init__(*args, **kwargs)
        self.state_start = STATE_CHECKING_SEL
        self.state_done = STATE_SEL_CHECK_COMPLETE

    def get_finished_message(self):
        return self.state_done

    def get_progress_timing(self):
        return [
         (
          self.state_start, 3),
         (
          self.state_done, 1)]

    def _check_system_event_log(self, node_config):
        logger = self.logger
        node_serial = node_config.node_serial.strip().lower()
        gold_node = 'gold' in node_serial
        spare = 'spare' in node_serial or 'xspa' in node_serial
        gold_block = 'gold' in node_config.block_id.strip().lower()
        if gold_node:
            return
        logger.info('Fetching IPMI system event log')
        sel = _read_system_event_log(node_config.ipmi_ip, node_config.ipmi_user, node_config.ipmi_password)
        for rec in sel:
            logger.info('  SEL: ' + (',').join(rec))

        for rec in sel:
            event = _get_event_description_from_sel_record(rec)
            if not event:
                continue
            event = event.lower()
            words = [ word.strip(string.punctuation) for word in event.split() ]
            for w, match_type in SEL_BLACK_LIST:
                if match_type == WORD_MATCH and w in words or match_type == SUBSTRING_MATCH and w in event:
                    e = StandardError('Unexpected SEL entry: %s' % event)
                    if node_config._parent:
                        node_config._parent._exceptions.append(e)
                    raise e

        _clear_system_event_log(node_config.ipmi_ip, node_config.ipmi_user, node_config.ipmi_password)

    def run(self):
        node_config = self.config
        self.set_status(self.state_start)
        self._check_system_event_log(node_config)
        self.set_status(self.state_done)


class ImagingStepFactorySELCheckPre(ImagingStepFactorySELCheckBase):

    def __init__(self, *args, **kwargs):
        super(ImagingStepFactorySELCheckPre, self).__init__(*args, **kwargs)
        self.state_start = STATE_CHECKING_SEL_PRE
        self.state_done = STATE_SEL_CHECK_COMPLETE_PRE


class ImagingStepFactorySELCheckPost(ImagingStepFactorySELCheckBase):

    def __init__(self, *args, **kwargs):
        super(ImagingStepFactorySELCheckPost, self).__init__(*args, **kwargs)
        self.state_start = STATE_CHECKING_SEL_POST
        self.state_done = STATE_SEL_CHECK_COMPLETE_POST


class ImagingStepFactorySELCheckBarrier(ImagingStepClusterTask):

    def run(self):
        pass