# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_time_check.py
# Compiled at: 2019-02-15 12:42:10
import time, datetime
from foundation import foundation_tools
from foundation.imaging_step import ImagingStepNodeTask
from foundation.factory_mode import get_config
STATE_CHECKING_TIME = 'Checking Node BIOS time settings'
STATE_CHECKING_TIME_DONE = 'BIOS time setting check passed'

def get_max_offset():
    fconfig = get_config()
    if fconfig:
        return fconfig.get('max_time_offset', None)
    return


class ImagingStepTimeCheck(ImagingStepNodeTask):
    """
    Check if the BIOS time offset is in acceptable range.
    
    Set the "max_time_offset" field in factory_settings.json to
    enable this step.
    """

    @classmethod
    def is_compatible(cls, config):
        max_offset = get_max_offset()
        return max_offset is not None

    def get_progress_timing(self):
        return [
         (
          STATE_CHECKING_TIME, 0.1)]

    def get_finished_message(self):
        return STATE_CHECKING_TIME_DONE

    def run(self):
        self.set_status(STATE_CHECKING_TIME)
        node_config = self.config
        logger = self.logger
        max_offset = get_max_offset()
        local_ts = int(time.time())
        node_ts, _, _ = foundation_tools.ssh(node_config, node_config.cvm_ip, [
         'date', '+%s'], user='root')
        node_ts = int(node_ts)
        local_str, node_str = map(lambda ts: datetime.datetime.fromtimestamp(ts).strftime('%c'), [
         local_ts, node_ts])
        offset = abs(node_ts - local_ts)
        logger.info('TimeCheck: local time: %s, node time: %s, offset: %ss', local_str, node_str, offset)
        if offset > max_offset:
            raise StandardError('Time difference(%s) is beyond max_time_offset(%s),please check BIOS time settings and retry' % (
             offset, max_offset))