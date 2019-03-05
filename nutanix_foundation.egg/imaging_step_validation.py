# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_validation.py
# Compiled at: 2019-02-15 12:42:10
import imaging_step, config_validator
STATE_DUMMY = 'Will run validations shortly'
STATE_START = 'Running validations'
STATE_DONE_FRIENDLY = 'All validations successful'

class ImagingStepValidation(imaging_step.ImagingStepNodeTask):

    def get_finished_message(self):
        return STATE_DONE_FRIENDLY

    def get_progress_timing(self):
        expected_runtime = 0.5
        if self.config.hypervisor == 'hyperv':
            expected_runtime = 2.0
        return [(STATE_DUMMY, 1), (STATE_START, expected_runtime)]

    def run(self):
        self.set_status(STATE_DUMMY)
        node_config = self.config
        self.set_status(STATE_START)
        node_config._cache.get(config_validator.common_validations, global_config=self.config.get_root())