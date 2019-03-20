# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_prepare_nos.py
# Compiled at: 2019-02-15 12:42:10
from imaging_step import ImagingStepNodeTask
from shared_functions import get_nos_version_from_tarball
from foundation import foundation_tools

class GetNosVersion(ImagingStepNodeTask):

    def run(self):
        logger = self.logger
        logger.info('Node IP: CVM(%s) HOST(%s) IPMI(%s)' % tuple(map(lambda k: getattr(self.config, k, '?'), [
         'svm_ip', 'hypervisor_ip', 'ipmi_ip'])))
        if not self.config.svm_install_type or not self.config.image_now:
            logger.info('GetNosVersion skipped')
            return
        self.config.nos_version = self.config._cache.get(get_nos_version_from_tarball, self.config.nos_package)
        logger.info('NOS Version is: %s', self.config.nos_version)
        session_id = self.config._session_id
        foundation_tools.update_metadata({'nos_version': self.config.nos_version}, session_id)