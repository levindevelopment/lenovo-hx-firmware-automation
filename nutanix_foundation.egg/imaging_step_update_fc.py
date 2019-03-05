# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_update_fc.py
# Compiled at: 2019-02-15 12:42:10
from foundation import foundation_central_utils as fc_utils
from foundation import network_validation
from foundation.imaging_step import ImagingStepNodeTask
STATE_GET_NETWORK_DETAILS = 'Getting current ip configuration'
STATE_DONE_FRIENDLY = 'Successfully updated Foundation Central'

class ImagingStepUpdateFC(ImagingStepNodeTask):

    def get_finished_message(self):
        return STATE_DONE_FRIENDLY

    def get_progress_timing(self):
        return [
         (
          STATE_GET_NETWORK_DETAILS, 1)]

    def run(self):
        node_config = self.config
        logger = self.logger
        enable_ns = node_config.enable_ns
        self.set_status(STATE_GET_NETWORK_DETAILS)
        node_ip = node_config.cvm_ip
        if not (enable_ns and getattr(node_config, 'process_backplane_only', False)):
            if getattr(node_config, 'ipv6_address', None):
                node_ip = node_config.ipv6_address
        logger.info('Reading present IP configuration')
        ip_config = None
        try:
            ip_config = network_validation.get_ip_via_genesis(node_config, node_ip)
        except StandardError as e:
            logger.error('Failed to get IP configuration: %s' % str(e))
            logger.warning('Proceeding without updating Foundation Central with the new node ip addresses')
            return
        else:
            logger.info('Present IP configuration is: %s' % str(ip_config))
            if not getattr(node_config, 'fc_imaged_node_uuid', None):
                logger.error("Couldn't find imaged_node_uuid in node_config")
                logger.warning('Proceeding without updating Foundation Central with the new node ip addresses')
                return

        imaged_node_uuid = node_config.fc_imaged_node_uuid
        if fc_utils.update_imaged_node_network_details(ip_config, imaged_node_uuid):
            logger.info('Updated new network configuration in Foundation Central: %s' % str(ip_config))
        else:
            logger.error('Failed to update network configuration in FC')
            logger.warning('Proceeding without updating Foundation Central with the new node ip addresses')
        return