# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_fru_check.py
# Compiled at: 2019-02-15 12:42:10
import os, random
from foundation import folder_central
from foundation import factory_mode
from foundation import foundation_tools
from foundation import ipmi_smc
from foundation import ipmi_util
from foundation.imaging_step import ImagingStepNodeTask, ImagingStepClusterTask
STATE_CHECKING_FRU = 'Checking parameters against node FRU'
STATE_CHECKING_FRU_DONE = 'Parameters match node FRU'
NODE_SERIAL_KEY = 'Board serial number'
BLOCK_ID_KEY = 'Serial Number'
CLUSTER_ID_KEY = 'Asset Number'
IBM_BLOCK_ID_KEY = 'Chassis serial number'

class ImagingStepFruCheck(ImagingStepNodeTask):

    def get_progress_timing(self):
        return [
         (
          STATE_CHECKING_FRU, 0.1)]

    def get_finished_message(self):
        return STATE_CHECKING_FRU_DONE

    def _program_fru(self, key, value):
        """
        Program a FRU field
        """
        node_config = self.config
        smc_lib_path = os.path.dirname(folder_central.get_smc_ipmitool_path())
        return foundation_tools.system(node_config, [
         'java', '-Djava.library.path=%s' % smc_lib_path,
         '-jar', folder_central.get_smc_ipmitool_path(),
         node_config.ipmi_ip,
         node_config.ipmi_user,
         node_config.ipmi_password,
         'ipmi', 'fruw', key, value])

    def _get_node_serial_from_fru(self):
        if factory_mode.is_ibm():
            backplane_fru = ipmi_util.get_component_fru(self.config, 'Backplane')
            return backplane_fru[NODE_SERIAL_KEY].upper()
        return self.get_fru()[NODE_SERIAL_KEY].upper()

    def _get_block_serial_from_fru(self):
        if factory_mode.is_ibm():
            backplane_fru = ipmi_util.get_component_fru(self.config, 'Backplane')
            return backplane_fru[IBM_BLOCK_ID_KEY].upper()
        return self.get_fru()[BLOCK_ID_KEY].upper()

    def dump_fru(self, fru):
        """
        Format and dump FRU to log.
        """
        logger = self.logger
        logger.info('Fru for this node is:\n%s', ('\n').join(map(lambda (k, v): ' %s: %s' % (k, v), sorted(fru.items()))))

    def get_fru(self):
        node_config = self.config
        return ipmi_util.get_system_fru(node_config)

    def get_net(self):
        node_config = self.config
        return ipmi_util.get_net_configuration(node_config)

    def run(self):
        self.set_status(STATE_CHECKING_FRU)
        node_config = self.config
        logger = self.logger
        assert hasattr(node_config, 'node_serial'), 'node_serial must be provided in factory imaging'
        assert hasattr(node_config, 'block_id'), 'block_id must be provided in factory imaging'
        config_node_serial = node_config.node_serial.strip().upper()
        config_block_id = node_config.block_id.strip().upper()
        gold_node = 'GOLD' in config_node_serial
        gold_block = 'GOLD' in config_block_id
        if gold_node:
            logger.info('Skipping FRU check because node %s is gold', config_node_serial)
        else:
            if gold_block:
                logger.info('Skipping FRU check because block %s is gold', config_block_id)
            else:
                logger.info('Checking parameters against FRU')
                fru = self.get_fru()
                self.dump_fru(fru)
                fru_node_serial = self._get_node_serial_from_fru()
                fru_block_id = self._get_block_serial_from_fru()
                with ipmi_util.ipmi_context(node_config) as (ipmi):
                    smc = ipmi_smc.SMCOEMHandler(0, ipmi)
                    if smc.is_twinpro():
                        logger.info('TwinPro detected, using block id from backplane')
                        fru_block_id = smc.get_system_sn()
                    else:
                        logger.info('Using block id from FRU')
                node_errors = []
                if not fru_node_serial == config_node_serial:
                    message = "Scanned node serial '%s' did not match '%s', the serial in FRU." % (
                     config_node_serial, fru_node_serial)
                    logger.warn(message)
                    if config_node_serial:
                        node_errors.append(message)
                    else:
                        node_config.node_serial = fru_node_serial
                        logger.debug('Using node serial from FRU')
                else:
                    logger.debug('Scanned node serial matches.')
                if not fru_block_id == config_block_id:
                    message = 'Scanned block id %s did not match %s, the id in FRU.' % (
                     config_block_id, fru_block_id)
                    logger.warn(message)
                    node_errors.append(message)
                else:
                    logger.debug('Scanned block id matches.')
                if node_errors:
                    raise StandardError((', ').join(node_errors))
                fru_pat = fru.get(CLUSTER_ID_KEY, '')
                if not fru_pat or not fru_pat.isdigit():
                    logger.warn('FRU check got invalid PAT: %s, will program a new one', fru_pat)
                    net_info = self.get_net()
                    mac_address = net_info['mac_address']
                    mac_address_hex = ('').join(mac_address.split(':'))
                    cluster_id_hex = hex(random.randint(0, 32767)) + mac_address_hex
                    cluster_id = str(int(cluster_id_hex, 16))
                    self._program_fru('PAT', cluster_id)
                    logger.info('FRU is programmed with a new PAT: %s', cluster_id)
                    fru_dict = self.get_fru()
                    assert fru_dict[CLUSTER_ID_KEY] == cluster_id, "PAT/%s should be '%s', but it's '%s' in the FRU" % (
                     CLUSTER_ID_KEY, cluster_id, fru_dict[CLUSTER_ID_KEY])
                logger.info('FRU check passed')
        node_config.fru_dict = self.get_fru()


class ImagingStepFruCheckBarrier(ImagingStepClusterTask):

    def get_progress_timing(self):
        return [
         (
          STATE_CHECKING_FRU, 0.1)]

    def get_finished_message(self):
        return STATE_CHECKING_FRU_DONE

    def run(self):
        logger = self.logger
        logger.info('FRU check passed on all nodes')


if __name__ == '__main__':
    import sys, logging
    from config_manager import NodeConfig
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) != 4:
        print 'usage: %s <IP> <username> <password>'
    else:
        nc = NodeConfig()
        nc.ipmi_ip, nc.ipmi_user, nc.impi_password = sys.argv[1:]
        nc._session_id = 'test_session'
        step = ImagingStepFruCheck(nc)
        step.dump_fru(step.get_fru())