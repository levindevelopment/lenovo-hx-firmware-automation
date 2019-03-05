# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/ipmi_smc.py
# Compiled at: 2019-02-15 12:42:10
import logging, weakref
from pyghmi.ipmi.oem.generic import OEMHandler
from pyghmi.exceptions import PyghmiException
logger = logging.getLogger(__file__)
BUS_ID = 7
SLAVE_ADDR_80 = 128
SLAVE_ADDR_82 = 130
SLAVE_ADDR_84 = 132
SLAVE_ADDR_86 = 134
IPMI_NETFN_APP = 6
SMC_TP_CMD = 82
DATA_IS_TP = 253
DATA_NODE_ID = 0
DATA_SYS_PN = 65
DATA_SYS_SN = 97

class SMCOEMHandler(OEMHandler):
    """
    OEMHandler for SMC IPMI
    
    Currently, only TwinPro related function is implemented
    """

    def __init__(self, oemid, ipmicmd):
        self.ipmicmd = weakref.proxy(ipmicmd)
        self.addr = SLAVE_ADDR_80
        self.device_type = 0

    def _master_write_read(self, bus_id, slave_addr, bytes_to_read, data_to_write):
        """
        Send raw master_write_read command slave_addr at bus_id
        """
        full_data = [
         bus_id, slave_addr, bytes_to_read] + data_to_write
        return self.ipmicmd.xraw_command(IPMI_NETFN_APP, command=SMC_TP_CMD, data=full_data)

    @staticmethod
    def _str_strip(data):
        """
        Strip padding chars
        """
        return data[:].rstrip('\x00').rstrip('')

    def is_twinpro(self):
        for addr in [SLAVE_ADDR_80, SLAVE_ADDR_86]:
            try:
                resp = self._master_write_read(BUS_ID, addr, 1, [DATA_IS_TP])
                if ord(resp['data'][0]) in (165, ):
                    self.addr = addr
                    self.device_type = 0
                    return True
                if ord(resp['data'][0]) in (166, 167, 168):
                    self.addr = addr
                    self.device_type = 2
                    return True
                if ord(resp['data'][0]) in (172, ):
                    self.addr = addr
                    self.device_type = 1
                    return True
                return False
            except PyghmiException as e:
                logger.debug('This system might no be TwinPro (%s)', e)

        return False

    def get_node_id(self):
        resp = self._master_write_read(BUS_ID, self.addr, 1, [DATA_NODE_ID])
        return ord(resp['data'][0])

    def get_system_pn(self):
        resp = self._master_write_read(BUS_ID, self.addr, 24, [DATA_SYS_PN])
        return SMCOEMHandler._str_strip(resp['data'])

    def get_system_sn(self):
        resp = self._master_write_read(BUS_ID, self.addr, 24, [DATA_SYS_SN])
        return SMCOEMHandler._str_strip(resp['data'])


if __name__ == '__main__':
    import sys
    from foundation.ipmi_util import get_session
    if len(sys.argv) != 4:
        print 'Usage %s <bmc_ip> <username> <password>' % sys.argv[0]
    else:
        print 'Checking %s' % sys.argv[1]
        session = get_session(*sys.argv[1:])
        smc = SMCOEMHandler(0, session)
        is_tp = smc.is_twinpro()
        print 'Is TwinPro:\t', is_tp
        if is_tp:
            print 'Node ID:\t', smc.get_node_id()
            print 'System PN:\t', smc.get_system_pn()
            print 'System SN:\t', smc.get_system_sn()