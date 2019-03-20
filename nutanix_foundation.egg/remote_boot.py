# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/remote_boot.py
# Compiled at: 2019-02-15 12:42:10
import platform

class RemoteBoot(object):

    def __init__(self, node_config):
        self.node_config = node_config

    def boot(self, iso, do_reset=True):
        """
          Virtual method for booting node specific iso.
        """
        raise NotImplementedError()

    def stop(self):
        """
          Virtual method for stopping virtual media process (if any).
        """
        raise NotImplementedError()

    def poweroff(self):
        """
          Virtual method for powering off node.
        """
        raise NotImplementedError()

    def powerreset(self):
        """
          Virtual method for powering off and power on node.
        """
        raise NotImplementedError()

    def wait_for_poweroff(self):
        """
          Virtual method for powering off node.
        """
        raise NotImplementedError()

    def set_first_boot_device(self):
        """
          Virtual method for setting satadom / raid as first boot device
        """
        raise NotImplementedError()

    def retry_boot_from_iso(self, iso):
        """
          This method is to provide a chance to let host retry the boot sequence.
          Currently only the SMC's vmwa may miss the first try and need a second
          chance.
        """
        raise NotImplementedError()


def get_platforms_details():
    """
    Gets the details of all platforms
    Returns:
      dict - key is the device class and value is the tuple of
             remote boot class, chassis class and vendor
    """
    from remote_boot_cimc import RemoteBootCIMC
    from remote_boot_idrac7 import RemoteBootIDRAC7
    from remote_boot_ilo import RemoteBootHPilo
    from remote_boot_imm import RemoteBootIMM2, RemoteBootASU
    from remote_boot_pxe import RemoteBootPXE
    from remote_boot_rmh import RemoteBootRMH
    from remote_boot_sim import RemoteBootSim
    from remote_boot_tsmm import RemoteBootTSMM
    from remote_boot_ucsm import RemoteBootUCSM
    from remote_boot_vmwa import RemoteBootVMWA
    from remote_boot_xcc import RemoteBootXCC
    from remote_boot_irmc import RemoteBootIRMC
    from remote_boot_inspur import RemoteBootInspur
    from remote_boot_ibmc import RemoteBootIbmc
    from remote_boot_intel import RemoteBootIntelBMC
    from imaging_step_type_detection import CLASS_IDRAC7, CLASS_IDRAC8, CLASS_IDRAC9, CLASS_ILO, CLASS_SMC_WA, CLASS_LENOVO_IMM2, CLASS_LENOVO_ASU, CLASS_LENOVO_TSMM, CLASS_LENOVO_XCC, CLASS_CIMC, CLASS_SIM, CLASS_UCSM, CLASS_VM_INSTALLER, CLASS_PXE, CLASS_PPC, CLASS_IRMC, CLASS_INSPUR, CLASS_IBMC, CLASS_INTELBMC
    platforms_map = {CLASS_UCSM: (
                  RemoteBootUCSM, 'CIMC', 'Cisco'), 
       CLASS_IDRAC7: (
                    RemoteBootIDRAC7, 'IDRAC7', 'Dell'), 
       CLASS_IDRAC8: (
                    RemoteBootIDRAC7, 'IDRAC7', 'Dell'), 
       CLASS_IDRAC9: (
                    RemoteBootIDRAC7, 'IDRAC9', 'Dell'), 
       CLASS_ILO: (
                 RemoteBootHPilo, 'ILO4', 'HP'), 
       CLASS_SMC_WA: (
                    RemoteBootVMWA, 'SMIPMI', 'Nutanix'), 
       CLASS_LENOVO_IMM2: (
                         RemoteBootIMM2, 'IMM2', 'Lenovo'), 
       CLASS_LENOVO_ASU: (
                        RemoteBootASU, 'IMM2', 'Lenovo'), 
       CLASS_LENOVO_TSMM: (
                         RemoteBootTSMM, 'TSMM', 'Lenovo'), 
       CLASS_LENOVO_XCC: (
                        RemoteBootXCC, 'TSMM', 'Lenovo'), 
       CLASS_CIMC: (
                  RemoteBootCIMC, 'CIMC', 'Cisco'), 
       CLASS_SIM: (
                 RemoteBootSim, None, None), 
       CLASS_PXE: (
                 RemoteBootPXE, None, None), 
       CLASS_PPC: (
                 RemoteBootRMH, 'SMIPMI', 'Nutanix'), 
       CLASS_IRMC: (
                  RemoteBootIRMC, 'IRMC', 'Fujitsu'), 
       CLASS_INSPUR: (
                    RemoteBootInspur, 'INSPUR', 'Inspur'), 
       CLASS_IBMC: (
                  RemoteBootIbmc, 'IBMC', 'Huawei'), 
       CLASS_INTELBMC: (
                      RemoteBootIntelBMC, 'INTELBMC', 'Intel')}
    if platform.system() != 'Linux':
        platforms_map[CLASS_SMC_WA] = (RemoteBootRMH, 'SMIPMI', 'Nutanix')
    return platforms_map


def new_remote_boot_instance(node_config):
    """
    Create new RemoteBoot instance with appropriate derived class.
    """
    from imaging_step_type_detection import CLASS_VM_INSTALLER
    platforms_map = get_platforms_details()
    if node_config.type == CLASS_VM_INSTALLER:
        raise StandardError('IPMI is not used in the context of FIELD VM')
    else:
        if node_config.type not in platforms_map.keys():
            raise StandardError('Unsupported node type: %s' % node_config.type)
    return platforms_map[node_config.type][0](node_config)