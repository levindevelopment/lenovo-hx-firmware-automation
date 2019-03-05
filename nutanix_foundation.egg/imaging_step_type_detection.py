# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_type_detection.py
# Compiled at: 2019-02-15 12:42:10
import os, pexpect, re, time, traceback, factory_mode, folder_central, foundation_tools, imaging_context, ipmi_util, racadm, remote_boot_cimc, remote_boot_ilo, remote_boot_ucsm, remote_boot_vmwa, remote_boot_inspur, remote_boot_ibmc, remote_boot_intel
from foundation.consts import ARCH_PPC, ARCH_X86
from foundation.ironwood import FujitsuEmptyResponseException
from foundation.ironwood import FujitsuIRMC, FujitsuAuthException
from imaging_step import ImagingStepNodeTask
from lenovo_util import LenovoUtil, CLASS_LENOVO_IMM2, CLASS_LENOVO_TSMM, CLASS_LENOVO_XCC, CLASS_LENOVO_ASU
from foundation.cvm_utilities import detect_remote_arch
from foundation.portable import is_portable
RESULT_SUCCESS = 'ok'
RESULT_NETWORK = 'network_error'
RESULT_AUTHENTICATION = 'auth_error'
RESULT_UNSUPPORTED = 'class_not_supported'
RESULT_MISSING_LENOVO_LIBS = 'missing_lenovo_libs'
RESULT_UNKNOWN = 'class_not_known'
CLASS_CIMC = 'cimc'
CLASS_SMC_WA = 'smc_wa'
CLASS_SMC_W = 'smc_w'
CLASS_QUANTA = 'quanta'
CLASS_IDRAC7 = 'idrac7'
CLASS_IDRAC8 = 'idrac8'
CLASS_IDRAC9 = 'idrac9'
CLASS_SIM = 'unit_test'
CLASS_ILO = 'ilo'
CLASS_UCSM = 'ucsm'
CLASS_VM_INSTALLER = 'vm_installer'
CLASS_PXE = 'pxe'
CLASS_PPC = 'ppc64le'
CLASS_IRMC = 'irmc'
CLASS_INSPUR = 'inspur'
CLASS_IBMC = 'ibmc'
CLASS_INTELBMC = 'intelbmc'
STATE_TYPE_DETECTION = 'Detecting model of nodes - please be patient'
STATE_TYPE_DETECTION_DONE = 'Vendor detection complete'
ILO_VER_RE = re.compile('MANAGEMENT_PROCESSOR = "(\\w+)"')
ILO_TYPE_DETECTION_TIMEOUT_S = 10

def detect_if_cvm_or_phoenix(node_config):
    user_marker = [
     ('nutanix', '/etc/nutanix/release_version'),
     ('root', '/phoenix/layout/layout_finder.py')]
    for user, marker in user_marker:
        _, _, ret = foundation_tools.ssh(node_config, node_config.phoenix_ip, command=[
         'test', '-f', marker], user=user, throw_on_error=False, log_on_error=False)
        if not ret:
            node_config.arch = detect_remote_arch(node_config)
            return True

    return False


def detect_device_type(node_config):
    """
      Attempts to detect target device class. First IPMI 'fru' command is
      performed. If this fails, racadm is tried for Dell systems that
      don't have IPMI configured.
    
      Returns the following tuple:
         result: RESULT_SUCCESS, RESULT_NETWORK, RESULT_UNKNOWN or
                 RESULT_AUTHENTICATION
         class: device class used in foundation
    """
    ipmi_ip = node_config.ipmi_ip
    ipmi_user = node_config.ipmi_user
    ipmi_password = node_config.ipmi_password
    logger = node_config.get_logger()

    def format_message(cmd, stdout, stderr, ret):
        return "Command '%s' returned stdout: \n%s\nstderr: \n%s\nreturn code: %s\n" % (
         cmd, stdout, stderr, ret)

    logger.info('Attempting to detect device type on %s' % ipmi_ip)
    logger.debug('factory mode is %s' % factory_mode.factory_mode())
    ipmi_network_issue = False
    racadm_network_issue = False
    imm_network_issue = False
    node_config.arch = ARCH_X86
    if not factory_mode.factory_mode():
        if getattr(node_config, 'ucsm_managed_mode', None):
            ucsm = remote_boot_ucsm.CiscoUCSM(node_config.ucsm_ip, node_config.ucsm_user, node_config.ucsm_password)
            try:
                ucsm.login()
                return (
                 RESULT_SUCCESS, CLASS_UCSM)
            except:
                err = traceback.format_exc()
                if 'Authentication failed' in err:
                    return (RESULT_AUTHENTICATION, None)
                logger.exception('Unable to log in to management server. Ensure that the management server ip (%s) is correct and reachable from Foundation VM' % node_config.ucsm_ip)
                raise

        logger.info('Checking if this is Quanta')
        stdout, stderr, ret = foundation_tools.ipmitool(node_config, ['fru'], throw_on_error=False)
        if not ret:
            if 'quanta' in stdout.lower():
                return (RESULT_UNSUPPORTED, CLASS_QUANTA)
        logger.info('Checking if this is Intel')
        intel_bmc = remote_boot_intel.IntelBMC(ipmi_ip, ipmi_user, ipmi_password, logger)
        if intel_bmc.is_Intel():
            return (RESULT_SUCCESS, CLASS_INTELBMC)
        logger.info('Checking if this is an Ironwood system.')
        irmc = FujitsuIRMC(ipmi_ip, ipmi_user, ipmi_password)
        try:
            irmc.get_version()
            return (
             RESULT_SUCCESS, CLASS_IRMC)
        except FujitsuAuthException:
            return (
             RESULT_AUTHENTICATION, None)
        except FujitsuEmptyResponseException:
            pass
        except StandardError:
            pass
        else:
            logger.info('Checking if this is a Lenovo system.')
            lnvo = LenovoUtil(ipmi_ip, ipmi_user, ipmi_password)
            identity = None
            try:
                identity = lnvo.get_identity()
            except StandardError as e:
                errstr = str(e)
                if 'Incorrect password provided' in errstr:
                    return (RESULT_AUTHENTICATION, None)
                if 'Unauthorized name in RAKP2' in errstr:
                    return (RESULT_AUTHENTICATION, None)
                if 'timeout' in errstr:
                    imm_network_issue = True
            else:
                if identity in [CLASS_LENOVO_XCC, CLASS_LENOVO_TSMM]:
                    return (RESULT_SUCCESS, identity)
                if identity in [CLASS_LENOVO_IMM2]:
                    return (RESULT_SUCCESS, CLASS_LENOVO_ASU)
                logger.info('Checking if this is UCS standalone node')
                cimc = remote_boot_cimc.CiscoCIMC(ipmi_ip, ipmi_user, ipmi_password)
                try:
                    cimc.login()
                    return (
                     RESULT_SUCCESS, CLASS_CIMC)
                except:
                    err = traceback.format_exc()
                    if 'Authentication failed' in err:
                        return (RESULT_AUTHENTICATION, None)
                else:
                    logger.info('Checking if this is Dell')
                    stdout, stderr, ret = racadm.execute(node_config, cmd_list=['get', 'iDrac.Info.Type'], throw_on_error=False)
                    if stderr:
                        if stderr.count('invalid username or password'):
                            return (
                             RESULT_AUTHENTICATION, None)
                        racadm_network_issue = stderr.count('Unable to connect to RAC at specified IP address') > 0
                    if stdout:
                        for line in stdout.splitlines():
                            p = line.find('=')
                            if p < 0:
                                continue
                            name = line[:p].strip()
                            value = line[p + 1:].strip()
                            if name == 'Type':
                                for expected_type in ['32', '34']:
                                    if expected_type in value:
                                        return (RESULT_SUCCESS, CLASS_IDRAC8)

                                for expected_type in ['16']:
                                    if expected_type in value:
                                        return (RESULT_SUCCESS, CLASS_IDRAC7)

                                for expected_type in ['14G']:
                                    if expected_type in value:
                                        return (RESULT_SUCCESS, CLASS_IDRAC9)

                    try:
                        identity = ipmi_util.get_identity(node_config)
                        if identity == 11183:
                            return (RESULT_SUCCESS, CLASS_PXE)
                    except StandardError:
                        pass

                    logger.info('Checking if this is HPE or NEC or HITACHI')
                    try:
                        hpilo = remote_boot_ilo.HPilo(ipmi_ip, ipmi_user, ipmi_password, logger)
                        manufacturer = hpilo.isHPE_OEM()
                        if manufacturer in ('HPE', 'NEC', 'HITACHI'):
                            logger.debug('It is %s node' % manufacturer)
                            return (
                             RESULT_SUCCESS, CLASS_ILO)
                    except:
                        err = traceback.format_exc()
                        if 'Authentication failed' in err:
                            return (RESULT_AUTHENTICATION, None)

                logger.info('Checking if this is HUAWEI')
                try:
                    ibmc = remote_boot_ibmc.Huawei(ipmi_ip, ipmi_user, ipmi_password, logger)
                    manufacturer = ibmc.get_manufacturer()
                    if manufacturer.lower() in ('huawei', ):
                        logger.debug('It is %s node' % manufacturer)
                        return (
                         RESULT_SUCCESS, CLASS_IBMC)
                except:
                    err = traceback.format_exc()
                    if 'Authentication failed' in err:
                        return (RESULT_AUTHENTICATION, None)

            logger.info('Checking if this is Inspur')
            try:
                inspur = remote_boot_inspur.InspurAPI(ipmi_ip, ipmi_user, ipmi_password, logger)
                if inspur.is_Inspur():
                    logger.debug('It is Inspur node')
                    return (
                     RESULT_SUCCESS, CLASS_INSPUR)
            except:
                err = traceback.format_exc()
                if 'Authentication failed' in err:
                    return (RESULT_AUTHENTICATION, None)

    if detect_if_ppc_node(node_config):
        node_config.arch = ARCH_PPC
        return (
         RESULT_SUCCESS, CLASS_PPC)
    if is_portable():
        logger.info('Checking if this is SMC from Board manufacturer')
        if detect_if_smc_board(node_config):
            return (RESULT_SUCCESS, CLASS_SMC_WA)
    logger.info('Checking if this is SMC')
    for _ in range(2):
        smc_ipmi_dir = os.path.dirname(folder_central.get_smc_ipmitool_path())
        process = pexpect.spawn('java -Djava.library.path=%s -jar %s %s %s %s shell' % (
         smc_ipmi_dir, folder_central.get_smc_ipmitool_path(),
         ipmi_ip,
         ipmi_user,
         ipmi_password), cwd=smc_ipmi_dir)
        try:
            process.expect_exact(remote_boot_vmwa.VMWA_PROMPTS, 30)
            try:
                process.close()
            except:
                pass
            else:
                if 'Cannot login' in process.before:
                    return (
                     RESULT_AUTHENTICATION, None)

            return (
             RESULT_SUCCESS, CLASS_SMC_WA)
        except pexpect.TIMEOUT:
            logger.debug('Got a pexpect.TIMEOUT exception with process.before = %s' % process.before)
            if 'Cannot connect to %s' % ipmi_ip in process.before:
                ipmi_network_issue = True
                break
            if 'SIM(W)' in process.before:
                return (RESULT_UNSUPPORTED, CLASS_SMC_W)
            if 'Cannot login' in process.before:
                if 'com.supermicro.ipmi.IPMIOEMCommand.getBoardModel' in process.before:
                    break
                return (
                 RESULT_AUTHENTICATION, None)
        else:
            time.sleep(5)

    if ipmi_network_issue and (factory_mode.factory_mode() or racadm_network_issue and imm_network_issue):
        return (RESULT_NETWORK, None)
    return (RESULT_UNKNOWN, None)


def detect_if_smc_board(node_config):
    fru = ipmi_util.get_system_fru(node_config)
    if 'Supermicro' == fru.get('Board manufacturer', None):
        return True
    return


def detect_if_ppc_node(node_config):
    stdout, stderr, ret = foundation_tools.ipmitool(node_config, ['fru'], throw_on_error=False)
    if not ret and re.search('Board Part Number\\s+:.*P8DTU', stdout):
        return True
    return False


def error_message(result, ipmi_ip):
    if result == RESULT_UNKNOWN:
        return "Foundation couldn't tell the vendor of node you're trying to image at %s. Please check that Foundation is up to date and that you're imaging supported hardware. If you are sure that the vendor is supported, perform a BMC reset and try again" % ipmi_ip
    if result == RESULT_AUTHENTICATION:
        return "Foundation couldn't log in to the IPMI interface with the credentials you supplied at %s. Please double-check your IPMI username and password" % ipmi_ip
    if result == RESULT_NETWORK:
        return "Foundation couldn't reach the IPMI interface at %s. Please double-check your IP addresses and network setup." % ipmi_ip
    if result == RESULT_UNSUPPORTED:
        return 'Foundation is not supported for this platform'
    if result != RESULT_SUCCESS:
        return 'Foundation failed to detect node type at %s.' % ipmi_ip


class ImagingStepTypeDetection(ImagingStepNodeTask):

    def run(self):
        logger = self.logger
        context = imaging_context.get_context()
        if context == imaging_context.FIELD_VM:
            logger.info('Running in CVM, type_detection is a no-op')
            self.config.type = CLASS_VM_INSTALLER
            return
        if context == imaging_context.FIELD_IPMI and getattr(self.config, 'device_hint', None) == 'vm_installer':
            logger.debug('Trying to use CVM/Phoenix to start imaging')
            if detect_if_cvm_or_phoenix(self.config):
                logger.info('CVM/Phoenix detected, using it to continue imaging')
                self.config.type = CLASS_VM_INSTALLER
                return
            logger.info('CVM/Phoenix is not running, trying IPMI')
        result, device_class = (None, None)
        try:
            result, device_class = detect_device_type(self.config)
        except:
            logger.exception('Exception in detect_device_type')

        if result != RESULT_SUCCESS:
            message = error_message(result, self.config.ipmi_ip)
            logger.fatal(message)
            raise StandardError(message)
        logger.info('Detected class %s for node with IPMI IP %s' % (
         device_class, self.config.ipmi_ip))
        self.config.type = device_class
        return