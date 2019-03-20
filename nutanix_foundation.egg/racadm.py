# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/racadm.py
# Compiled at: 2019-02-15 12:42:10
import re, time
from foundation import folder_central
from foundation.foundation_tools import system
BOOT_MODE_REGEX = re.compile('BootMode=(\\S+)')
BOOT_SEQ_HDD_PARSER = re.compile('HddSeq=(.+)')
SYSTEM_MODEL_REGEX = re.compile('System Model\\s*=\\s*(\\S+.*)')
TABLE_KEY_VALUE = re.compile('(\\S+.*)\\s*=\\s*(\\S+.*)')
JOB_STATUS_RE = re.compile('Status=(\\S+)')
COMMIT_JID_RE = re.compile('Commit JID\\s*=\\s*(\\S+)')
IDRAC_VERSION_RE = re.compile('Version=(\\S+)')
POLLING_ATTEMPTS = 120

def execute_with_retry(node_config, cmd_list, throw_on_error=True, retries=5, delay_s=5):
    """
    Executes a racadam command with retries.
    
    Args:
      node_config: NodeConfig object
      cmd_list(list): command to execute represented as a list of string args
      throw_on_error: throw error on exception or return stdout,stderr,ret
      retries: Number of times to retry a command.
      delay_s: Wait time between retries.
    
    Returns:
      (stdout, stderr, return_code)
    
    Raises:
      (StandardError)
    
    """
    while True:
        try:
            stdout, stderr, return_code = execute(node_config, cmd_list, throw_on_error=throw_on_error)
            if return_code == 0 or retries == 0:
                return (stdout, stderr, return_code)
        except Exception as e:
            if retries == 0:
                if throw_on_error:
                    raise e
                return (str(e), str(e), 1)
        else:
            retries -= 1
            time.sleep(delay_s)


def execute(node_config, cmd_list, throw_on_error=True, log_on_error=False):
    """
    Executes a racadm command for a node.
    
    Args:
      node_config: NodeConfig object
      cmd_list(list): command to execute represented as a list of string args
      throw_on_error: throw error on exception or return stdout,stderr,ret
    
    Returns:
      (stdout, stderr, return_code)
    
    Raises:
      (StandardError)
    
    """
    cmd = [
     folder_central.get_dell_racadm_path(),
     '-r', node_config.ipmi_ip,
     '-u', node_config.ipmi_user,
     '-p', node_config.ipmi_password] + cmd_list
    return system(node_config, cmd, throw_on_error=throw_on_error, log_on_error=log_on_error, timeout=60, log_command=False)


def get_biosbootsettings_bootmode(node_config):
    """
    Fetches the boot mode from iDrac.
    
    Args:
      node_config: NodeConfig object
    
    Returns:
      (str): boot mode, e.g. Bios, UEFI
    
    Raises:
      (StandardError): If the command fails to execute.
    
    """
    cmd_list = [
     'get', 'bios.biosbootsettings.BootMode']
    stdout, _, _ = execute_with_retry(node_config, cmd_list)
    reg_result = BOOT_MODE_REGEX.search(stdout)
    if not reg_result:
        raise StandardError("Couldn't parse BootMode from racadm output: %s" % stdout)
    return reg_result.groups()[0].strip()


def set_biosbootsettings_bootmode(node_config, boot_mode='Bios'):
    """
    Sets the boot mode. A cold reboot is required for the settings to take effect.
    This method doesn't take care of the reboot in order to allow user to bundle
    multiple iDrac settings in one reboot.
    
    Args:
      node_config: NodeConfig object
      boot_mode(str): "BIOS", "UEFI" etc.
    
    Returns:
      None on success.
    
    Raises:
      (StandardError): Upon failure to execute command.
    
    """
    cmd_list = [
     'set', 'bios.biosbootsettings.BootMode', boot_mode]
    _, _, _ = execute_with_retry(node_config, cmd_list)


def get_hwinventory(node_config):
    """
    Gets hardware inventory from iDrac.
    
    Args:
      node_config: NodeConfig object
    
    Returns:
      (list(dict)): list of hardware inventory dictionaries.
    
    Raises:
      (StandardError): upon failure to execute command
    """
    cmd_list = [
     'hwinventory']
    stdout, _, _ = execute_with_retry(node_config, cmd_list)
    return parse_hardware_inventory(stdout)


def parse_hardware_inventory(inventory):
    """
    Parses the iDrac hwinventory output.
    
    Args:
      inventory(str): stdout from racadm hwinventory.
    
    Returns:
      (list(dict)): list of hardware inventory dictionaries.
    
    """
    parsed_inventory = []
    device = {}
    for line in inventory.splitlines():
        instance_id_match = line.startswith('[InstanceID:')
        key_match_result = TABLE_KEY_VALUE.match(line)
        if instance_id_match or key_match_result:
            if instance_id_match:
                if device:
                    parsed_inventory.append(device)
                device = {}
            else:
                key = key_match_result.groups()[0].strip()
                value = key_match_result.groups()[1].strip()
                device[key] = value

    if device:
        parsed_inventory.append(device)
    return parsed_inventory


def get_harddrive_boot_seq(node_config):
    """
    Gets the hardrive boot sequence
    
    Args:
      node_config: NodeConfig object
    
    Returns:
      (list): Current boot order for harddrives.
              e.g. ["Disk.SDInternal.1-1", "NonRAID.Integrated.1-1"]
    
    Raises:
      (StandardError): upon failure to execute command
    
    """
    cmd_list = [
     'get', 'bios.BiosBootSettings.HddSeq']
    stdout, _, _ = execute_with_retry(node_config, cmd_list)
    re_result = BOOT_SEQ_HDD_PARSER.search(stdout)
    if not re_result:
        raise StandardError("Couldn't parse HDD boot sequence from iDrac output: %s" % stdout)
    hdd_seq_str = re_result.groups()[0]
    return hdd_seq_str.strip().split(',')


def set_harddrive_boot_seq(node_config, hdd_boot_seq):
    """
    Sets the harddrive boot sequence.
    
    Args:
      node_config: NodeConfig object
      hdd_boot_seq(list): e.g. ["Disk.SDInternal.1-1", "NonRAID.Integrated.1-1"]
    
    Returns:
      None on success.
    
    Raises:
      (StandardError): upon failure to execute command.
    
    """
    cmd_list = [
     'set', 'bios.BiosBootSettings.HddSeq', (',').join(hdd_boot_seq)]
    _, _, _ = execute_with_retry(node_config, cmd_list)


def get_model(node_config):
    """
    Gets the model string from iDrac.
    
    Args:
      node_config: NodeConfig object.
    
    Returns:
      (str): model (e.g. PowerEdge R630).
    
    Raises:
      (StandardError): upon failure to execute command.
    """
    cmd_list = [
     'getsysinfo']
    stdout, _, _ = execute_with_retry(node_config, cmd_list)
    re_result = SYSTEM_MODEL_REGEX.search(stdout)
    if not re_result:
        raise StandardError("Couldn't parse model from iDrac output: %s" % stdout)
    return re_result.groups()[0].strip()


def execute_bios_settings_reboot_job(node_config):
    logger = node_config.get_logger()
    logger.debug('Scheduling system reboot')
    stdout, _, _ = execute_with_retry(node_config, ['jobqueue', 'create', 'BIOS.Setup.1-1', '-r', 'pwrcycle',
     '-s', 'TIME_NOW', '-e', 'TIME_NA'])
    re_result = COMMIT_JID_RE.search(stdout)
    if not re_result:
        raise StandardError("Couldn't parse job id from output: %s" % stdout)
    commit_job_id = re_result.groups()[0].strip()
    poll_job_for_completion(node_config, commit_job_id)


def poll_job_for_completion(node_config, job_id):
    logger = node_config.get_logger()
    cmd_list = ['jobqueue', 'view', '-i', job_id]
    for i in range(POLLING_ATTEMPTS):
        logger.debug('[%s/%s] Polling job %s for completion' % (
         i, POLLING_ATTEMPTS, job_id))
        stdout, _, _ = execute_with_retry(node_config, cmd_list)
        re_result = JOB_STATUS_RE.search(stdout)
        if not re_result:
            continue
        job_status = re_result.groups()[0]
        if job_status == 'Completed':
            logger.debug('Job %s is complete' % job_id)
            break
        time.sleep(10)
    else:
        raise StandardError("Job %s didn't finish in time." % job_id)


def get_idrac_firmware_version(node_config):
    """
    Get version number of iDrac
    
    Args:
      node_config: NodeConfig object.
    
    Returns:
      (list(int)): e.g. [3, 0, 0, 0]
    
    """
    logger = node_config.get_logger()
    stdout, _, _ = execute_with_retry(node_config, ['get', 'iDrac.Info.Version'])
    re_result = IDRAC_VERSION_RE.search(stdout)
    if not re_result:
        raise StandardError('Unable to determine iDrac version')
    version = map(int, re_result.groups()[0].strip().split('.'))
    logger.info('iDRAC version: %s' % version)
    return version


def set_bios_property_if_required(node_config, property, new_value):
    """
    Sets property in bios to a given new_value if not already set.
    
    Args:
      node_config: NodeConfig object.
      property(str): bios property to set, e.g. bios.ProcSettings.ProcX2Apic.
      new_value(str): new value to set for the given property, e.g Enabled.
    
    Returns:
      (bool): True if a change was required and successfully made, False if a
      change wasn't required.
    
    Raises:
      (StandardError): upon failure to execute command.
    """
    logger = node_config.get_logger()
    stdout, _, _ = execute_with_retry(node_config, ['get', property])
    key_in_output = property.split('.')[-1]
    reg_parser = re.compile('%s=(\\S+)' % key_in_output)
    re_result = reg_parser.search(stdout)
    if not re_result:
        raise StandardError('Unable to parse key %s in output %s' % (
         key_in_output, stdout))
    current_value = re_result.groups()[0].strip()
    logger.debug('Current value of %s is %s' % (property, current_value))
    if current_value != new_value:
        logger.debug('Setting value of %s to %s' % (property, new_value))
        cmd_list = ['set', property, new_value]
        _, _, _ = execute_with_retry(node_config, cmd_list)
        return True
    return False


def rac_reset(node_config):
    """
    Resets iDRAC, waits for it to come up.
    
    Args:
      node_config: Node Config Object
    
    Returns:
      None of success
    
    Raises:
      (StandardError): Upon failure.
    """
    execute_with_retry(node_config, ['racreset'])
    execute_with_retry(node_config, ['hwinventory'], retries=60, delay_s=10)