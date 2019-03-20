# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/remote_boot_vmwa.py
# Compiled at: 2019-02-15 12:42:10
import errno, os, pexpect, re, remote_boot_ipmi, time, traceback, foundation_tools, folder_central
from pyghmi.exceptions import IpmiException
from foundation import ipmi_util
VMWA_PROMPTS = [
 'SIM(WA)>', 'ASPD_T>', 'AST2500>']
BOARD_PART_NUMBER_RE = re.compile('Board Part Number\\s+:\\s+(\\S+)')
TICK = 5
BMC_RESET_TIMEOUT_S = TICK * 60
POWER_CHANGE_RETRY = 4

class RemoteBootVMWA(remote_boot_ipmi.RemoteBootIPMI):

    def __init__(self, node_config):
        remote_boot_ipmi.RemoteBootIPMI.__init__(self, node_config)
        self.process = None
        return

    def set_first_boot_device(self):
        """
          Set SATADOM as first boot device on SMC
          NOTE: this function is NOOP-ed since we could just set the CDROM as next
          boot device.
        """
        pass

    def shell_command(self, cmd, expected_text, timeout_s=60, retries=5):
        logger = self.node_config.get_logger()
        for retries in range(retries):
            try:
                self.process.sendline(cmd)
                self.process.expect_exact(VMWA_PROMPTS, timeout_s)
                if expected_text in self.process.before:
                    return self.process.before
                logger.info('Did not receive expected result "%s"; instead received\n%s' % (
                 expected_text,
                 self.process.before))
            except pexpect.ExceptionPexpect as e:
                logger.info('Pexpect took exception to something: %s.\nStack:\n%s' % (
                 str(e), traceback.format_exc()))
                logger.info('Before: %s\nAfter: %s' % (self.process.before,
                 self.process.after))
            else:
                time.sleep(TICK)
        else:
            raise StandardError('SMCIPMITool command failed multiple times. Here is the text of the shell session:\nBefore: %s\nAfter:%s' % (
             self.process.before, self.process.after))

    def retry_boot_from_iso(self, iso):
        logger = self.node_config.get_logger()
        logger.info('Retrying to boot from iso.')
        self.reset_bmc()
        self.boot_from_iso(iso)

    def reset_bmc(self):
        """
        Reset BMC and wait for it, update self.process after BMC is up
        """
        logger = self.node_config.get_logger()
        logger.info('Resetting BMC')
        with ipmi_util.ipmi_context(self.node_config) as (ipmi):
            ipmi.reset_bmc()
        time.sleep(TICK * 2)
        st = time.time()
        while 1:
            if time.time() - st < BMC_RESET_TIMEOUT_S:
                logger.debug('[%d/%ds] Waiting for BMC', time.time() - st, BMC_RESET_TIMEOUT_S)
                time.sleep(TICK)
                _, _, ret = foundation_tools.system(self.node_config, [
                 'ping', '-c3', '-W3', self.node_config.ipmi_ip], log_on_error=False, throw_on_error=False)
                if ret != 0:
                    continue
                time.sleep(TICK)
                logger.debug('Creating new shell for BMC')
                self.new_bmc_shell()
                logger.info('Reset BMC completed')
                break
        else:
            raise StandardError('Cannot reach BMC after reset')

    def boot(self, iso, do_reset=True):
        logger = self.node_config.get_logger()
        logger.info('Starting SMCIPMITool')
        for i in range(3):
            try:
                self.new_bmc_shell()
                self.boot_from_iso(iso)
                break
            except OSError as e:
                if e.errno == errno.EBADF:
                    logger.warn('ignore EBADF from pexpect, retrying')
                else:
                    raise

        else:
            raise StandardError('Failed to start SMCIPMITool')

    def new_bmc_shell(self, retry=5):
        """
        Spawn and return an new SMCIPMITool shell.
        """
        logger = self.node_config.get_logger()
        for _ in range(1 + retry):
            if getattr(self, 'process', None):
                try:
                    self.process.close(force=True)
                except Exception:
                    pass

            self.process = pexpect.spawn('java -Djava.library.path=%s -jar %s %s %s %s shell' % (
             os.path.dirname(folder_central.get_smc_ipmitool_path()),
             folder_central.get_smc_ipmitool_path(),
             self.node_config.ipmi_ip, self.node_config.ipmi_user,
             self.node_config.ipmi_password))
            try:
                self.process.expect_exact(VMWA_PROMPTS, 10)
                break
            except pexpect.TIMEOUT:
                logger.info('SMCIPMITool failed to start, retrying in 5 seconds')
                time.sleep(TICK)
                continue

        else:
            raise StandardError('SMCIPMITool failed to start - giving up')

        return

    def set_power(self, state, retry=POWER_CHANGE_RETRY):
        """
        This is a wrapper function for ipmi.set_power
        
        pyghmi 1.0.14+ will raise exception on error, this function will catch that
        exception and retry.
        """
        logger = self.node_config.get_logger()
        for attempt in range(retry):
            try:
                logger.debug('changing power state to %s, attempt %s/%s', state, attempt + 1, retry)
                with ipmi_util.ipmi_context(self.node_config) as (ipmi):
                    cur_state = ipmi.set_power(state, wait=True)['powerstate']
                    logger.info('changed power state to %s', cur_state)
                    return cur_state
            except IpmiException as e:
                logger.warn('failed to change power state, retrying: %s', e)
                time.sleep(TICK)

        else:
            raise StandardError('failed to change power state to %s', state)

    def poweroff(self):
        """
        Power off node and wait for power status changed to off
        
        This function will reset bmc on retry.
        """
        logger = self.node_config.get_logger()
        with ipmi_util.ipmi_context(self.node_config) as (ipmi):
            powerstate = ipmi.get_power()['powerstate']
        logger.info('current power state is %s', powerstate)
        if powerstate != 'off':
            try:
                return self.set_power('off')
            except StandardError:
                logger.warn('bmc seems not responding to power commands, will reset it and retry')

            self.reset_bmc()
            return self.set_power('off')
        return powerstate

    def get_vmwa_status(self):
        """
        Get vmwa status.
        """
        logger = self.node_config.get_logger()
        try:
            self.process.sendline('vmwa status')
            self.process.expect_exact(VMWA_PROMPTS, 60)
            logger.debug('vmwa status: %s, %s, %s', self.process.before, self.process.match, self.process.after)
            return self.process.before
        except pexpect.ExceptionPexpect:
            logger.error('vmwa status: %s, %s', self.process.before, self.process.after)
            logger.exception('pexpect raised exception')

        return ''

    def check_vmwa_mount(self, iso, retry=3):
        """
        Check if iso is mounted.
        """
        logger = self.node_config.get_logger()
        for i in range(retry):
            logger.debug('[%s/%s] Checking virtual media: %s', i + 1, retry, iso)
            vmwa_status = self.get_vmwa_status()
            if iso not in vmwa_status:
                logger.error('Foundation did not detect the iso in virtual media')
                logger.error('Foundation will check again in 10 seconds')
                time.sleep(10)
            else:
                logger.debug('Virtual media is mounted successfully: %s', iso)
                break
        else:
            message = 'Foundation did not detect the iso in the virtual media after multiple attempts. Reset BMC and try to image again.'
            logger.error(message)
            raise StandardError(message)

    def boot_from_iso(self, iso):
        """
        Poweroff node, unmount isos, mount iso, set boot order and power on.
        """
        logger = self.node_config.get_logger()
        self.poweroff()
        logger.info('Disconnecting virtual media')
        self.shell_command('vmwa dev2stop', 'done')
        logger.info('Attaching virtual media: %s', iso)
        try:
            self.shell_command('vmwa dev2iso %s' % iso, 'Device 2 :VM Plug-In OK!!', timeout_s=120)
        except StandardError as e:
            if 'Exist an effective Connect from others' in str(e):
                self.reset_bmc()
                self.shell_command('vmwa dev2iso %s' % iso, 'Device 2 :VM Plug-In OK!!', timeout_s=120)
            else:
                raise

        self.check_vmwa_mount(iso)
        logger.info('Setting cdrom as boot device for next boot')
        with ipmi_util.ipmi_context(self.node_config) as (ipmi):
            bootdev = ipmi.set_bootdev('optical')
            logger.info('Next boot device is set to %s', bootdev['bootdev'])
        with ipmi_util.ipmi_context(self.node_config) as (ipmi):
            powerstate = ipmi.get_power()['powerstate']
        logger.info('Power status is %s', powerstate)
        if powerstate != 'off':
            raise StandardError('Power status should be off,please check BMC status and retry to image again')
        self.set_power('on')
        logger.info('Sleeping for 40 seconds')
        time.sleep(40)
        self.check_vmwa_mount(iso)
        with ipmi_util.ipmi_context(self.node_config) as (ipmi):
            powerstate = ipmi.get_power()['powerstate']
        logger.info('Power status is %s', powerstate)
        if powerstate != 'on':
            raise StandardError('Power status should be on, please check BMC status and retry to image again')
        logger.info('BMC should be booting into phoenix')

    def stop(self):
        logger = self.node_config.get_logger()
        logger.info('Exiting SMCIPMITool')
        try:
            self.process.sendline('exit')
            self.process.wait()
        except OSError as e:
            if e.errno == errno.EBADF:
                logger.warn('Ignoring EBADF from pexpect: %s', e)
            else:
                raise