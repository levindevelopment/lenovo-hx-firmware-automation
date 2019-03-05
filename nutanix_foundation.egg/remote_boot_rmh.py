# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/remote_boot_rmh.py
# Compiled at: 2019-02-15 12:42:10
import logging, os, time, threading, select, subprocess, signal, platform, folder_central
from foundation.foundation_tools import DEVNULL, CREATE_NO_WINDOW
from foundation.portable import is_mac, is_win
from foundation.remote_boot_vmwa import RemoteBootVMWA
from foundation import ipmi_util
TICK = 5
BMC_RESET_TIMEOUT_S = TICK * 60
POWER_DOWN_RETRY = 1
MOUNT_TIMEOUT = 70
logger = logging.getLogger(__name__)

class RemoteMediaHelper(object):

    def __init__(self):
        self._proc = None
        self._iso = None
        self._lock = threading.Lock()
        return

    def wait_for(self, iso, timeout=MOUNT_TIMEOUT):
        """ wait for the iso to be mounted """
        if not is_mac():
            time.sleep(TICK)
            return
        st = time.time()
        while time.time() < st + timeout:
            if self._proc.poll() is not None:
                break
            logger.debug('[%s/%ss] waiting for iso %s to be mounted', int(time.time() - st), timeout, iso)
            sel_out, _, _ = select.select([self._proc.stdout], [], [], TICK)
            if not sel_out:
                continue
            line = self._proc.stdout.readline()
            if iso in line:
                return

        raise StandardError('failed to mount iso %s' % iso)
        return

    def mount(self, node_config, iso):
        with self._lock:
            if not self._proc:
                java = 'java'
                rmh_path = folder_central.get_smc_rmh_path()
                env = os.environ.copy()
                env['PATH'] = os.path.dirname(java) + ';' + env.get('PATH')
                extra_args = {}
                if is_win():
                    extra_args['stdin'] = DEVNULL
                    extra_args['creationflags'] = CREATE_NO_WINDOW
                self._proc = subprocess.Popen([
                 java,
                 '-Djava.library.path=' + os.path.dirname(rmh_path),
                 '-jar', 'RemoteMediaHelper.jar',
                 node_config.ipmi_ip,
                 node_config.ipmi_user,
                 node_config.ipmi_password, iso], cwd=os.path.dirname(folder_central.get_smc_rmh_path()), stdout=subprocess.PIPE, stderr=subprocess.PIPE, **extra_args)
                self.wait_for(iso)
                if self._proc.poll():
                    msg = 'Mount failed with error %s, error code %s' % (
                     self._proc.returncode, self._proc.communicate())
                    self._proc = None
                    self._iso = None
                    raise StandardError(msg)
                else:
                    self._iso = iso
            else:
                raise StandardError('Already mounted iso: %s', self._iso)
        return

    def umount(self):
        with self._lock:
            if not self._proc:
                logger.warn('not mounted yet, ignoring umount')
            else:
                if platform.system() == 'Windows':
                    self._proc.terminate()
                else:
                    self._proc.send_signal(signal.SIGINT)
                self._proc.wait()
                self._proc = None
                self._iso = None
        return


class RemoteBootRMH(RemoteBootVMWA):

    def __init__(self, *args, **kwargs):
        super(RemoteBootRMH, self).__init__(*args, **kwargs)
        self.rmh = RemoteMediaHelper()

    def reset_bmc(self):
        raise NotImplementedError

    def boot(self, iso, do_reset=True):
        logger = self.node_config.get_logger()
        logger.info('Starting SMCIPMITool')
        self.boot_from_iso(iso)

    def boot_from_iso(self, iso):
        """
        Poweroff node, unmount isos, mount iso, set boot order and power on.
        """
        logger = self.node_config.get_logger()
        logger.info('Detecting power status')
        self.poweroff()
        logger.info('Attaching virtual media: %s', iso)
        self.rmh.mount(self.node_config, iso)
        logger.info('Setting cdrom as boot device for next boot')
        with ipmi_util.ipmi_context(self.node_config) as (ipmi):
            bootdev = ipmi.set_bootdev('optical')
            logger.info('Next boot device is set to %s', bootdev['bootdev'])
        with ipmi_util.ipmi_context(self.node_config) as (ipmi):
            powerstate = ipmi.get_power()['powerstate']
        logger.info('Power status is %s', powerstate)
        if powerstate != 'off':
            raise StandardError('Power status should be off,please check BMC status and retry to image again')
        logger.info('Powering up node')
        with ipmi_util.ipmi_context(self.node_config) as (ipmi):
            ipmi.set_power('on', wait=True)
        logger.info('Sleeping for 40 seconds')
        time.sleep(40)
        with ipmi_util.ipmi_context(self.node_config) as (ipmi):
            powerstate = ipmi.get_power()['powerstate']
        logger.info('Power status is %s', powerstate)
        if powerstate != 'on':
            raise StandardError('Power status should be on, please check BMC status and retry to image again')
        logger.info('BMC should be booting into phoenix')

    def stop(self):
        logger = self.node_config.get_logger()
        logger.info('Exiting SMCIPMITool')
        self.rmh.umount()