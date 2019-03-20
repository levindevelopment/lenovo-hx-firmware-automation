# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/lenovo_util.py
# Compiled at: 2019-02-15 12:42:10
import logging, time, traceback, pyghmi.ipmi.command as cmd
from pyghmi.exceptions import IpmiException
from threading import Lock
logger = logging.getLogger('lenovo_util')
PYGHMI_LOCK = Lock()
CLASS_LENOVO_IMM2 = 'lenovo_imm2'
CLASS_LENOVO_ASU = 'lenovo_asu'
CLASS_LENOVO_TSMM = 'lenovo_tsmm'
CLASS_LENOVO_XCC = 'lenovo_xcc'
CLASS_LENOVO_GENERIC = 'lenovo_generic'
CLASS_IPMI_GENERIC = 'ipmi_generic'
UEFI = 0
LEGACY = 1
type_map = {7154: CLASS_IPMI_GENERIC, 
   19046: CLASS_LENOVO_GENERIC, 
   20301: CLASS_LENOVO_IMM2}

def get_boot_mode_str(mode):
    """
    Returns the str value of boot mode
    """
    if mode == LEGACY:
        return 'legacy'
    if mode == UEFI:
        return 'uefi'
    return
    return


class LenovoUtil(object):

    def __init__(self, ipv4_addr, username, password, gateway=None, netmask=None, ipv6_addr=None, use_ipv6=False):
        self.ipv4_addr = ipv4_addr
        self.username = username
        self.password = password
        self.gateway = gateway
        self.netmask = netmask
        self.ipv6_addr = ipv6_addr
        self.use_ipv6 = use_ipv6
        self.session = None
        self.system_fru = None
        self._has_megarac = None
        self._hasxcc = None
        return

    def _catch_ipmi_exc(func):
        """
        Most of the exceptions thrown in the pyghmi module are of type
        IpmiException. Most of the Foundation code handles and expects
        exceptions of type StandardError.  This decorator will re-throw
        IpmiExceptions as StandardError exceptions for functions that use it.
        """

        def wrapped_func(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            except IpmiException:
                raise StandardError(traceback.format_exc())

        return wrapped_func

    def _connect(func):
        """
        A decorator function used to connect and verify a stable connection to the
        BMC before invoking other API calls.
        """

        def wrapped_func(self, *args, **kwargs):
            try:
                self.get_session()
                return func(self, *args, **kwargs)
            finally:
                self._logout()

        return wrapped_func

    def _logout(self):
        """
        Logout of session to BMC.
        """
        try:
            if self.session and self.session.ipmi_session.logged:
                with PYGHMI_LOCK:
                    self.session.ipmi_session.logout()
        except:
            logger.error('An error occurred when trying to logout of session: %s' % traceback.format_exc)

    @property
    def is_megarac(self):
        """
        This function will determine if the remote BMC has megarac functionality
        which currently is limited to only Lenovo 2U4N systems.
        """
        if self._has_megarac is not None:
            return self._has_megarac
        self.get_session()
        try:
            with PYGHMI_LOCK:
                rsp = self.session.xraw_command(netfn=50, command=126)
            if len(rsp['data'][:]) == 1 and rsp['data'][0] in ('\x00', '\x01'):
                self._has_megarac = True
        except IpmiException as e:
            if e.ipmicode == 193:
                self._has_megarac = False

        return self._has_megarac

    @property
    def is_xcc(self):
        """
        This function will determine if the remote BMC uses XCC
        """
        if self._hasxcc is not None:
            return self._hasxcc
        self.get_session()
        try:
            with PYGHMI_LOCK:
                rsp = self.session.xraw_command(netfn=58, command=193)
                if len(rsp['data'][:]) != 3:
                    self._hasxcc = False
                else:
                    rdata = bytearray(rsp['data'][:])
                    self._hasxcc = rdata[1] & 16 == 16
        except IpmiException as e:
            self._hasxcc = False

        return self._hasxcc

    def get_session(self, tries=3):
        """
        Creates a pyghmi IPMI session with the remote BMC.
        """
        self.session = None
        if self.use_ipv6:
            addr = self.ipv6_addr
        else:
            addr = self.ipv4_addr
        while self.session is None:
            try:
                with PYGHMI_LOCK:
                    self.session = cmd.Command(addr, self.username, self.password)
                    self.session.oem_init()
                    self.session.register_key_handler(lambda x: True)
            except IpmiException as e:
                self.session = None
                logger.error('Error attempting connection to Lenovo BMC (%s): %s' % (
                 addr, str(e)))
                tries -= 1
                if not tries:
                    raise StandardError(str(e))

        return

    @_catch_ipmi_exc
    @_connect
    def get_identity(self):
        """
        Obtains the specific identity of the remote system which can have an impact
        as to what virtual media method should be used.
        """
        with PYGHMI_LOCK:
            self.system_fru = self.session.get_inventory_of_component('System')
        if not self.system_fru:
            return
        mfg_id = self.system_fru['Manufacturer ID']
        logger.info('Manufacturer ID = %s' % mfg_id)
        system_type = type_map.get(mfg_id)
        if system_type == CLASS_LENOVO_GENERIC:
            if self.is_megarac:
                system_type = CLASS_LENOVO_TSMM
            elif self.is_xcc:
                system_type = CLASS_LENOVO_XCC
            else:
                system_type = CLASS_LENOVO_IMM2
        if system_type == CLASS_IPMI_GENERIC:
            if self.is_megarac:
                system_type = CLASS_LENOVO_TSMM
            elif self.is_xcc:
                system_type = CLASS_LENOVO_XCC
        return system_type

    @_catch_ipmi_exc
    @_connect
    def get_fru(self):
        """
        Obtains the specific identity of the remote system which can have an impact
        as to what virtual media method should be used.
        """
        with PYGHMI_LOCK:
            self.system_fru = self.session.get_inventory_of_component('System')
        return self.system_fru

    @_catch_ipmi_exc
    def set_ipv4_config(self, gateway, netmask, use_ipv6=True):
        """
        Set target boot device. In order to set the IPv4 address config via the
        BMC's IPv6 address the caller must pass the IPv6 address, netmask and
        gateway to the LenovoUtil class constructor along with setting
        the use_ipv6 flag.
        """
        self.use_ipv6 = use_ipv6
        if use_ipv6 and not self.ipv6_addr:
            msg = 'ipv6_addr must be set in the constructor when using the use_ipv6 flag.'
            logger.error(msg)
            raise StandardError(msg)
        self.get_session(tries=2)
        cidr_netmask = sum([ bin(int(x)).count('1') for x in netmask.split('.') ])
        cidr_addr = '%s/%s' % (self.ipv4_addr, cidr_netmask)
        with PYGHMI_LOCK:
            self.session.set_net_configuration(ipv4_address=cidr_addr, ipv4_configuration='static', ipv4_gateway=gateway)
        self.use_ipv6 = False
        self.get_session(tries=10)

    @_catch_ipmi_exc
    @_connect
    def set_boot_device(self, device, uefiboot=False):
        """
        Set target boot device.
        """
        logger.info("Setting boot device as '%s'" % device)
        with PYGHMI_LOCK:
            ret = self.session.set_bootdev(device, uefiboot=uefiboot)
        if 'error' in ret:
            logger.error('Error occured while setting boot device: %s' % ret['error'])
            raise StandardError(ret['error'])
        logger.info('Boot device set successfully: %s' % ret)

    @_catch_ipmi_exc
    @_connect
    def set_power(self, action):
        """
        Set power action of node.
        """
        logger.info("Executing power action '%s' on node '%s'." % (
         action, self.ipv4_addr))
        with PYGHMI_LOCK:
            self.session.set_power(action)

    @_connect
    def attach_media(self, nfs_path, tries=3):
        """
        Attach virtual media to node."
        """
        logger.info("Attaching virtual media @ '%s'." % nfs_path)
        success = False
        while not success:
            try:
                with PYGHMI_LOCK:
                    self.session.attach_remote_media(nfs_path)
                success = True
            except IpmiException as e:
                logger.error('Error occured during virtual media mount: %s' % str(e))
                tries -= 1
                if not tries:
                    raise StandardError(str(e))
                time.sleep(5)

    @_catch_ipmi_exc
    @_connect
    def detach_media(self):
        logger.info('Detaching virtual media')
        with PYGHMI_LOCK:
            self.session.detach_remote_media()