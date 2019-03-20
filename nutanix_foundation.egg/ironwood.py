# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/ironwood.py
# Compiled at: 2019-02-15 12:42:10
import base64, contextlib, httplib, json, logging, os, re, struct, time, lxml.etree
from foundation import folder_central
from foundation import foundation_tools
from foundation import ipmi_util
_LOG = logging.getLogger(__file__)
LEGACY_BOOT_SETTING = {'Server': {'SystemConfig': {'@Processing': 'execute', 
                               'BiosConfig': {'CsmConfig': {'LaunchCsmEnabled': True, 
                                                            'BootOptionFilter': 'LegacyOnly', 
                                                            'PxeOptionRomPolicy': 'LegacyOnly', 
                                                            'StorageOptionRomPolicy': 'LegacyOnly', 
                                                            'OtherPciDeviceRomPriority': 'LegacyOnly', 
                                                            'VideoOptionRomPolicy': 'LegacyOnly'}, 
                                              '@Version': '1.03'}}, 
              '@Version': '1.01'}}
ENDPOINT_BIOS_SETTING = '/rest/v1/Oem/eLCM/ProfileManagement/set'
ENDPOINT_SESSION_PROGRESS = '/sessionInformation/%s/status'
ENDPOINT_SESSION_REMOVE = '/sessionInformation/%s/remove'

class FujitsuAuthException(StandardError):
    pass


class FujitsuEmptyResponseException(StandardError):
    pass


class ScciShareType(object):
    __slots__ = []
    __name__ = 'integer'
    NFS = 0
    CIFS = 1
    __STR_INT_MAP__ = {'NFS': NFS, 'CIFS': CIFS}

    def __call__(self, value):
        if isinstance(value, basestring) and value in self.__STR_INT_MAP__:
            return self.__STR_INT_MAP__[value]
        try:
            value = int(value)
        except (TypeError, ValueError):
            pass

        if value not in [self.NFS, self.CIFS]:
            raise ValueError('Invalid ScciShareType %s' % value)
        return value


ScciShareType = ScciShareType()

class HTTPMethods(object):
    __slots__ = []
    DELETE = 'DELETE'
    GET = 'GET'
    HEAD = 'HEAD'
    OPTIONS = 'OPTIONS'
    PATCH = 'PATCH'
    POST = 'POST'
    PUT = 'PUT'

    def __iter__(self):
        return iter([self.DELETE, self.GET, self.HEAD, self.OPTIONS,
         self.PATCH, self.POST, self.PUT])


HTTPMethods = HTTPMethods()

class ScciConfigValue(object):
    """
    An SCCI Configuration Space Value.
    """
    __slots__ = [
     'command', 'value_id', 'data_type']

    def __init__(self, command, value_id, data_type):
        self.command = command
        self.value_id = '%X' % value_id
        self.data_type = data_type

    def to_command(self, value=None):
        if value is None:
            raise NotImplementedError('Only SET is currently implemented')
        return ScciSetConfigCommand.new(self, value)


class ScciOp(object):
    """
    An SCCI Command.
    """
    __slots__ = [
     'cmd_string', 'op_code', 'data_type']

    def __init__(self, cmd_string, op_code, data_type):
        self.cmd_string = cmd_string
        self.op_code = '%X' % op_code
        self.data_type = data_type

    def to_command(self, value):
        return ScciCommand.new(self, value)


class ScciOps(object):
    """
    SCCI Commands.
    """
    __slots__ = []
    BMC_VMEDIA_CONNECT = ScciOp('ConnectRemoteCdImage', 0, int)


ScciOps = ScciOps()

class ScciConfigValues(object):
    __slots__ = []
    BMC_IPV4_ENABLED = ScciConfigValue('ConfBmcIpv4Enabled', 6689, int)
    BMC_IPV4_IP = ScciConfigValue('ConfBMCIpAddr', 5184, str)
    BMC_NETMASK = ScciConfigValue('ConfBMCNetmask', 5185, str)
    BMC_GATEWAY = ScciConfigValue('ConfBMCGateway', 5186, str)
    BMC_REMOTE_CD_SERVER = ScciConfigValue('ConfBmcRemoteCdImageServer', 6752, str)
    BMC_REMOTE_CD_USER = ScciConfigValue('ConfBmcRemoteCdImageUserName', 6753, str)
    BMC_REMOTE_CD_PASSWORD = ScciConfigValue('ConfBmcRemoteCdImageUserPassword', 6754, str)
    BMC_REMOTE_CD_DOMAIN = ScciConfigValue('ConfBmcRemoteCdImageUserDomain', 6755, str)
    BMC_REMOTE_CD_SHARE_TYPE = ScciConfigValue('ConfBmcRemoteCdImageShareType', 6756, ScciShareType)
    BMC_REMOTE_CD_SHARE_NAME = ScciConfigValue('ConfBmcRemoteCdImageShareName', 6757, str)
    BMC_REMOTE_CD_IMG_NAME = ScciConfigValue('ConfBmcRemoteCdImageImageName', 6758, str)
    BMC_VMEDIA_OPT_CD_NUM = ScciConfigValue('ConfBmcMediaOptionsCdNumber', 6760, int)
    BMC_VMEDIA_ENABLED = ScciConfigValue('ConfBmcMediaOptionsRemoteMediaEnabled', 6784, int)


ScciConfigValues = ScciConfigValues()

class ScciResponseLookup(lxml.etree.CustomElementClassLookup):
    """
    Custom XML element lookup unmarshaling <Status> elements to 'ScciStatus'.
    """

    def lookup(self, node_type, document, namespace, name):
        if name == 'Status':
            return ScciStatus
        return


class ScciElement(lxml.etree.ElementBase):
    """
    Base for any SCCI XML element classes.
    """

    @classmethod
    def get_attrib(cls):
        return {}

    def _init(self):
        for key, val in self.get_attrib().iteritems():
            self.set(key, val)

    def to_string(self):
        return lxml.etree.tostring(self, encoding=unicode)


class ScciStatus(ScciElement):
    """
    Class representing responses to SCCI commands.
    """

    def format_error(self, details=False, verbose=False):
        ret = ['%s (%s): %s' % (self.rv, self.severity.title(), self.message)]
        if details:
            ret.append((', ').join((e.text for e in self.errors)))
        if verbose:
            ret.append((', ').join((lxml.etree.tostring(e) for e in self.errors)))
        return (': ').join(ret)

    @property
    def rv(self):
        return int(self.find('./Value').text)

    @property
    def severity(self):
        return self.find('./Severity').text.strip().lower()

    @property
    def message(self):
        msg = self.find('./Message')
        if msg is not None:
            return msg.text
        return ''

    @property
    def errors(self):
        return self.findall('./Error')


class ScciCommandSeq(ScciElement):
    TAG = 'CMDSEQ'

    def append_command(self, cmd, value):
        self.append(cmd.to_command(value))


class ScciData(ScciElement):
    TAG = 'DATA'

    @classmethod
    def new(cls, obj, value):
        if obj.data_type in [int, long]:
            type_str = 'integer'
        else:
            if obj.data_type in [str, basestring]:
                type_str = 'string'
            else:
                type_str = obj.data_type.__name__
        ret = cls(attrib={'Type': 'xsd::%s' % type_str})
        ret.text = str(obj.data_type(value))
        return ret


class ScciCommand(ScciElement):
    TAG = 'CMD'

    @classmethod
    def get_attrib(cls):
        attrib = super(ScciCommand, cls).get_attrib()
        attrib.update({'Context': 'SCCI', 
           'OI': '0'})
        return attrib

    @classmethod
    def new(cls, op, value):
        cmd = cls(attrib={'OC': op.cmd_string, 'OE': op.op_code})
        cmd.append(ScciData.new(op, value))
        return cmd


class ScciSetConfigCommand(ScciCommand):

    @classmethod
    def get_attrib(cls):
        attrib = super(ScciSetConfigCommand, cls).get_attrib()
        attrib.update({'OC': 'ConfigSpace', 
           'type': 'SET'})
        return attrib

    @classmethod
    def new(cls, config_value, value):
        cmd = cls(attrib={'OE': config_value.value_id})
        cmd.append(ScciData.new(config_value, value))
        return cmd


class FujitsuIRMC(object):
    """
    Provides a subset of the Fujitsu iRMC interface.
    """
    IPV4_RE = re.compile('^(?P<block>[12]?[0-9]{0,2}(?:\\.(?!$)|(?P=block)$)){4}$')

    def __init__(self, ip_address, username, password):
        """
        Args:
          ip_address (str): IPv4 or v6 address for iRMC.
          username (str): iRMC username.
          password (str): iRMC password.
        """
        self._ip_address = ip_address
        self._username = username
        self._password = password
        self._request_headers = {'Authorization': 'Basic %s' % base64.b64encode('%s:%s' % (self._username, self._password)), 
           'Content-Type': 'application/x-www-form-urlencoded'}
        self._resp_parser = lxml.etree.XMLParser()
        self._resp_parser.set_element_class_lookup(ScciResponseLookup())

    def lookup_node_position(self):
        """
        Lookup node position via OEM IPMI command.
        
        Returns:
          (int) 1-indexed node position.
        """
        ipmi = ipmi_util.get_session(self._ip_address, self._username, self._password)
        resp = ipmi.xraw_command(46, 245, data=(128, 40, 0, 139, 1, 1))
        slot_index = struct.unpack('<7BH', resp['data'])[4]
        return slot_index

    def configure_bmc_ipv4(self, ip, netmask, gateway):
        """
        Configures iRMC IPV4 networking.
        
        Args:
          ip (str): IPv4 address to be set.
          netmask (str): Netmask to be set.
          gateway (str): IPv4 address of gateway to be used.
        
        Raises:
          StandardError: Configuration failed.
        """
        cmds = ScciCommandSeq()
        cmds.append_command(ScciConfigValues.BMC_IPV4_ENABLED, 1)
        cmds.append_command(ScciConfigValues.BMC_IPV4_IP, ip)
        cmds.append_command(ScciConfigValues.BMC_NETMASK, netmask)
        cmds.append_command(ScciConfigValues.BMC_GATEWAY, gateway)
        return self._issue_scci_cmds(cmds)

    def mount_iso(self, iso):
        """
        Configures and activates 'iso' as a remote-mounted virtual CD device.
        
        Args:
          iso (str): Path to iso to mount.
        """
        share_name, iso_name = os.path.split(folder_central.get_nfs_path_from_tmp_path(iso))
        share_host = foundation_tools.get_my_ip(self._ip_address)
        cmds = ScciCommandSeq()
        cmds.append_command(ScciConfigValues.BMC_VMEDIA_ENABLED, 1)
        cmds.append_command(ScciConfigValues.BMC_VMEDIA_OPT_CD_NUM, 2)
        cmds.append_command(ScciConfigValues.BMC_REMOTE_CD_SERVER, share_host)
        cmds.append_command(ScciConfigValues.BMC_REMOTE_CD_DOMAIN, '')
        cmds.append_command(ScciConfigValues.BMC_REMOTE_CD_SHARE_TYPE, ScciShareType.NFS)
        cmds.append_command(ScciConfigValues.BMC_REMOTE_CD_SHARE_NAME, share_name)
        cmds.append_command(ScciConfigValues.BMC_REMOTE_CD_IMG_NAME, iso_name)
        cmds.append_command(ScciConfigValues.BMC_REMOTE_CD_USER, '')
        cmds.append_command(ScciConfigValues.BMC_REMOTE_CD_PASSWORD, '')
        self._issue_scci_cmds(cmds)
        time.sleep(60)
        cmds = ScciCommandSeq()
        cmds.append_command(ScciOps.BMC_VMEDIA_CONNECT, 1)
        status = self._issue_scci_cmds(cmds)
        time.sleep(5)
        return status

    def set_legacy_boot(self):
        """
        Sets boot type as Legacy boot.
        """
        content = json.dumps(LEGACY_BOOT_SETTING)
        raw_json, status = self._issue_http_request(self._ip_address, HTTPMethods.POST, ENDPOINT_BIOS_SETTING, content)
        if status != 202:
            raise StandardError('Failed to create profile to set bios settings: HTTP %s' % status)
        session_id = None
        try:
            session_id = json.loads(raw_json)['Session']['Id']
        except Exception as e:
            raise StandardError('Failed to parse session id from response: %s' % str(e))
        else:
            endpoint_session_progress = ENDPOINT_SESSION_PROGRESS % str(session_id)
            in_progress = True
            while in_progress:
                raw_json, status = self._issue_http_request(self._ip_address, HTTPMethods.GET, endpoint_session_progress)
                if status != 200:
                    raise StandardError('Unable to get session status: HTTP %s' % status)
                session_status = None
                try:
                    session_status = json.loads(raw_json)['Session']['Status']
                except Exception as e:
                    raise StandardError('Failed to parse session status from response: %s' % str(e))
                else:
                    if session_status in ('terminated by request', 'terminated with error',
                                          'terminated regularly'):
                        in_progress = False
                        if session_status != 'terminated regularly':
                            raise StandardError('Bios boot setting change terminated abruptly')
                    time.sleep(10)

        endpoint_session_remove = ENDPOINT_SESSION_REMOVE % str(session_id)
        raw_json, status = self._issue_http_request(self._ip_address, HTTPMethods.DELETE, endpoint_session_remove)
        if status != 200:
            raise StandardError('Failed to delete session: HTTP %s' % status)
        return

    def get_report(self):
        """
        Dump configuration, version, sensor, and event information.
        
        Returns:
          (lxml.etree.Element) Root element of report.xml.
        
        Raises:
          FujitsuAuthException on 401
          StandardError any other non 200/201 code
        """
        raw_xml, status = self._issue_http_request(self._ip_address, HTTPMethods.GET, '/report.xml')
        if status == 401:
            raise FujitsuAuthException()
        else:
            if status not in (200, 201):
                raise StandardError('Failed to dump report.xml: HTTP %s' % status)
        return lxml.etree.fromstring(raw_xml)

    def get_version(self):
        """
        Get iRMC version string.
        """
        report = self.get_report()
        fw = report.find('./System/ManagementControllers/iRMC/Firmware')
        if fw is None:
            raise StandardError('Failed to get iRMC version')
        return fw.text

    def unmount_iso(self):
        """
        Deactivate media mount configured for a virtual optical drive.
        """
        cmds = ScciCommandSeq()
        cmds.append_command(ScciOps.BMC_VMEDIA_CONNECT, 0)
        self._issue_scci_cmds(cmds)

    def _is_ipv4(self, address):
        """
        Args:
          address (str): Possible IPv4 address string.
        
        Returns:
          (bool) True if 'address' is a valid IPv4 address, else False.
        """
        if filter(None, self.IPV4_RE.findall(address)):
            return True
        return False

    def _issue_http_request(self, ip, method, path, content=None):
        """
        Issues HTTP 'method' to 'path' at 'ip' with body 'content'.
        
        Args:
          ip (str): v4 or v6 IP address to which request should be sent.
          method (HTTPMethods): HTTP method to use.
          path (str): Absolute request path.
          content (None|str): If not None, request body.
        
        Returns:
          (str, int) Pair (Response body, HTTP status code)
        """
        if self._is_ipv4(ip):
            conn = httplib.HTTPSConnection(ip)
        else:
            conn = httplib.HTTPSConnection('[%s]' % ip.strip('[]'))
        with contextlib.closing(conn.connect() or conn):
            conn.request(method, path, content, self._request_headers)
            try:
                with contextlib.closing(conn.getresponse()) as (resp):
                    return (resp.read(), resp.status)
            except httplib.BadStatusLine as exc:
                if exc.line == "''":
                    raise FujitsuEmptyResponseException()
                raise

    def _issue_scci_cmds(self, cmds, endpoint='/config'):
        """
        Issues provided SCCI command sequence to 'endpoint'.
        
        Args:
          cmds (ScciCommandSeq): Command sequence to send.
          endpoint (str): Endpoint to which 'cmds' should be sent.
        
        Raises:
          FujitsuAuthException: Repsonse is HTTP 401
          StandardError: Any other exception is encountered
        """
        content, status = self._issue_http_request(self._ip_address, HTTPMethods.POST, endpoint, cmds.to_string())
        if status == 401:
            raise FujitsuAuthException()
        else:
            if status not in (200, 201):
                raise StandardError('Error issuing request: %s' % status)
        resp = lxml.etree.fromstring(content, parser=self._resp_parser)
        if resp.rv != 0 or resp.severity != 'information':
            raise StandardError(resp.format_error(details=True))