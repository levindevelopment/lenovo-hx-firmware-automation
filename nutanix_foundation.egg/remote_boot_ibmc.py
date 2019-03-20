# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/remote_boot_ibmc.py
# Compiled at: 2019-02-15 12:42:10
import base64, httplib, json, logging, time, requests, warnings, foundation_tools, remote_boot, folder_central
from foundation_settings import settings as foundation_settings
POWER_MAPPING = {'on': 'On', 
   'off': 'ForceOff', 
   'restart': 'ForceRestart'}
HTTP_PORT = foundation_settings['http_port']

class Huawei(object):

    def __init__(self, ip, user, password, logger):
        """
        Initializes the class to communicate with IBMC
        Accepts BMC IP, User, Password and logger object
        """
        assert ip is not None
        assert user is not None
        assert password is not None
        self._ip = ip
        self._username = user
        self._password = password
        self.logger = logger or logging
        self._verify = False
        self._tag = None
        self._session_id = None
        self._token = None
        return

    def _login(self):
        """
        Login to the Huawei IBMC
        """
        data = {'UserName': self._username, 'Password': self._password}
        status, res = self._restapi('POST', '/redfish/v1/SessionService/Sessions', data)
        self._check_response('Error while reading VMM device status', status, res)

    def _logoff(self):
        """
        Logout from the Huawei IBMC
        """
        session_id = self._session_id
        self.get('/redfish/v1/SessionService/Sessions' + '/' + session_id, None, None)
        self.delete('/redfish/v1/SessionService/Sessions' + '/' + session_id)
        self._session_id = None
        self._token = None
        self._tag = None
        return

    def _set_headers(self, headers):
        """
        Method to set HTTP headers
        """
        if headers is None:
            headers = {}
        headers['Content-Type'] = 'application/json'
        if self._token is not None:
            headers['X-Auth-Token'] = self._token
        if 'If-Match' in headers and self._tag:
            headers['If-Match'] = self._tag
        return headers

    def _restapi(self, method, api_path='', data=None, headers=None, log_on_error=True, raise_on_error=True):
        """
        To do the actual rest call
        """
        headers = self._set_headers(headers=headers)
        response_text = None
        response_status = None
        response_header = None
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore')
            with requests.Session() as (session):
                session.headers = headers
                session.verify = self._verify
                if data is not None:
                    data = json.dumps(data)
                url = 'https://' + self._ip + api_path
                try:
                    if method == 'GET' and method == 'DELETE':
                        req = requests.Request(method, '%s' % url)
                    else:
                        req = requests.Request(method, '%s' % url, data=data)
                    prepped = session.prepare_request(req)
                    response = session.send(prepped)
                    response_status = response.status_code
                    response_text = response.text
                    response_header = response.headers
                except e:
                    self.logger.info('Unable to connect to IBMC , %s ' % str(e))
                    if log_on_error:
                        self.logger.error('Unable to connect to IBMC')
                    if raise_on_error:
                        raise

                response_body = {}
                if response_text:
                    try:
                        response_body = json.loads(response_text)
                    except Exception:
                        if log_on_error:
                            self.logger.error('Unable to process the response data')
                        if raise_on_error:
                            raise

        if 'ETag' in response_header:
            self._tag = response_header['Etag']
        if self._session_id == None and 'Location' in response_header:
            location = response_header['Location'].split('/')
            self._session_id = location.pop()
            self._token = response_header['X-Auth-Token']
        return (response_status, response_body)

    def get(self, url_path='', data=None, headers=None):
        """
        To do GET request
        """
        return self._restapi('GET', url_path, data, headers)

    def post(self, url_path='', data=None, headers=None):
        """
        To do POST request
        """
        return self._restapi('POST', url_path, data, headers)

    def patch(self, url_path='', data=None, headers=None):
        """
        To do PATCH request
        """
        if headers is None:
            headers = {}
        headers['If-Match'] = None
        return self._restapi('PATCH', url_path, data, headers)

    def delete(self, url_path='', headers=None):
        """
        To do delete request
        """
        if headers is None:
            headers = {}
        headers['If-Match'] = None
        return self._restapi('DELETE', url_path, headers)

    def _check_response(self, err_msg, status, response):
        """
        Checks  the given response and if it is not the
        Positive HTTP status raise the error with info
        """
        if status >= 200 and status < 300:
            return
        message = "%s - HTTP Status '%s'" % (err_msg, status)
        if status >= 400 and status < 600:
            if 'error' in response and '@Message.ExtendedInfo' in response['error']:
                extended_err_msg = response['error']['@Message.ExtendedInfo']
                message = message + " Extended Error '%s'" % extended_err_msg
                self.logger.error(message)
        raise StandardError(err_msg)

    def get_manufacturer(self):
        """
        To get the OEM
        """
        self._login()
        status, res = self.get('/redfish/v1/Systems/1/', None, None)
        self._check_response('Error while reading Manufacturer', status, res)
        self._logoff()
        if 'Manufacturer' in res.keys():
            return res['Manufacturer'].upper()
        return
        return

    def _get_vm_device_status(self):
        """
        Get virtual media mount status.
        """
        status, res = self.get('/redfish/v1/Managers/1/VirtualMedia/CD', None, None)
        self._check_response('Error while reading VMM device status', status, res)
        return (
         res, res['Image'])

    def add_vmedia_image(self, image_url):
        """
        Adds the Virtual media image URL to the approriate device.
        """
        self._login()
        response, vm_device_uri = self._get_vm_device_status()
        if response.get('Inserted') is True:
            self._eject_vmedia()
        settings = dict()
        settings['VmmControlType'] = 'Connect'
        settings['Image'] = image_url
        status, res = self.post('/redfish/v1/Managers/1/VirtualMedia/CD/Oem/Huawei/Actions/VirtualMedia.VmmControl', settings, None)
        self._check_response('Error while adding VMedia', status, res)
        for _ in range(200):
            response, vm_device_uri = self._get_vm_device_status()
            if response.get('Inserted') is True:
                break
            time.sleep(3)
        else:
            raise StandardError('Unable to mount vm %s node in timely                           manner' % response)

        self._logoff()
        return True

    def eject_vmedia(self):
        """
        Eject the virtual image
        """
        self._login()
        self._eject_vmedia()
        self._logoff()

    def _eject_vmedia(self):
        """
        Delete virtual media mount.
        """
        response, vm_device_uri = self._get_vm_device_status()
        if response.get('Inserted') is False:
            return
        settings = dict()
        settings['VmmControlType'] = 'Disconnect'
        status, res = self.post('/redfish/v1/Managers/1/VirtualMedia/CD/Oem/Huawei/Actions/VirtualMedia.VmmControl', settings, None)
        self._check_response('Error while removing VMedia', status, res)
        for _ in range(200):
            response, vm_device_uri = self._get_vm_device_status()
            if response.get('Inserted') is False:
                break
            time.sleep(3)
        else:
            raise StandardError('Unable to unmount vm %s node in timely                           manner' % response)

        return

    def _get_type(self, obj):
        """
        Return the type of an object.
        """
        typever = obj['@odata.type']
        typesplit = typever.split('.')
        return typesplit[0] + '.' + typesplit[1]

    def _get_system_details(self):
        """
        Gets the system details of the server
        """
        uri = '/redfish/v1/Systems/1'
        system_types = ['#ComputerSystem.v1_2_0']
        status, response = self.get('/redfish/v1/Systems/1', None, None)
        self._check_response('Unable to get system details', status, response)
        stype = self._get_type(response)
        if stype not in system_types:
            raise StandardError('%s is not a valid system type ' % stype)
        return response

    def set_boot_mode_power_policy(self, bootmode='Legacy', power_policy='RestorePreviousState'):
        """
        Sets the boot mode
        Args:
          bootmode: Boot mode which need to be set (Uefi/LegacyBios)
        """
        if bootmode not in ('Uefi', 'Legacy'):
            raise StandardError('%s not a valid boot mode' % bootmode)
        if power_policy not in ('TurnOn', 'RestorePreviousState', 'StayOff'):
            raise StandardError('%s is not a valid power policy' % power_policy)
        self._login()
        status, res = self.get('/redfish/v1/Systems/1', None, None)
        self._check_response('Error while reading System details', status, res)
        settings = {'Boot': {'BootSourceOverrideTarget': 'Cd', 'BootSourceOverrideEnabled': 'Continuous', 
                    'BootSourceOverrideMode': bootmode}, 
           'Oem': {'Huawei': {'PowerOnStrategy': power_policy}}}
        status, res = self.patch('/redfish/v1/Systems/1', settings, None)
        self._check_response('Error while changing bootmode', status, res)
        self._logoff()
        self.power_control('off')
        self.power_control('on')
        return

    def set_bios_settings(self):
        """
        Set bios settings
        """
        self._login()
        status, res = self.get('/redfish/v1/Systems/1/Bios/Settings', None, None)
        self._check_response('Error while reading BIOS settings', status, res)
        settings = {'Attributes': {'IOAPICMode': 'Enabled', 'MonitorMwaitEnable': 'Enabled', 
                          'XPTPrefetchEn': 'Enabled', 
                          'CustomPowerPolicy': 'Efficiency', 
                          'ProcessorAutonomousCStateEnable': 'Disabled', 
                          'ProcessorX2APIC': 'Enabled'}}
        status, res = self.patch('/redfish/v1/Systems/1/Bios/Settings', settings, None)
        self._check_response('Error while changing BIOS settings', status, res)
        self._logoff()
        self.power_control('off')
        self.power_control('on')
        return

    def power_control(self, option):
        """
        Method to do power control operations
        Args:
          option: options (on/off)
        """
        if option == self.get_power_status():
            return
        if option not in POWER_MAPPING.keys():
            raise StandardError('Unable to process the option :%s', option)
        self._login()
        status, res = self.post('/redfish/v1/Systems/1/Actions/ComputerSystem.Reset', {'ResetType': POWER_MAPPING[option]}, None)
        self._check_response('Unable to power control the server', status, res)
        self._logoff()
        for _ in range(200):
            status = self.get_power_status()
            if option == status:
                break
            time.sleep(3)
        else:
            raise StandardError('Unable to power %s node in timely manner' % option)

        return

    def get_power_status(self):
        """
        Gets the current power status of the server
        """
        self._login()
        system = self._get_system_details()
        self._logoff()
        return system['PowerState'].lower()

    def set_ipv4_address(self, mac, ipv4, netmask, gateway):
        """
        Configure IPv4 setting on ethernet interface with mac address 'mac'.
        Args:
          mac: MAC address of IBMC interface.
          ipv4: IPv4 adddress to be configured on IBMC interface.
          netmask: Netmask to be configured on IBMC interface.
          gateway: Gateway to be configured on IBMC interface.
        """
        ethernet_interfaces = self._get_available_ethernet_interfaces()
        eth_uris = []
        for member in ethernet_interfaces['Members']:
            eth_uris.append(member['@odata.id'])

        eth_uri_to_configure = None
        for eth_uri in eth_uris:
            response = self._get_ethernet_interface_details(eth_uri)
            if response['PermanentMACAddress'].lower() == mac.lower():
                eth_uri_to_configure = eth_uri
                break
        else:
            raise StandardError("Unable to find mac address '%s'" % mac)

        self._set_ipv4_address(eth_uri_to_configure, ipv4, netmask, gateway)
        return

    def _get_available_ethernet_interfaces(self):
        """
        Returns available ethernet interface
        """
        self._login()
        status, response = self.get('/redfish/v1/Managers/1/EthernetInterfaces', None, None)
        self._logoff()
        self._check_response('Error while getting eth interfaces', status, response)
        return response

    def _get_ethernet_interface_details(self, eth_uri):
        """
        Returns ethernet interface details
        Args: ethernet interface url from ethernet interfaces response
        """
        self._login()
        status, response = self.get(eth_uri, None, None)
        self._logoff()
        self._check_response('Error while getting ethernet interface', status, response)
        return response

    def _set_ipv4_address(self, eth_uri_to_configure, ipv4, netmask, gateway):
        """
        Sets ipv4 address for ethernet interface
        Args: ethernet uri, ipv4 address, netmask, gateway
        """
        ipv4_settings = {}
        ipv4_settings['IPv4Addresses'] = [
         {'Address': ipv4, 'Gateway': gateway, 
            'SubnetMask': netmask, 
            'AddressOrigin': 'Static'}]
        self._login()
        status, res = self.patch(eth_uri_to_configure, ipv4_settings, None)
        self._check_response('Error while setting ipv4 address', status, res)
        self._logoff()
        return


class RemoteBootIbmc(remote_boot.RemoteBoot):

    def get_ibmc(self):
        """
        Returns a ibmc object.
        """
        ibmc = Huawei(self.node_config.ipmi_ip, self.node_config.ipmi_user, self.node_config.ipmi_password, self.node_config.get_logger())
        return ibmc

    def boot(self, iso, do_reset=True):
        """
        Method for booting node specific iso from foundation.
        Args:
          iso: ISO image path
          do_reset: Whether the server has to be rebooted or not
        """
        logger = self.node_config.get_logger()
        ibmc = self.get_ibmc()
        ibmc.set_boot_mode_power_policy('Legacy', 'RestorePreviousState')
        ibmc.set_bios_settings()
        foundation_ip = self.node_config.foundation_ip
        use_foundation_ips = getattr(self.node_config, 'use_foundation_ips', False)
        if use_foundation_ips:
            foundation_ip = self.node_config.foundation_ipmi_ip
        uri = folder_central.get_nfs_path_from_tmp_path(iso)
        image_url = 'nfs://%s%s' % (foundation_ip, uri)
        logger.info('Url to download phoenix iso: %s' % image_url)
        ibmc.add_vmedia_image(image_url)
        if do_reset:
            ibmc.power_control('off')
            ibmc.power_control('on')

    def stop(self):
        """
        Method for stopping virtual media process (if any).
        """
        ibmc = self.get_ibmc()
        ibmc.eject_vmedia()

    def poweroff(self):
        """
        Method for powering off node.
        """
        ibmc = self.get_ibmc()
        ibmc.power_control('off')

    def set_first_boot_device(self):
        pass

    def pre_boot_bios_settings(self):
        pass