# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/remote_boot_intel.py
# Compiled at: 2019-02-15 12:42:10
import base64, httplib, json, logging, os, re, requests, time, foundation_tools, remote_boot
POWER_MAPPING = {'on': 'On', 
   'off': 'ForceOff', 
   'restart': 'ForceRestart'}

class IntelBMC(object):

    def __init__(self, ip, user, password, logger):
        """
          Initializes the class
          Setting basic mandatory params
        """
        assert ip is not None
        assert user is not None
        assert password is not None
        self.ip = ip
        self.user = user
        self.password = password
        self.logger = logger or logging
        return

    def _rest_call(self, uri, method, request_headers, request_body, log_on_error=True, raise_on_error=True):
        """
        Method does rest call and handles the response.
        Args:
          uri: RESt URI
          method: RESt call method (GET/POST/PATCH)
          request_headers: Header for the request
          request_body: Request params
        Returns:
          tuple (status, response)
        """
        request_headers = request_headers or {}
        request_body = request_body or {}
        auth_key = base64.b64encode('%s:%s' % (self.user,
         self.password)).decode('ascii')
        request_headers['Authorization'] = 'Basic %s' % auth_key
        request_headers['Content-Type'] = 'application/json'
        response_text = None
        response_status = None
        conn = httplib.HTTPSConnection(host=self.ip, strict=True)
        try:
            if method == 'GET':
                conn.request(method, uri, headers=request_headers)
            else:
                conn.request(method, uri, body=json.dumps(request_body), headers=request_headers)
            response = conn.getresponse()
            response_text = response.read()
            response_status = response.status
        except Exception:
            if log_on_error:
                self.logger.error('Unable to connect to IntelIBMC')
            if raise_on_error:
                raise
        finally:
            conn.close()

        response_body = {}
        if response_text:
            try:
                response_body = json.loads(response_text)
            except Exception:
                if log_on_error:
                    self.logger.error('Unable to process the response data')
                if raise_on_error:
                    raise

        return (
         response_status, response_body)

    def _sdp_tool_cmd_execute(self, cmd_options, success_identifier):
        """
        To execute and validate the SDB tool command and result
        Args:
          cmd_options: SDP Tool command options list
          success_identifier: Text to identify the command success status
        """
        cmd_base = [
         '/usr/bin/sudo', '/usr/bin/SDPTool', self.ip, self.user,
         self.password]
        cmd = cmd_base + cmd_options + ['-no_user_interaction']
        pattern = '^.+%s.+$' % success_identifier
        self.logger.debug('SDP Tool Command : %s' % cmd)
        out, err, ret = foundation_tools.system(None, cmd, timeout=600)
        self.logger.debug('Outout : %s, Error : %s' % (out, err))
        if re.match(pattern, out, re.DOTALL):
            self.logger.debug('Command success')
            return True
        self.logger.debug('Command failure')
        return False
        return

    def _check_response(self, err_msg, status, response):
        """
        Args:
          err_msg: Error Message, if HTTP requeset is not successful.
          status: HTTP Status.
          response: Response of HTTP request.
        Raises StandardError if status is not successfull.
        If an error occurs, indicated by a return code 4xx or 5xx, an ExtendedError
        JSON response is returned. The expected resource is not returned.
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

    def get_system_serial(self):
        """
        Returns the system serial number
        """
        uri = '/redfish/v1/Systems'
        status, response = self._rest_call(uri, 'GET', None, None, log_on_error=False, raise_on_error=False)
        self._check_response('Unable to get system details', status, response)
        try:
            return response['Members'][0]['@odata.id'].split('/')[-1]
        except:
            raise StndardError('Unable to get the System serial')

        return

    def get_manufacturer(self):
        """
        Returns the manufacturer name
        Returns:
          Manufacturer name
        """
        uri = '/redfish/v1/Chassis/RackMount'
        status, response = self._rest_call(uri, 'GET', None, None, log_on_error=False, raise_on_error=False)
        if 'Manufacturer' in response:
            return response['Manufacturer'].lower()
        return
        return

    def is_Intel(self):
        """
        Checked whether the given server is Intel
        Returns:
          True, If the server is Intel
          False, If the server is not Intel server
        """
        if self.get_manufacturer() == 'intel corporation':
            return True
        return False

    def get_power_status(self):
        """
        Gets the current power status of the server
        """
        uri = '/redfish/v1/Chassis/RackMount/Baseboard'
        status, response = self._rest_call(uri, 'GET', None, None)
        self._check_response('Error while getting Power State', status, response)
        return response['PowerState'].lower()

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
        power_settings = {'ResetType': POWER_MAPPING[option]}
        system_serial = self.get_system_serial()
        uri = '/redfish/v1/Systems/%s/Actions/ComputerSystem.Reset/' % system_serial
        status, response = self._rest_call(uri, 'POST', None, power_settings)
        self._check_response('Unable to power control the server', status, response)
        for _ in range(200):
            status = self.get_power_status()
            if option == status:
                break
            time.sleep(3)
        else:
            raise StandardError('Unable to power %s node in timely manner' % option)

        return

    def add_vmedia_image(self, iso):
        """
        Adds the Virtual media image URL to the appropriate device.
        Args:
          iso : ISO image
        """
        self.logger.debug('ISO image to mount: %s' % iso)
        sdb_option = ['vmedia', iso]
        if self._sdp_tool_cmd_execute(sdb_option, success_identifier='mounted successfully') is False:
            raise StandardError('Unable to vmedia mount ISO image')

    def eject_vmedia(self, iso):
        """
        Delete virtual media mount.
        """
        self.logger.debug('ISO image to unmount: %s' % iso)
        sdb_options = ['unmount', iso]
        if self._sdp_tool_cmd_execute(sdb_options, success_identifier='unmount successful') is False:
            raise StandardError('Unable to vmedia unmount ISO image')

    def set_boot_mode(self, bootmode='LegacyBios'):
        """
        Sets the boot mode
        Args:
          bootmode: Boot mode which need to be set (Uefi/LegacyBios)
        """
        BOOT_MODE_MAP = {'LegacyBios': '00', 'Uefi': '01'}
        if bootmode not in ('Uefi', 'LegacyBios'):
            raise StandardError('%s not a valid boot mode' % bootmode)
        sdb_options = ['setoptions', '/bcs', '',
         'Boot Mode', BOOT_MODE_MAP[bootmode]]
        if self._sdp_tool_cmd_execute(sdb_options, success_identifier='Successful') is False:
            raise StandardError('Unable to set boot mode to Legacy BIOS')

    def set_ipv4_address(self, ipv4, netmask, gateway):
        """
        Sets ipv4 static address
        """
        uri = '/redfish/v1/Managers/1/EthernetInterfaces/3'
        static_ip_setting = {'DHCPv4': {'DHCPEnabled': False}}
        status, response = self._rest_call(uri, 'PATCH', None, static_ip_setting)
        self._check_response('Error while setting address origin to Static', status, response)
        ipv4_settings = {}
        ipv4_settings['IPv4Addresses'] = [
         {'Address': ipv4, 
            'Gateway': gateway, 
            'SubnetMask': netmask}]
        status, response = self._rest_call(uri, 'PATCH', None, ipv4_settings)
        self._check_response('Error while setting ipv4 address', status, response)
        return


class RemoteBootIntelBMC(remote_boot.RemoteBoot):

    def get_intelbmc(self):
        """
        Returns a ilo object.
        """
        ibmc = IntelBMC(self.node_config.ipmi_ip, self.node_config.ipmi_user, self.node_config.ipmi_password, self.node_config.get_logger())
        return ibmc

    def boot(self, iso, do_reset=True):
        """
        Method for booting node specific iso from foundation.
        Args:
          iso: ISO image path
          do_reset: Whether the server has to be rebooted or not
        """
        self.phoenix_iso = iso
        self.iso_mount_done = False
        logger = self.node_config.get_logger()
        ibmc = self.get_intelbmc()
        ibmc.set_boot_mode('LegacyBios')
        ibmc.add_vmedia_image(self.phoenix_iso)
        self.iso_mount_done = True
        if do_reset:
            ibmc.power_control('off')
            ibmc.power_control('on')

    def stop(self):
        """
        Method for stopping virtual media process (if any).
        """
        if self.iso_mount_done:
            ibmc = self.get_intelbmc()
            ibmc.eject_vmedia(self.phoenix_iso)

    def poweroff(self):
        """
        Method for powering off node.
        """
        ibmc = self.get_intelbmc()
        ibmc.power_control('off')

    def set_first_boot_device(self):
        pass