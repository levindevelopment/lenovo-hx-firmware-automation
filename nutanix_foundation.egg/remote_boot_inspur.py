# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/remote_boot_inspur.py
# Compiled at: 2019-02-15 12:42:10
import json, logging, os, requests, time, folder_central, foundation_tools, remote_boot
POWER_MAPPING = {'on': 1, 
   'off': 0, 
   'restart': 2}

class InspurAPI(object):

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
          method: RESt call method (GET/POST/PUT)
          request_headers: Header for the request
          request_body: Request params
        Returns:
          tuple (status, response)
        """
        request_headers = request_headers or {}
        request_body = request_body or {}
        try:
            session_url = 'https://%s/api/session' % self.ip
            session_auth = {'username': self.user, 'password': self.password, 
               'encrypt_flag': 0}
            s = requests.session()
            s.verify = False
            r = s.post(session_url, data=session_auth)
            s.headers.update({'X-CSRFTOKEN': r.json()['CSRFToken'], 'Content-Type': 'application/json'})
            if method == 'GET':
                req = requests.Request(method, 'https://%s%s' % (self.ip, uri))
            else:
                req = requests.Request(method, 'https://%s%s' % (self.ip, uri), data=json.dumps(request_body))
            prepped = s.prepare_request(req)
            response = s.send(prepped)
            response_status = response.status_code
            response_text = response.text
            del_req = requests.Request('DELETE', session_url)
            del_prepped = s.prepare_request(del_req)
            del_response = s.send(del_prepped)
        except Exception:
            if log_on_error:
                self.logger.error('Unable to connect to Inspur BMC')
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

        return (
         response_status, response_body)

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
            extended_err_msg = response['error']
            message = message + " Extended Error '%s'" % extended_err_msg
        self.logger.error(message)
        raise StandardError(err_msg)

    def get_manufacturer(self):
        """
        Method to give the manufacturer name
        Returns:
          Manufacturer name
        """
        uri = '/api/fru'
        status, response = self._rest_call(uri, 'GET', None, None, log_on_error=False, raise_on_error=False)
        self._check_response('Unable to get system details', status, response)
        return response[0]['product']['manufacturer']

    def is_Inspur(self):
        """
        Method to check whether the node is Inspur or not
        Returns:
        """
        oem = self.get_manufacturer()
        if oem == 'Inspur':
            return True
        return False

    def _get_chassis_status(self):
        """
        Gets the Chassis status of the server
        """
        uri = '/api/chassis-status'
        status, response = self._rest_call(uri, 'GET', None, None)
        self._check_response('Unable to get chassis status', status, response)
        return response

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
        power_settings = {'power_command': POWER_MAPPING[option]}
        uri = '/api/actions/power'
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

    def get_power_status(self):
        """
        Gets the current power status of the server
        """
        system = self._get_chassis_status()
        return system['PowerStatus'].lower()

    def setup_vmedia(self, remote_address, remote_source_path):
        """
        Adds the Virtual media NFS folder
        Args:
          remote_address: Host of the NFS share directory
          remote_source_path: NFS share directory path
        """
        uri = '/api/settings/media/general'
        status, response = self._rest_call(uri, 'GET', None, None)
        self._check_response('Unable to get vmedia attributes', status, response)
        vm_settings = response
        vm_settings['remote_media_support'] = 1
        vm_settings['cd_remote_server_address'] = remote_address
        vm_settings['cd_remote_source_path'] = remote_source_path
        vm_settings['cd_remote_share_type'] = 'nfs'
        vm_settings['mount_cd'] = 1
        status, response = self._rest_call(uri, 'PUT', None, vm_settings)
        self._check_response('Error while adding VMedia', status, response)
        return self.wait_till_vmedia_mount()

    def wait_till_vmedia_mount(self):
        """
        Waits for vmedia mount
        """
        uri = '/api/settings/media/general'
        for _ in range(5):
            status, response = self._rest_call(uri, 'GET', None, None)
            self._check_response('Unable to get vmedia attributes', status, response)
            if response['remote_media_support'] and response['mount_cd']:
                return True
            time.sleep(10)

        return False

    def disable_vmedia(self):
        """
        Disables virtual media
        """
        uri = '/api/settings/media/general'
        status, response = self._rest_call(uri, 'GET', None, None)
        self._check_response('Unable to get vmedia attributes', status, response)
        vm_settings = response
        vm_settings['remote_media_support'] = 0
        vm_settings['cd_remote_server_address'] = ''
        vm_settings['cd_remote_source_path'] = ''
        vm_settings['mount_cd'] = 0
        status, response = self._rest_call(uri, 'PUT', None, vm_settings)
        self._check_response('Error while disabling vmedia', status, response)
        return True

    def change_boot_priority(self, option, only_next_boot=True):
        """
        Sets first boot priortiy
        option: Boot option to set
        only_next_boot: Enable boot option only for next boot
        """
        uri = '/api/bootOption'
        BOOT_OPTION_MAP = {'PXE': 1, 'HDD': 2, 
           'CD': 5}
        style = 0 if only_next_boot else 1
        boot_order_settings = {'dev': BOOT_OPTION_MAP[option], 'enable': 1, 
           'style': style}
        status, response = self._rest_call(uri, 'POST', None, boot_order_settings)
        self._check_response('Error changing boot priority', status, response)
        return True

    def update_bios_settings(self):
        """
        Updates various BIOS settings
        """
        expected_bios_settings = dict()
        expected_bios_settings['BootMode'] = 1
        expected_bios_settings['CSMSupport'] = 1
        expected_bios_settings['OptionRomNetwork'] = 2
        expected_bios_settings['OptionRomStorage'] = 2
        expected_bios_settings['OptionRomVideo'] = 2
        expected_bios_settings['OptionRomOtherPCIE'] = 2
        expected_bios_settings['MonitorMWaitSupport'] = 1
        expected_bios_settings['EnhancedHaltState'] = 1
        expected_bios_settings['PowerPerformTuning'] = 0
        self.power_control('on')
        uri = '/api/biossetup'
        status, response = self._rest_call(uri, 'GET', None, None)
        self._check_response('Unable to get BIOS details', status, response)
        if self._is_bios_settings_ok(response, expected_bios_settings):
            self.logger.debug('BIOS settings are already good')
            return
        self.logger.debug('Going to update BIOS settings')
        bios_settings = response
        bios_settings.update(expected_bios_settings)
        status, response = self._rest_call(uri, 'PUT', None, bios_settings)
        self._check_response('Error while changing BIOS settings', status, response)
        self.power_control('off')
        self.power_control('on')
        return

    def set_power_policy_to_last_state(self):
        """
        Sets the power policy to last power state
        """
        self.power_control('on')
        uri = '/api/settings/power_policy'
        status, response = self._rest_call(uri, 'POST', None, {'action': 1})
        if 'action' in response and response['action'] != 1 or status not in (200,
                                                                              201):
            self.logger.debug('Power Policy update failed response %s, status %d' % (
             response, status))
            return False
        return True

    def _is_bios_settings_ok(self, response, expected_bios_settings):
        """
        Checks whether the BIOS settings already set as expected
        Returns:
               True if the BIOS setup is already set as expected
               False if BIOS setup needs an update
        """
        bios_settings_fields = [
         'BootMode', 'CSMSupport', 'OptionRomNetwork',
         'OptionRomStorage', 'OptionRomVideo',
         'OptionRomOtherPCIE', 'MonitorMWaitSupport',
         'EnhancedHaltState', 'PowerPerformTuning']
        actual_bios_settings = dict()
        for field in bios_settings_fields:
            if field in response:
                actual_bios_settings[field] = response[field]

        if actual_bios_settings == expected_bios_settings:
            return True
        return False

    def reset_bmc(self):
        """
        Resets BMC
        """
        uri = '/api/diagnose/bmc-reset'
        status, response = self._rest_call(uri, 'POST', None, {'reset': 0})
        self._check_response('Unable to reset the BMC', status, response)
        return self.wait_till_bmc_reset()

    def wait_till_bmc_reset(self):
        """
        Waits till the BMC responds, used after BMC reset
        to confirm whether the BMC is up again
        """
        uri = '/api/settings/services'
        for _ in range(10):
            time.sleep(60)
            try:
                status, response = self._rest_call(uri, 'GET', None, None)
                if status in (200, 201):
                    self.logger.debug('BMC is responding after reset')
                    return True
            except Exception as e:
                self.logger.info('Still BMC is not responding, retrying')

        return False


class RemoteBootInspur(remote_boot.RemoteBoot):

    def get_inspur(self):
        """
        Creates Inspur API object
        """
        inspur = InspurAPI(self.node_config.ipmi_ip, self.node_config.ipmi_user, self.node_config.ipmi_password, self.node_config.get_logger())
        self.mount_success = False
        return inspur

    def boot(self, iso, do_reset=True):
        """
        Boots the given ISO file on server
        Args:
          iso: ISO file path
          do_reset: Need server reset or not
        """
        logger = self.node_config.get_logger()
        inspur = self.get_inspur()
        inspur.update_bios_settings()
        self.prepare_phoenix_iso_for_inspur(iso)
        if self.add_vmedia() is False:
            logger.debug('Vmedia ISO mount failing, doing BMC reset')
            if inspur.reset_bmc() is True:
                if self.add_vmedia() is False:
                    raise StandardError('Vmedia ISO mount failed !')
            else:
                raise StandardError('BMC reset failed !')
        inspur.change_boot_priority('CD', only_next_boot=False)
        if do_reset:
            inspur.power_control('off')
            inspur.power_control('on')

    def add_vmedia(self):
        """
        Sets the configured NFS folder as remote vmedia folder in server
        and mounts the first ISO in that folder as vmedia source.
        """
        inspur = self.get_inspur()
        foundation_ip = foundation_tools.get_my_ip(self.node_config.ipmi_ip)
        if not inspur.setup_vmedia(foundation_ip, self.phoenix_dir):
            return False
        inspur.power_control('on')
        out, err, ret = foundation_tools.ipmitool_with_retry(self.node_config, [
         'raw', '0x32', '0xD7', '0x00',
         '0x01', '0x01', '0x01', '0x00'], throw_on_error=False, retries=5, delay_s=5)
        if ret != 0:
            return False
        self.mount_success = True
        return True

    def prepare_phoenix_iso_for_inspur(self, iso):
        """
        Prepare Phoenix ISO file for Inspur platform
        Args:
          iso: ISO file path
        """
        try:
            logger = self.node_config.get_logger()
            nfs_path = folder_central.get_nfs_path_from_tmp_path(iso)
            nfs_folder, nfs_file = os.path.split(nfs_path)
            phoenix_dir = '%s/%s' % (nfs_folder,
             nfs_file.split('_')[1].rstrip('.iso'))
            if not os.path.exists(phoenix_dir):
                os.mkdir(phoenix_dir)
                if not os.path.exists(phoenix_dir):
                    raise StandardError('Failed to create node specific folder for Inspur')
            phoenix_iso = phoenix_dir + '/' + nfs_file
            os.rename(iso, phoenix_iso)
            if not os.path.exists(phoenix_iso):
                raise StandardError('Failed to copy node specific phoenix for Inspur')
            logger.debug('Phoenix iso for Inspur, %s' % phoenix_iso)
            self.phoenix_iso = phoenix_iso
            self.phoenix_dir = phoenix_dir
            return phoenix_dir
        except:
            raise StandardError('Unable to prepare phonix iso for Inspur')

    def cleanup_iso(self):
        """
        Cleans up iso file prepared for inspur
        """
        if os.path.exists(self.phoenix_iso):
            os.unlink(self.phoenix_iso)
        if os.path.exists(self.phoenix_dir):
            os.rmdir(self.phoenix_dir)

    def poweroff(self):
        """
        Method for powering off node.
        """
        inspur = self.get_inspur()
        inspur.power_control('off')

    def eject_vmedia(self):
        """
        Method for diabling virtual media
        """
        if self.mount_success:
            out, err, ret = foundation_tools.ipmitool_with_retry(self.node_config, [
             'raw', '0x32', '0xD7', '0x00',
             '0x01', '0x01', '0x00', '0x00'], throw_on_error=False, retries=5, delay_s=5)
        inspur = self.get_inspur()
        inspur.disable_vmedia()
        self.cleanup_iso()

    def stop(self):
        """
        Method does cleanup and sets power policy
        """
        self.eject_vmedia()
        logger = self.node_config.get_logger()
        inspur = self.get_inspur()
        if inspur.set_power_policy_to_last_state() == False:
            logger.warning('Unable to set power policy to last power state')

    def set_first_boot_device(self):
        pass