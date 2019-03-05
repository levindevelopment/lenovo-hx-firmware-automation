# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/remote_boot_ilo.py
# Compiled at: 2019-02-15 12:42:10
import base64, httplib, json, logging, time, foundation_tools, remote_boot
from foundation_settings import settings as foundation_settings
POWER_MAPPING = {'on': 'On', 
   'off': 'ForceOff', 
   'restart': 'ForceRestart'}
POWER_REGULATOR_MODES = [
 'OsControl', 'DynamicPowerSavings',
 'StaticHighPerf', 'StaticLowPower']
HTTP_PORT = foundation_settings['http_port']
ILO4 = 'ilo4'
ILO5 = 'ilo5'

class HPilo(object):

    def __init__(self, ip, user, password, logger):
        assert ip is not None
        assert user is not None
        assert password is not None
        self.ip = ip
        self.user = user
        self.password = password
        self.logger = logger or logging
        self.ilo_version = None
        self.__set_ilo_version()
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
        auth_data = self.user + ':' + self.password
        hr = 'BASIC ' + base64.b64encode(auth_data.encode('ascii')).decode('utf-8')
        request_headers['Authorization'] = hr
        request_headers['Content-Type'] = 'application/json'
        response_text = None
        response_status = None
        conn = httplib.HTTPSConnection(host=self.ip, strict=True)
        try:
            conn.request(method, uri, json.dumps(request_body), request_headers)
            response = conn.getresponse()
            response_text = response.read()
            response_status = response.status
        except Exception:
            if log_on_error:
                self.logger.error('Unable to connect to iLO')
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

    def _check_response(self, err_msg, status, response):
        """
        Args:
          err_msg: Error Message, if HTTP requeset is not successful.
          status: HTTP Status.
          response: Response of HTTP request.
        Raises StandardError if status is not successfull.
        Refer to page 8:
        http://h20565.www2.hpe.com/hpsc/doc/public/display?docId=c04423967
        Error codes:
        2xx : Successful operation.
        4xx : Client-side error with error message returned.
        5xx : iLO error with error message returned.
        If an error occurs, indicated by a return code 4xx or 5xx, an ExtendedError
        JSON response is returned. The expected resource is not returned.
        """
        if status >= 200 and status < 300:
            return
        message = "%s - HTTP Status '%s'" % (err_msg, status)
        if status >= 400 and status < 600:
            if self.ilo_version == ILO4:
                extended_err_msg = response['Messages'][0]['MessageID']
            else:
                extended_err_msg = response['error']['@Message.ExtendedInfo']
            message = message + " Extended Error '%s'" % extended_err_msg
        self.logger.error(message)
        raise StandardError(err_msg)

    def __set_ilo_version(self):
        """
        Method to set the iLO version
        """
        status, response = self._rest_call('/rest', 'GET', None, None, log_on_error=False, raise_on_error=False)
        if status != 404:
            self.ilo_version = ILO4
            return
        status, response = self._rest_call('/redfish', 'GET', None, None, log_on_error=False, raise_on_error=False)
        if status != 404:
            self.ilo_version = ILO5
        return

    def _get_manufacturer(self, obj):
        """
        Method to give the manufacturer name
        Returns:
          Manufacturer name
        """
        return obj['Manufacturer']

    def isHPE_OEM(self):
        """
        Method to check whether the node is HPE OEM Based
        Returns:
          HPE : If the given node is HPE
          NEC : If the given node is NEC
          HITACHI : If the given node in HITACHI
          None : If the node is not a HPE or NEC node
        """
        if self.ilo_version is None:
            return False
        uri = '/rest/v1/Systems/1'
        if self.ilo_version == ILO5:
            uri = '/redfish/v1/Systems/1/'
        status, response = self._rest_call(uri, 'GET', None, None, log_on_error=False, raise_on_error=False)
        self._check_response('Unable to get system details', status, response)
        oem = self._get_manufacturer(response)
        if oem not in ('HPE', 'NEC', 'HITACHI'):
            return
        return oem

    def _get_vm_device_status(self):
        """
        Method to get Virtual media status.
        Returns:
          Tuple (Virtual media info, virtual media access URI)
        """
        manager_uri = '/rest/v1/Managers/1'
        if self.ilo_version == ILO5:
            manager_uri = '/redfish/v1/Managers/1/'
        status, response = self._rest_call(manager_uri, 'GET', None, None)
        self._check_response('Unable to get the manager URL', status, response)
        try:
            if self.ilo_version == ILO4:
                vmedia_uri = response['links']['VirtualMedia']['href']
            else:
                vmedia_uri = response['VirtualMedia']['@odata.id']
        except KeyError:
            raise StandardError("'VirtualMedia' section in Manager/links does not exist")

        for memberuri in self._get_vmedia_collection(vmedia_uri):
            status, response = self._rest_call(memberuri, 'GET', None, None)
            self._check_response('Unable to get the vMedia response', status, response)
            if 'cd' in [ item.lower() for item in response['MediaTypes'] ]:
                if self.ilo_version == ILO4:
                    vm_device_uri = response['links']['self']['href']
                else:
                    vm_device_uri = memberuri
                return (response, vm_device_uri)

        raise StandardError('vMedia doesnt exist')
        return

    def _get_vmedia_collection(self, vmedia_uri):
        """
        Method that gives the Virtual media collections in the server.
        Args:
          vmedia_uri: Virtual media URI
        Returns:
          List of virtual media collection
        """
        status, response = self._rest_call(vmedia_uri, 'GET', None, None)
        members = list()
        self._check_response('Error while getting Vmedia Members', status, response)
        try:
            if self.ilo_version == ILO4:
                for member in response['links']['Member']:
                    members.append(member['href'])

            else:
                for member in response['Members']:
                    members.append(member['@odata.id'])

            return members
        except KeyError:
            raise StandardError('Vmedia members not found')

        return

    def add_vmedia_image(self, image_url):
        """
        Adds the Virtual media image URL to the approriate device.
        Args:
          image_url : URL of the iso image
        """
        response, vm_device_uri = self._get_vm_device_status()
        if response.get('Inserted') is True:
            self.eject_vmedia()
        vm_settings = {}
        vm_settings['Image'] = image_url
        if self.ilo_version == ILO4:
            vm_settings['Oem'] = {'Hp': {'BootOnNextServerReset': True}}
        else:
            vm_settings['Oem'] = {'Hpe': {'BootOnNextServerReset': True}}
        status, response = self._rest_call(vm_device_uri, 'PATCH', None, vm_settings)
        self._check_response('Error while adding VMedia', status, response)
        return True

    def eject_vmedia(self):
        """
        Delete virtual media mount.
        """
        response, vm_device_uri = self._get_vm_device_status()
        if response.get('Inserted') is False:
            return
        vm_settings = dict()
        vm_settings['Image'] = None
        status, response = self._rest_call(vm_device_uri, 'PATCH', None, vm_settings)
        self._check_response('Error while removing VMedia', status, response)
        return

    def _get_type(self, obj):
        """
        Return the type of an object.
        """
        typever = obj['Type'] if self.ilo_version == ILO4 else obj['@odata.type']
        typesplit = typever.split('.')
        return typesplit[0] + '.' + typesplit[1]

    def _get_system_details(self):
        """
        Gets the system details of the server
        """
        uri = '/rest/v1/Systems/1'
        system_types = ['ComputerSystem.0', 'ComputerSystem.1']
        if self.ilo_version == ILO5:
            uri = '/redfish/v1/Systems/1/'
            system_types = ['#ComputerSystem.v1_2_0', '#ComputerSystem.v1_3_0', '#ComputerSystem.v1_4_0']
        status, response = self._rest_call(uri, 'GET', None, None)
        self._check_response('Unable to get system details', status, response)
        stype = self._get_type(response)
        if stype not in system_types:
            raise StandardError('%s is not a valid system type ' % stype)
        return response

    def _set_virtualization_mode(self):
        """
        Sets the virtualization mode
        Args:
        """
        bootmode = 'LegacyBios'
        uri = '/rest/v1/Systems/1/Bios/Settings'
        if self.ilo_version == ILO5:
            uri = '/redfish/v1/Systems/1/Bios/Settings/'
        status, response = self._rest_call(uri, 'GET', None, None)
        self._check_response('Unable to get BIOS details', status, response)
        self.logger.info('Get Virulization attributes')
        if self.ilo_version == ILO4:
            if response['BootMode'] is not bootmode:
                bios_settings = dict()
                bios_settings['BootMode'] = bootmode
        else:
            bios_settings = dict()
            bios_settings['Attributes'] = dict()
            bios_settings['Attributes']['Sriov'] = 'Enabled'
            bios_settings['Attributes']['IntelProcVtd'] = 'Enabled'
            bios_settings['Attributes']['ProcVirtualization'] = 'Enabled'
            bios_settings['Attributes']['ProcX2Apic'] = 'Enabled'
        status, response = self._rest_call(uri, 'PATCH', None, bios_settings)
        self._check_response('Error while changing virtualization mode', status, response)
        return

    def _set_boot_mode(self, bootmode='LegacyBios'):
        """
        Sets the boot mode
        Args:
          bootmode: Boot mode which need to be set (Uefi/LegacyBios)
        """
        if bootmode not in ('Uefi', 'LegacyBios'):
            raise StandardError('%s not a valid boot mode' % bootmode)
        uri = '/rest/v1/Systems/1/Bios/Settings'
        if self.ilo_version == ILO5:
            uri = '/redfish/v1/Systems/1/Bios/Settings/'
        status, response = self._rest_call(uri, 'GET', None, None)
        self._check_response('Unable to get BIOS details', status, response)
        if self.ilo_version == ILO4:
            if response['BootMode'] is not bootmode:
                bios_settings = dict()
                bios_settings['BootMode'] = bootmode
        else:
            if response['Attributes']['BootMode'] is not bootmode:
                bios_settings = dict()
                bios_settings['Attributes'] = dict()
                bios_settings['Attributes']['BootMode'] = bootmode
        status, response = self._rest_call(uri, 'PATCH', None, bios_settings)
        self._check_response('Error while changing bootmode', status, response)
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
        power_settings = {'Action': 'Reset', 'ResetType': POWER_MAPPING[option]}
        uri = '/rest/v1/Systems/1'
        if self.ilo_version == ILO5:
            power_settings = {'Action': 'ComputerSystem.Reset', 'ResetType': POWER_MAPPING[option]}
            uri = '/redfish/v1/Systems/1/Actions/ComputerSystem.Reset/'
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
        system = self._get_system_details()
        if self.ilo_version == ILO4:
            return system['Power'].lower()
        return system['PowerState'].lower()

    def get_post_state(self):
        """
        Get server POST state.
        """
        uri = '/rest/v1/Systems/1'
        name = 'Hp'
        if self.ilo_version == ILO5:
            uri = '/redfish/v1/Systems/1/'
            name = 'Hpe'
        status, response = self._rest_call(uri, 'GET', None, None)
        self._check_response('Error while getting POST State', status, response)
        return response['Oem'][name]['PostState']

    def set_ipv4_address(self, mac, ipv4, netmask, gateway):
        """
        Configure IPv4 setting on ethernet interface with mac address 'mac'.
        Args:
          mac: MAC address of ILO interface.
          ipv4: IPv4 adddress to be configured on ILO interface.
          netmask: Netmask to be configured on ILO interface.
          gateway: Gateway to be configured on ILO interface.
        """
        if self.ilo_version == ILO4:
            uri = '/rest/v1/Managers/1/EthernetInterfaces'
            status, response = self._rest_call(uri, 'GET', None, None)
            self._check_response('Error while getting eth interfaces', status, response)
            eth_uris = []
            for member in response['links']['Member']:
                eth_uris.append(member['href'])

            eth_uri_to_configure = None
            for eth_uri in eth_uris:
                status, response = self._rest_call(eth_uri, 'GET', None, None)
                self._check_response('ILO Error getting ethernet interface', status, response)
                if response['MacAddress'].lower() == mac.lower():
                    eth_uri_to_configure = eth_uri
                    break
            else:
                raise StandardError("Unable to find mac address '%s'" % mac)

        else:
            uri = '/redfish/v1/Managers/1/EthernetInterfaces/'
            status, response = self._rest_call(uri, 'GET', None, None)
            self._check_response('Error while getting eth interfaces', status, response)
            eth_uris = []
            for member in response['Members']:
                eth_uris.append(member['@odata.id'])

        eth_uri_to_configure = None
        for eth_uri in eth_uris:
            status, response = self._rest_call(eth_uri, 'GET', None, None)
            self._check_response('ILO Error getting ethernet interface', status, response)
            if response['MACAddress'].lower() == mac.lower():
                eth_uri_to_configure = eth_uri
                break
        else:
            raise StandardError("Unable to find mac address '%s'" % mac)

        if self.ilo_version == ILO5:
            static_ip_setting = {'Oem': {'Hpe': {'DHCPv4': {'Enabled': False}}}}
            status, response = self._rest_call(eth_uri_to_configure, 'PATCH', None, static_ip_setting)
            self._check_response('Error while setting address origin to Static', status, response)
        ipv4_settings = {}
        ipv4_settings['IPv4Addresses'] = [
         {'Address': ipv4, 
            'Gateway': gateway, 
            'SubnetMask': netmask}]
        status, response = self._rest_call(eth_uri_to_configure, 'PATCH', None, ipv4_settings)
        self._check_response('Error while setting ipv4 address', status, response)
        return

    def reset_ilo(self):
        """
        Resets ILO.
        """
        ilo_ip = self.ip
        if self.ip.startswith('[') and self.ip.endswith(']'):
            ilo_ip = self.ip[1:-1]
        ilo_reset_cmd = [
         'reset', '/map1']
        out, _, _ = foundation_tools.ssh(None, ilo_ip, ilo_reset_cmd, throw_on_error=False, log_on_error=False, user=self.user, password=self.password, key_filename=None, look_for_keys=False)
        if 'resetting ilo' not in out.lower():
            raise StandardError('Unable to reset ILO')
        time.sleep(90)
        return

    def get_ilo_license(self):
        """
        Get ILO License.
        """
        uri = '/rest/v1/Managers/1'
        name = 'Hp'
        if self.ilo_version == ILO5:
            uri = '/redfish/v1/Managers/1/'
            name = 'Hpe'
        status, response = self._rest_call(uri, 'GET', None, None)
        self._check_response('Error while gettting iLO License', status, response)
        return response['Oem'][name]['License']['LicenseString']

    def set_power_regulator_mode(self, power_regulator_mode):
        """
        Set power regulator settings.
        Args:
          power_regulator_mode: Power regulator mode to set.
        """
        if power_regulator_mode not in POWER_REGULATOR_MODES:
            raise StandardError('%s not a valid power regulator mode' % power_regulator_mode)
        if self.ilo_version == ILO4:
            uri = '/rest/v1/Systems/1/Bios/Settings'
            power_settings = {'PowerProfile': 'Custom', 'PowerRegulator': power_regulator_mode}
        else:
            uri = '/redfish/v1/Systems/1/Bios/Settings/'
            power_settings = {'Attributes': dict()}
            power_settings['Attributes']['WorkloadProfile'] = 'Custom'
            power_settings['Attributes']['PowerRegulator'] = power_regulator_mode
        status, response = self._rest_call(uri, 'PATCH', None, power_settings)
        self._check_response('Error while setting power regulator setting', status, response)
        return

    def set_numa_and_asr(self):
        """
        Sets:
          1. NUMA Group Size Optimization to "Clustered"
          2. ASR Status to "Disabled"
          3. Sub-NUMA Clustering to "Disabled"
          For Gen 10 servers as suggested in  HPE-168.
        """
        if self.ilo_version == ILO5:
            uri = '/redfish/v1/Systems/1/Bios/Settings/'
            numa_asr_settings = {}
            numa_asr_settings['Attributes'] = {'AsrStatus': 'Disabled', 
               'SubNumaClustering': 'Disabled', 
               'NumaGroupSizeOpt': 'Clustered'}
            status, response = self._rest_call(uri, 'PATCH', None, numa_asr_settings)
            self._check_response('Error while setting NUMA & ASR status settings', status, response)
        return

    def _set_ahci_sata_controller(self):
        """
          1. Enables AHCI mode SATA Controller
          2. Used for NEC servers, since by default
             they are coming up with RAID mode SATA
             controller, we need to change
             it to AHCI mode
        """
        uri = '/redfish/v1/Systems/1/Bios/Settings/'
        sata_controller_settings = {}
        sata_controller_settings['Attributes'] = {'EmbeddedSata': 'Ahci'}
        status, response = self._rest_call(uri, 'PATCH', None, sata_controller_settings)
        self._check_response('Error while enabling Ahci mode SATA controller', status, response)
        return


class RemoteBootHPilo(remote_boot.RemoteBoot):

    def get_hpilo(self):
        """
        Returns a ilo object.
        """
        hpilo = HPilo(self.node_config.ipmi_ip, self.node_config.ipmi_user, self.node_config.ipmi_password, self.node_config.get_logger())
        return hpilo

    def boot(self, iso, do_reset=True):
        """
        Method for booting node specific iso from foundation.
        Args:
          iso: ISO image path
          do_reset: Whether the server has to be rebooted or not
        """
        from http_server import FileServer
        logger = self.node_config.get_logger()
        hpilo = self.get_hpilo()
        ilo_license = hpilo.get_ilo_license()
        logger.info("Installed iLO License: '%s'" % ilo_license)
        if 'advanced' not in ilo_license.lower():
            raise StandardError("Installed iLO License is '%s', Advanced License is required" % ilo_license)
        hpilo.set_numa_and_asr()
        hpilo.set_power_regulator_mode('OsControl')
        self.set_virtualization()
        self.set_boot_mode('LegacyBios')
        foundation_ip = self.node_config.foundation_ip
        use_foundation_ips = getattr(self.node_config, 'use_foundation_ips', False)
        if use_foundation_ips:
            foundation_ip = self.node_config.foundation_ipmi_ip
        uri = FileServer.add_file(iso)
        image_url = 'http://%s:%s/%s' % (foundation_ip, HTTP_PORT, uri)
        logger.info('Url to download phoenix iso: %s' % image_url)
        self.wait_to_finish_post()
        hpilo.add_vmedia_image(image_url)
        if do_reset:
            hpilo.power_control('off')
            hpilo.power_control('on')

    def wait_to_finish_post(self):
        """
        Wait for the node to finish POST (Power-On Self-Test).
        """
        hpilo = self.get_hpilo()
        for _ in range(200):
            post_state = hpilo.get_post_state()
            if post_state == 'FinishedPost':
                break
            time.sleep(3)
        else:
            raise StandardError('Unable to Finish Power-On Self-Test in timely manner')

    def stop(self):
        """
        Method for stopping virtual media process (if any).
        """
        hpilo = self.get_hpilo()
        hpilo.eject_vmedia()

    def poweroff(self):
        """
        Method for powering off node.
        """
        hpilo = self.get_hpilo()
        hpilo.power_control('off')

    def set_first_boot_device(self):
        pass

    def set_virtualization(self):
        hpilo = self.get_hpilo()
        hpilo._set_virtualization_mode()

    def set_boot_mode(self, mode):
        """
        Set the boot mode.
        Args:
          mode: Boot mode (Uefi/LegacyBios)
        """
        hpilo = self.get_hpilo()
        hpilo._set_boot_mode(mode)

    def pre_boot_bios_settings(self):
        """
        Method to update BIOS settings before installation
        Returns:
          None
        """
        hpilo = self.get_hpilo()
        if not hpilo.isHPE_OEM() == 'NEC':
            return
        logger = self.node_config.get_logger()
        try:
            logger.info('Setting AHCI SATA controller')
            hpilo._set_ahci_sata_controller()
            hpilo.power_control('off')
            hpilo.power_control('on')
        except:
            logger.exception('Failed to set SATA Controller to AHCI')