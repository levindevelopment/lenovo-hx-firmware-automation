# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/remote_boot_ucsm.py
# Compiled at: 2019-02-15 12:42:10
import logging, os, requests, time, warnings, xml.etree.ElementTree as ElementTree
from foundation import folder_central
from foundation import foundation_tools
from foundation import remote_boot
NTNX_TEMPLATE = 'NTNX-SP-template'
SP_ASSOC_WAIT_CYCLES = 120
SP_ASSOC_INTERVAL_S = 30
UCSM_OBJECT_NAME_LEN = 16

class CiscoUCSM(object):

    def __init__(self, ip, user, password):
        self.cookie = None
        self.ip = ip
        self.user = user
        self.password = password
        return

    def __del__(self):
        """
        Since this class maintains an active session in the UCS manager, we
        should ensure that the session is invalidated after use. This destructor
        will take care of logging out from UCS manager.
        """
        self.logout()

    def __request(self, xml):
        """
        Posts XML request to the UCS manager.
        Args:
          xml: XML string to be posted to UCS manager.
        
        Returns:
          ElementTree object pointing to the root of the response XML.
        
        Raises:
          StandardError if the UCS manager ip is invalid or the xml request
          is invalid.
        """
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore')
            r = requests.post('https://%s:443/nuova' % self.ip, data=xml, verify=False, headers={'Content-Type': 'application/xml'})
            root = ElementTree.fromstring(r.text)
            if root.attrib['response'] != 'yes':
                raise StandardError('Failed to authenticate with management server')
            if 'errorCode' in root.attrib:
                raise StandardError('Request failed, error %s (%s)' % (
                 root.attrib['errorCode'], root.attrib['errorDescr']))
            r.stream = False
            return root

    def login(self):
        """
        Login to the UCS manager.
        """
        xml = '<aaaLogin inName="%s" inPassword="%s" />' % (
         self.user, self.password)
        root = self.__request(xml)
        self.cookie = root.attrib['outCookie']

    def logout(self):
        """
        Logout from the UCS manager.
        """
        if not self.cookie:
            return
        xml = '<aaaLogout cookie="%s" inCookie="%s" />' % (
         self.cookie, self.cookie)
        self.__request(xml)
        self.cookie = None
        return

    def get_object(self, dn, hierarchical=False):
        """
        Gets the configuration object corresponding to the domain name dn.
        Args:
          dn: Distinguished name of the XML object to be retrieved.
          hierarchical: Returns all child objects if true. Otherwise, returns only
              the element corresponding to the dn.
        
        Returns:
          ElementTree object to the root of the XML corresponding to dn.
        
        Raises:
          StandardError if the response XML is not in expected format.
        """
        hierarchical_flag = 'false'
        if hierarchical:
            hierarchical_flag = 'true'
        xml = '<configResolveDn dn="%s" cookie="%s" inHierarchical="%s" />' % (
         dn, self.cookie, hierarchical_flag)
        root = self.__request(xml)
        config = root.find('outConfig')
        if config == None:
            raise StandardError('Management server response missing outConfig element')
        children = list(config)
        if not children:
            return
        if len(children) != 1:
            raise StandardError('Management server response contains more than one object')
        return children[0]

    def get_class_objects(self, cls, hierarchical=False):
        """
        Gets the configuration object corresponding to the class.
        Args:
          cls: Class name of the object to be retrieved.
          hierarchical: Returns all child objects if true. Otherwise, returns only
              the element corresponding to the dn.
        
        Returns:
          List of ElementTree objects containing XML classes.
        """
        hierarchical_flag = 'false'
        if hierarchical:
            hierarchical_flag = 'true'
        xml = '<configResolveClasses cookie="%s" inHierarchical="%s"><inIds><Id value="%s"/></inIds></configResolveClasses>' % (
         self.cookie, hierarchical_flag, cls)
        root = self.__request(xml)
        config = root.find('outConfigs')
        if config == None:
            raise StandardError('Management server response missing outConfigs element')
        children = list(config)
        return children

    def set_object(self, dn, config, hierarchical=False):
        """
        Set the configuration object correnponding to the dn.
        Args:
          dn: Distinguished name of the object to be set.
          config: XML configuration to be submitted to UCS manager.
          hierarchical: True if config contains all children of the object with dn.
              Otherwise, it should be False.
        
        Returns:
          None
        """
        hierarchical_flag = 'false'
        if hierarchical:
            hierarchical_flag = 'true'
        xml = '<configConfMo cookie="%s" inHierarchical="%s" dn="%s" ><inConfig> %s </inConfig></configConfMo>' % (
         self.cookie, hierarchical_flag, dn, config)
        self.__request(xml)

    def set_objects(self, config, hierarchical=False):
        """
        Set the configuration objects.
        Args:
          config: XML configuration containing multiple objects, to be submitted
              to UCS manager.
          hierarchical: True if config contains all children of the object with dn.
              Otherwise, it should be False.
        """
        hierarchical_flag = 'false'
        if hierarchical:
            hierarchical_flag = 'true'
        xml = '<configConfMos cookie="%s" inHierarchical="%s"><inConfigs>%s</inConfigs></configConfMos>' % (
         self.cookie, hierarchical_flag, config)
        self.__request(xml)

    def get_service_profile_dn(self, server_name):
        """
        Gets the distinguished name for the service profile associated with
        a server.
        Args:
          server_name: Node serial number of the server.
        
        Returns:
          Distinguished name of the service profile associated with the server, if
          one is found. Otherwise, returns None.
        """
        servers = self.get_class_objects('computeItem')
        for server in servers:
            if server.attrib['serial'] == server_name:
                sp_dn = server.attrib['assignedToDn']
                return sp_dn

        return

    def get_service_profile_name(self, server_name):
        """
        Gets the name of the service profile associated with a server.
        Args:
          server_name: Node serial number of the server.
        
        Returns:
          Name of the service profile associated with the server, if
          one is found. Otherwise, returns None.
        """
        sp_dn = self.get_service_profile_dn(server_name)
        if sp_dn:
            index = sp_dn.find('/ls-') + 4
            return sp_dn[index:]
        return

    def power_control(self, sp_dn, option):
        """
        Power control action for a service profile. This function uses
        hard shutdown and power on options to ensure that power state changes
        for the node.
        Args:
          sp_dn: dn corresponding to the service profile.
          option : One of {up, down}
        """
        dn = '%s/power' % sp_dn
        if option in ('up', 'down'):
            state = 'admin-%s' % option
        else:
            raise StandardError('Invalid power control option (%s) received' % option)
        config = '<pair key="%s"><lsPower dn="%s" state="%s" status="created,modified" /></pair>' % (
         dn, dn, state)
        self.set_objects(config)

    def validate_node_serial(self, serial):
        """
        Validates whether the given node serial is available in UCS manager.
        Args:
          serial: Serial number of the node.
        
        Returns:
          None
        
        Raises:
          StandardError if the given node serial is not available.
        """
        if serial not in self.get_servers():
            raise StandardError("Server with serial '%s' is not available" % serial)

    def get_power_status(self, server):
        """
        Get power status of a server.
        Args:
          server: Node serial number of the server.
        
        Returns:
          "on" if the power is on and "off" otherwise.
        """
        self.validate_node_serial(server)
        dn = self.get_dn_from_serial(server)
        vmap = self.get_object(dn)
        return vmap.attrib['operPower']

    def get_dn_from_serial(self, serial):
        """
        Get dn for the corresponding to node with give serial.
        Args:
          serial: Node serial number of the server.
        
        Raises:
          StandardError if server is not found in UCS manager.
        """
        servers = self.get_class_objects('computeItem')
        for server in servers:
            if server.attrib['serial'] == serial:
                return server.attrib['dn']

        raise StandardError('Server with serial %s is not found' % serial)

    def get_server_dn_associated_to_service_profile(self, sp_name):
        """
        Gets the dn of the server associated to a service profile.
        Args:
          sp_name: Name of the service profile.
        
        Returns:
          Distinguished name of the server associated to the service profile.
          None if is not associated to any server.
        """
        sp_dn = 'org-root/ls-%s' % sp_name
        root = self.get_object(sp_dn)
        if root.attrib.get('pnDn'):
            return root.attrib['pnDn']
        return

    def get_servers(self):
        """
        Get all the servers configured in the UCS manager.
        Returns:
          List of server serial numbers.
        """
        servers_list = []
        servers = self.get_class_objects('computeItem')
        for server in servers:
            servers_list.append(server.attrib['serial'])

        return servers_list

    def create_vmedia_policy(self, policy_name, desc='', retry_on_mount='yes'):
        """
        Create a vmedia policy on UCS manager.
        Args:
          policy_name: Name of the vmedia policy.
          desc: Description of the policy.
          retry_on_mount: If True, retries mount of failure. Else if first attempt
              fails, it won't try again.
        """
        dn = 'org-root/mnt-cfg-policy-%s' % policy_name
        config = '<pair key="%s"><cimcvmediaMountConfigPolicy descr="%s" dn="%s" name="%s" policyOwner="local" retryOnMountFail="%s" status="created,modified"/></pair>' % (
         dn, desc, dn, policy_name, retry_on_mount)
        self.set_objects(config)

    def vmedia_mount_add(self, mount_name, policy_name, remote_ip, remote_path, remote_file, desc=''):
        """
        Adds a vmedia mount to a vmedia policy.
        Args:
          mount_name: Name to be given for the mount point.
          policy_name: Name of the vmedia policy to which this mount point should
              be added.
          remote_ip: IP of the remote server.
          remote_path: Complete path of the remote share.
          remote_file: File name of the image file in remote share.
          desc: Description of the mount point.
        """
        dn = 'org-root/mnt-cfg-policy-%s/cfg-mnt-entry-%s' % (
         policy_name, mount_name)
        config = '<pair key="%s"><cimcvmediaConfigMountEntry description="%s" deviceType="cdd" dn="%s" imageFileName="%s" imagePath="%s" mappingName="%s" mountProtocol="nfs" password="" remoteIpAddress="%s" remotePort="2049" status="created,modified" userId="" /></pair>' % (
         dn, desc, dn, remote_file, remote_path,
         mount_name, remote_ip)
        self.set_objects(config)

    def vmedia_mount_remove(self, mount_name, policy_name):
        """
        Remove a vmedia mouont from a vmedia policy
        Args:
          mount_name: Name of the mount point to be deleted.
          policy_name: Name of the vmedia policy from which mount point has
              to be deleted.
        """
        dn = 'org-root/mnt-cfg-policy-%s/cfg-mnt-entry-%s' % (
         policy_name, mount_name)
        config = '<pair key="%s"><cimcvmediaConfigMountEntry dn="%s" status="deleted" /></pair>' % (
         dn, dn)
        self.set_objects(config)

    def delete_vmedia_policy(self, policy_name):
        """
        Delete the given vmedia policy.
        Args:
          policy_name: Name of the vmedia policy to be deleted.
        """
        dn = 'org-root/mnt-cfg-policy-%s' % policy_name
        config = '<pair key="%s"><cimcvmediaMountConfigPolicy dn="%s" status="deleted" /></pair>' % (
         dn, dn)
        self.set_objects(config)

    def current_max_sessions(self):
        """
        Get current value associated with maximum sessions in web session limits.
        Args:
          None
        Returns:
          str: Current value associated with maximum sessions
        """
        dn = 'sys/svc-ext/web-svc-limits'
        root = self.get_object(dn)
        return root.attrib.get('totalSessions')

    def set_maximum_sessions_limit(self, max_sessions):
        """
        Set limit on number of active web sessions.
        Args:
          max_sessions (str): number of active web sessions.
        """
        dn = 'sys/svc-ext/web-svc-limits'
        xml = '<pair key="%s"><commWebSvcLimits totalSessions="%s" dn="%s" status="created,modified" /></pair>' % (
         dn, max_sessions, dn)
        self.set_objects(xml)

    def set_vmedia_policy(self, service_profile_dn, policy_name):
        """
        Sets the vmedia policy for a service profile.
        Args:
          service_profile_dn: dn of the service profile.
          policy_name: Name of the vmedia policy
        """
        xml = '<lsServer vmediaPolicyName="%s" />' % policy_name
        self.set_object(service_profile_dn, xml)

    def is_iso_mounted(self, mount_name, server):
        """
        Checks whether a vmedia has been mounted successfully or not.
        Mount entry may not appear instantly. Hence, retries are needed.
        Args:
          mount_name: Name of the mount point entry.
          server: Node serial number of the server.
        
        Returns:
          Tuple (mount status, error if mount failed).
        """
        self.validate_node_serial(server)
        dn = self.get_dn_from_serial(server)
        mount_status_dn = '%s/mgmt/actual-mount-list' % dn
        err = ''
        for _ in range(10):
            root = self.get_object(mount_status_dn, hierarchical=True)
            for entry in root:
                if entry.tag != 'cimcvmediaActualMountEntry':
                    continue
                if entry.attrib['mappingName'] == mount_name and entry.attrib['deviceType'] == 'cdd':
                    if entry.attrib['operMountStatus'].lower() == 'mounted':
                        return (True, '')
                    err = 'Mount failed with error: %s' % entry.attrib['errorType']

            time.sleep(3)

        if not err:
            err = 'Unable to find mount entry'
        return (False, err)

    def create_boot_policy(self, policy_name, desc='', iso_boot=True):
        """
        Creates a boot policy with virtual media and local storage as
        boot options. Default boot order:
        1. CIMC Virtual Media, 2. Embedded Local Disk, 3. Internal SD card.
        Args:
          policy_name: Name of the boot policy.
          desc: Description of the boot policy.
          iso_boot: If True, sets virtual media as first boot device. If False,
              sets local storage as first boot device.
        """
        dn = 'org-root/boot-policy-%s' % policy_name
        if iso_boot:
            vmedia_order = 1
            storage_order = 2
        else:
            storage_order = 1
            vmedia_order = 3
        vmedia_xml = '<lsbootVirtualMedia order="%d" rn="read-only-remote-cimc-vm" />' % vmedia_order
        storage_xml = '<lsbootStorage order="%d" rn="storage" ><lsbootLocalStorage rn="local-storage"><lsbootEmbeddedLocalDiskImage order="%d" rn="embedded-local-jbod" /><lsbootUsbFlashStorageImage order="%d" rn="sd-card" /></lsbootLocalStorage></lsbootStorage>' % (
         storage_order, storage_order, storage_order + 1)
        xml = '<pair key="%s"><lsbootPolicy dn="%s" descr="%s" name="%s" policyOwner="local" rebootOnUpdate="no" status="created,modified">%s%s</lsbootPolicy></pair>' % (
         dn, dn, desc, policy_name, vmedia_xml, storage_xml)
        self.set_objects(xml)

    def set_boot_policy(self, service_profile_dn, policy):
        """
        Sets the boot policy for a service profile.
        Args:
          service_profile_dn: Distinguished name of the service profile.
          policy: Name of the boot policy.
        
        Returns:
          None
        """
        xml = '<lsServer bootPolicyName="%s" />' % policy
        self.set_object(service_profile_dn, xml)

    def delete_boot_policy(self, policy_name):
        """
        Delete a boot policy from UCS manager.
        Args:
          policy_name: Name of the boot policy.
        
        Returns:
          None
        """
        dn = 'org-root/boot-policy-%s' % policy_name
        xml = '<pair key="%s"><lsbootPolicy dn="%s" status="deleted" /></pair>' % (
         dn, dn)
        self.set_objects(xml)

    def create_local_disk_policy(self, policy_name, desc=''):
        """
        Creates a local disk configuration policy which exposes flex flash drive.
        Args:
          policy_name: Name of the policy to be created.
          desc: Description of the policy.
        
        Returns:
          None
        """
        dn = 'org-root/local-disk-config-%s' % policy_name
        xml = '<storageLocalDiskConfigPolicy descr="%s" dn="%s" flexFlashRAIDReportingState="enable" flexFlashState="enable" mode="any-configuration" name="%s" protectConfig="no"/>' % (
         desc, dn, policy_name)
        self.set_object(dn, xml)

    def set_local_disk_policy(self, service_profile_dn, policy):
        """
        Assigns a local disk configuration policy to a service profile.
        Args:
          service_profile_dn: Distinguished name of the service profile.
          policy: Name of the local disk configuration policy.
        
        Returns:
          None
        """
        xml = '<lsServer localDiskPolicyName="%s" />' % policy
        self.set_object(service_profile_dn, xml)

    def delete_local_disk_policy(self, policy_name):
        """
        Deletes a local disk config policy.
        Args:
          policy_name: Name of the local disk config policy to be deleted.
        
        Returns:
          None
        """
        dn = 'org-root/local-disk-config-%s' % policy_name
        xml = '<pair key="%s"><storageLocalDiskConfigPolicy dn="%s" status="deleted" /></pair>' % (
         dn, dn)
        self.set_objects(xml)

    def set_cimc_ip(self, ipmi_ip, ipmi_netmask, ipmi_gateway, serial):
        self.validate_node_serial(serial)
        xml = '<vnicIpV4StaticAddr addr="%s" defGw="%s" rn="ipv4-static-addr" subnet="%s" />' % (
         ipmi_ip, ipmi_gateway, ipmi_netmask)
        node_dn = self.get_dn_from_serial(serial)
        dn = '%s/mgmt/ipv4-static-addr' % node_dn
        self.set_object(dn, xml)

    def create_service_profile_template(self, template_name, type='initial-template', desc=''):
        """
        Create service profile template.
        Args:
          template_name: Name of the service profile template.
          type: Type of the template. Must be one of
              {"initial-template", "updating-template"}.
          desc: Description for the template.
        
        Returns:
          None
        """
        dn = 'org-root/ls-%s' % template_name
        config = '<pair key="%s"><lsServer agentPolicyName="" descr="%s" dn="%s" extIPState="none" resolveRemote="yes" status="created,modified" type="%s"><vnicConnDef dn="%s/conn-def" lanConnPolicyName="" sanConnPolicyName="" /></lsServer></pair>' % (
         dn, desc, dn, type, dn)
        self.set_objects(config)

    def get_profile_type(self, profile_name):
        """
        Returns the type of the profile.
        Args:
          profile_name: Name of the profile.
        
        Returns:
          "initial-template" if this is an initial service profile template.
          "updating-template" if this is an updating service profile template.
          "instance" if this is a service profile.
          None if this is not a service profile or a template.
        """
        dn = 'org-root/ls-%s' % profile_name
        root = self.get_object(dn)
        if root is not None:
            return root.attrib['type']
        return

    def create_service_profile_from_template(self, sp_name, template_name):
        """
        Create service profile from the given service profile template.
        Args:
          sp_name: Name of the service profile.
          template_name: Name of the template.
        
        Returns:
          None
        """
        dn = 'org-root/ls-%s' % template_name
        config = '<lsInstantiateNNamedTemplate cookie="%s" dn="%s" inErrorOnExisting="true" inHierarchical="false" inTargetOrg="org-root"><inNameSet><dn value="%s" /></inNameSet></lsInstantiateNNamedTemplate>' % (
         self.cookie, dn, sp_name)
        self.__request(config)

    def delete_profile(self, profile_name):
        """
        Delete a service profile or a template.
        Args:
          profile_name: Name of the service profile or template to be deleted.
        
        Returns:
          None
        """
        dn = 'org-root/ls-%s' % profile_name
        config = '<pair key="%s"><lsServer dn="%s" status="deleted" /></pair>' % (
         dn, dn)
        self.set_objects(config)

    def associate_service_profile_to_server(self, sp_name, server):
        """
        Associates a service profile to a server.
        Args:
          sp_name: Name of the service profile.
          server: Serial number of the server.
        
        Returns:
          None
        """
        self.validate_node_serial(server)
        dn = 'org-root/ls-%s/pn' % sp_name
        server_dn = self.get_dn_from_serial(server)
        config = '<pair key="%s"><lsBinding dn="%s" pnDn="%s" restrictMigration="no" status="created,modified" /></pair>' % (
         dn, dn, server_dn)
        self.set_objects(config)

    def disassociate_service_profile_from_server(self, server):
        """
        Disassociates a service profile from a server.
        Args:
          server: Serial number of the server to be disassociated from a
              service profile.
        
        Returns:
          None
        """
        cur_sp_dn = self.get_service_profile_dn(server)
        if not cur_sp_dn:
            return
        config = '<pair key="%s"><lsBinding dn="%s" status="deleted" /></pair>' % (
         cur_sp_dn, cur_sp_dn)
        self.set_objects(config)
        return

    def wait_for_service_profile_disassociation(self, sp_name, server, logger=None):
        """
        Waits until a service profile is associated to a server. This process of
        association can take up to 15 mins.
        Args:
          sp_name: Name of the service profile.
          server: Serial number of the server.
          logger: Logging object to which message should be logged.
        
        Returns:
          None
        """
        logger = logger or logging
        self.validate_node_serial(server)
        total_wait_time = SP_ASSOC_WAIT_CYCLES * SP_ASSOC_INTERVAL_S
        server_dn = self.get_dn_from_serial(server)
        for i in range(SP_ASSOC_WAIT_CYCLES):
            root = self.get_object(server_dn)
            if root.attrib['association'] == 'none':
                break
            else:
                message = '[%d/%ds] Waiting to get service profile %s disassociated from server %s' % (
                 i * SP_ASSOC_INTERVAL_S, total_wait_time,
                 sp_name, server)
                logger.info(message)
                time.sleep(SP_ASSOC_INTERVAL_S)
        else:
            raise StandardError('Timed out waiting for service profile (%s) to get disassociated from server (%s)' % (
             sp_name, server))

    def wait_for_service_profile_association(self, sp_name, server, logger=None):
        """
        Waits until a service profile is associated to a server. This process of
        association can take up to 15 mins.
        Args:
          sp_name: Name of the service profile.
          server: Serial number of the server.
          logger: Logging object to which message should be logged.
        
        Returns:
          None
        """
        self.validate_node_serial(server)
        total_wait_time = SP_ASSOC_WAIT_CYCLES * SP_ASSOC_INTERVAL_S
        sp_dn = 'org-root/ls-%s' % sp_name
        server_dn = self.get_dn_from_serial(server)
        for i in range(SP_ASSOC_WAIT_CYCLES):
            root = self.get_object(sp_dn)
            if root.attrib['assocState'] == 'associated':
                binding_dn = '%s/pn' % sp_dn
                bind_root = self.get_object(binding_dn)
                assigned_server = bind_root.attrib['assignedToDn']
                if assigned_server == server_dn:
                    break
                else:
                    raise StandardError('Service profile %s got assigned to some other server at %s' % (
                     sp_name, assigned_server))
            else:
                message = '[%d/%ds] Waiting to get service profile %s assigned to server %s' % (
                 i * SP_ASSOC_INTERVAL_S, total_wait_time,
                 sp_name, server)
                if logger:
                    logger.info(message)
                else:
                    logging.info(message)
                time.sleep(SP_ASSOC_INTERVAL_S)
        else:
            raise StandardError('Timed out waiting for service profile (%s) to get associated with server (%s). Please check FSM tab for server and service profile in UCS manager for errors' % (
             sp_name, server))

    def get_mac_availability_in_pool(self, pool='default', raise_on_error=True):
        """
        Get the available number of MAC addresses in a given pool.
        Args:
          pool: Name of the mac pool available or used in UCS manager.
          raise_on_error: If True, raises any exception occurred. Else ignores it.
        
        Returns:
          The number of mac addresses available in the given pool. If the pool is
          not found and raise_on_error is False, 0 is returned.
        
        Raises:
          StandardError if pool name provided is not present.
        """
        try:
            mac_pool = self.get_object('org-root/mac-pool-%s' % pool)
            return int(mac_pool.attrib['size']) - int(mac_pool.attrib['assigned'])
        except:
            if raise_on_error:
                logging.exception('Error while reading mac pool (%s) details' % pool)
                raise StandardError('Invalid mac pool: %s' % pool)

        return 0

    def get_cimc_version(self, server):
        """
        Get CIMC version of the given server.
        Args:
          server: Node serial number of the server.
        
        Returns:
          The version of CIMC firmware on the server. If the version is not
          available, returns None.
        """
        self.validate_node_serial(server)
        dn = self.get_dn_from_serial(server)
        firmware = self.get_object('%s/mgmt/fw-system' % dn)
        return firmware.attrib.get('version') or None

    def get_flexflash_firmware(self, server):
        """
        Gets SDCard firmware version of the given server.
        Args:
          server: Node serial number of the server.
        
        Returns:
          The version of SD card firmware on the server. If the version is not
          available, returns None.
        """
        self.validate_node_serial(server)
        dn = self.get_dn_from_serial(server)
        flexflash = self.get_object('%s/board/storage-flexflash-1/fw-system' % dn)
        return flexflash.attrib.get('version') or None

    def has_flexflash_drive(self, node_serial):
        """
        Checks whether a server has a flex flash card present in it.
        Args:
          node_serial: Node serial number of the server.
        
        Returns:
          True if flex flash card is present, False otherwise.
        """
        self.validate_node_serial(node_serial)
        server_dn = self.get_dn_from_serial(node_serial)
        dn = '%s/board/storage-flexflash-1' % server_dn
        root = self.get_object(dn, hierarchical=True)
        if root is None:
            return False
        for child in list(root):
            if child.tag == 'storageFlexFlashCard':
                return True

        return False

    def format_sd_card(self, node_serial):
        """
        Formats the flex flash drive in a server. This method causes UCS manager
        to simply delete all partitions present on the disk. If the method is
        called for a server which does not have a flex flash drive, it will
        raise an exception.
        Args:
          node_serial: Node serial number of the server.
        
        Returns:
          None
        """
        self.validate_node_serial(node_serial)
        server_dn = self.get_dn_from_serial(node_serial)
        dn = '%s/board/storage-flexflash-1' % server_dn
        xml = '<storageFlexFlashController operationRequest="format" dn="%s" status="created,modified"  sacl="addchild,del,mod"></storageFlexFlashController>' % dn
        self.set_object(dn, xml)
        time.sleep(5)

    def get_ucs_manager_version(self):
        """
        Retrieves the ucs manager version currently running on the fabric
        interconnects.
        
        Returns:
          UCS manager version as string.
        """
        dn = 'sys/mgmt/fw-system'
        xml = self.get_object(dn)
        version = xml.get('version')
        return version

    def has_gpu_model(self, node_serial, model):
        """
        Checks whether a server has a specific GPU model.
        
        Args:
          node_serial: Node serial of the server.
          model: Name of the GPU model (Ex: "Nvidia M10", "Nvidia M60") as seen
              in UCS manager.
        
        Returns:
          True if the server has the GPU model. False otherwise.
        """
        server_dn = self.get_dn_from_serial(node_serial)
        dn = '%s/board' % server_dn
        root = self.get_object(dn, hierarchical=True)
        if root is None:
            return False
        for child in list(root):
            if child.tag == 'graphicsCard':
                if child.get('model', '').lower() == model.lower():
                    return True

        return False

    def get_available_vlans(self):
        """
        Retrieves all available vlans in ucs manager.
        
        Returns:
          List of ElementTree objects corresponding to available vlans.
        """
        root = self.get_object('fabric/lan', hierarchical=True)
        vlan_xml_list = []
        for child in list(root):
            if child.tag == 'fabricVlan' and (child.get('rn') or child.get('dn')):
                vlan_xml_list.append(child)

        return vlan_xml_list

    def get_all_vlan_details(self):
        """
        Retrieves details of all vlans available in ucs manager.
        
        Returns:
          List of dict objects of the following form:
          {
            "name": "<name of vlan object>",
            "dn": "<distinguished name of the vlan object>",
            "vlan_id": "<vlan tag>",
            "native": "<boolean denoting whether this is a native vlan>"
          }
        """
        vlans = self.get_available_vlans()
        vlans_list = []
        for vlan in vlans:
            vlan_dict = {}
            dn = vlan.get('dn')
            if not dn:
                dn = 'fabric/lan/%s' % vlan.get('rn')
            vlan_id = vlan.get('id')
            vlan_dict['name'] = vlan.get('name')
            vlan_dict['dn'] = dn
            vlan_dict['vlan_id'] = vlan_id
            native = vlan.get('defaultNet', 'no')
            if native == 'yes':
                vlan_dict['native'] = True if 1 else False
                vlans_list.append(vlan_dict)

        return vlans_list

    def get_available_mac_pools(self):
        """
        Retrieves all available mac pools in ucs manager.
        
        Returns:
          List of ElementTree objects for all mac pools in ucs manager.
        """
        root = self.get_object('org-root', hierarchical=True)
        mac_pool_list = []
        for child in list(root):
            if child.tag == 'macpoolPool' and (child.get('rn') or child.get('dn')):
                mac_pool_list.append(child)

        return mac_pool_list

    def get_all_mac_pools_details(self):
        """
        Retrieves the details of all mac pools available in ucs manager.
        
        Returns:
          List of dict objects of the following form:
          {
            "name": "<name of the mac pool>",
            "size": "<size of the mac pool>",
            "assigned": "<number of mac addresses which are already assigned>",
            "address_from": "<first address of the mac address range>",
            "address_to": "<last address of the mac address range>"
          }
        """
        mac_pools = self.get_available_mac_pools()
        pools_list = []
        for pool in mac_pools:
            pool_dict = {}
            dn = pool.get('dn')
            if not dn:
                dn = 'org-root/%s' % pool.get('rn')
            pool_dict['name'] = pool.get('name')
            pool_dict['size'] = pool.get('size')
            pool_dict['assigned'] = pool.get('assigned')
            for child in list(pool):
                if child.tag == 'macpoolBlock':
                    pool_dict['address_from'] = child.get('from')
                    pool_dict['address_to'] = child.get('to')
                    break

            pools_list.append(pool_dict)
            pool_dict['dn'] = dn

        return pools_list

    def get_cimc_oob_net_details(self, node_serial):
        """
        Retrieves the out of band network settings of cimc.
        Args:
          node_serial: Serial of the server.
        
        Returns:
          Dictionary of the following form:
          {
            "cimc_ip": "<OOB ip of cimc>",
            "cimc_gateway": "<gateway ip of cimc>",
            "subnet_mask": "<subnet mask of cimc>"
          }
        """
        node_dn = self.get_dn_from_serial(node_serial)
        dn = '%s/mgmt/ipv4-static-addr' % node_dn
        root = self.get_object(dn)
        ip = root.get('addr')
        gw = root.get('defGw')
        subnet = root.get('subnet')
        return {'cimc_ip': ip, 
           'cimc_gateway': gw, 
           'subnet_mask': subnet}

    def get_nodepos_and_model(self, serial):
        """
        Map the node position and model of each server using the slotId
        and model name  respectively.
        
        Args:
          serial: Serial number of the server
        Returns:
          Tuple of the following form.
          (<position>, <model>)
        """
        servers_list = self.get_class_objects('computeItem')
        for node in servers_list:
            if node.attrib['serial'] == serial:
                if node.tag == 'computeBlade':
                    return (chr(int(node.attrib['slotId']) + 64), node.attrib['model'])
                if node.tag == 'computeRackUnit':
                    return (chr(65), node.attrib['model'])
                return (None, None)

        return


class RemoteBootUCSM(remote_boot.RemoteBoot):

    def __init__(self, node_config):
        remote_boot.RemoteBoot.__init__(self, node_config)
        self.ucsm = None
        if not hasattr(node_config, 'ucsm_node_serial') or not hasattr(node_config, 'ucsm_ip') or not hasattr(node_config, 'ucsm_user') or not hasattr(node_config, 'ucsm_password'):
            raise StandardError('NodeConfig object must have the attributes: ucsm_node_serial, ucsm_ip, ucsm_user, ucsm_password')
        self.node_serial = node_config.ucsm_node_serial
        if not getattr(self.node_config, 'ucsm_object_prefix', None):
            self.node_config.ucsm_object_prefix = 'fdtn'
        prefix_len = UCSM_OBJECT_NAME_LEN - len(self.node_serial)
        self.policy_name = ('%s%s' % (self.node_config.ucsm_object_prefix[0:prefix_len],
         self.node_serial))[0:UCSM_OBJECT_NAME_LEN]
        if node_config.sp_name:
            self.policy_name = node_config.sp_name
        self.vmedia_policy_name = ('{}{}').format(self.node_config.ucsm_object_prefix, self.node_serial)
        self.logger = node_config.get_logger()
        self.phoenix_mount_name = 'foundation_mnt'
        return

    def get_ucsm(self):
        """
        Returns a UCSM object.
        """
        if self.ucsm and self.ucsm.cookie:
            return self.ucsm
        ucsm = CiscoUCSM(self.node_config.ucsm_ip, self.node_config.ucsm_user, self.node_config.ucsm_password)
        ucsm.login()
        self.ucsm = ucsm
        return ucsm

    def wait_for_poweroff(self, retries=200, raise_on_timeout=True):
        """
        Wait for the node to power down.
        """
        ucsm = self.get_ucsm()
        for _ in range(retries):
            status = ucsm.get_power_status(self.node_serial)
            if status == 'off':
                self.logger.info('Node is powered off')
                break
            self.logger.info('Waiting for node to power off')
            time.sleep(3)

        if raise_on_timeout:
            raise StandardError('Server (%s) did not shut down in a timely manner' % self.node_serial)

    def wait_for_poweron(self, retries=200, raise_on_timeout=True):
        """
        Wait for the node to power on.
        """
        ucsm = self.get_ucsm()
        for _ in range(retries):
            status = ucsm.get_power_status(self.node_serial)
            if status == 'on':
                self.logger.info('Node is powered on')
                break
            self.logger.info('Waiting for node to power on')
            time.sleep(3)

        if raise_on_timeout:
            raise StandardError('Server (%s) did not power up in a timely manner' % self.node_serial)

    def boot(self, iso, do_reset=True):
        """
        Boots a node with the given iso. If a service profile is not associated
        with the server, this function creates a service profile from nutanix
        template and associates it with the server. Since changing the boot
        policy for a service profile (which is associated to a server) is a time
        consuming process, this method first assigns a boot policy to the service
        profile and then associates the service profile to the server.
        Args:
          iso: Path to the iso image.
          do_reset: Resets the node if True. Otherwise, no power action is
              performed on the node.
        Raises:
          StandardError if mac pool doesn't have enough addresses.
        """
        ucsm = self.get_ucsm()
        server = self.node_serial
        logger = self.logger
        sp_name = self.policy_name
        sp_dn = ucsm.get_service_profile_dn(server)
        if not sp_dn:
            raise StandardError('Server (%s) does not have a service profile associated with it' % server)
        nfs_path = folder_central.get_nfs_path_from_tmp_path(iso)
        nfs_folder, nfs_file = os.path.split(nfs_path)
        foundation_ip = foundation_tools.get_my_ip(self.node_config.ucsm_ip)
        available_macs = ucsm.get_mac_availability_in_pool(raise_on_error=False)
        if available_macs < 2:
            raise StandardError('The default mac pool in management server has only %d available addresses. It must have at least 2 mac addresses for the service profile association to succeed. Please add more addresses to the default mac pool' % available_macs)
        ucsm.create_vmedia_policy(self.vmedia_policy_name, desc='VMedia policy used by Foundation to boot node in to phoenix')
        ucsm.vmedia_mount_add(self.phoenix_mount_name, self.vmedia_policy_name, foundation_ip, nfs_folder, nfs_file, desc='phoenix mount point in FVM')
        ucsm.set_vmedia_policy(sp_dn, self.vmedia_policy_name)
        logger.info('Created vmedia policy %s' % self.vmedia_policy_name)
        ucsm.wait_for_service_profile_association(sp_name, server, logger=logger)
        mount_status, err = ucsm.is_iso_mounted(self.phoenix_mount_name, server)
        if not mount_status:
            raise StandardError('Failed to mount phoenix iso with error: %s' % err)
        if do_reset:
            for _ in range(10):
                status = ucsm.get_power_status(server)
                if status == 'on':
                    ucsm.power_control(sp_dn, 'down')
                    self.wait_for_poweroff(retries=20, raise_on_timeout=False)
                else:
                    break
            else:
                self.wait_for_poweroff(retries=20)

            for _ in range(10):
                ucsm.power_control(sp_dn, 'up')
                self.wait_for_poweron(retries=20, raise_on_timeout=False)
                status = ucsm.get_power_status(server)
                if status == 'on':
                    break
            else:
                self.wait_for_poweron(retries=20)

    def stop(self):
        """
        Method for stopping virtual media (if any).
        """
        ucsm = self.get_ucsm()
        ucsm.vmedia_mount_remove(self.phoenix_mount_name, self.vmedia_policy_name)
        ucsm.delete_vmedia_policy(self.vmedia_policy_name)

    def poweroff(self):
        """
        Power off the node.
        """
        ucsm = self.get_ucsm()
        sp_dn = ucsm.get_service_profile_dn(self.node_serial)
        if sp_dn:
            ucsm.power_control(sp_dn, 'down')
        else:
            self.logger.info('No service profile associated with the server %s' % self.node_serial)

    def set_first_boot_device(self):
        """
        Virtual method for setting satadom / raid as first boot device
        """
        pass


def get_ucsm_object(ucsm_ip, ucsm_user, ucsm_password):
    ucsm = CiscoUCSM(ucsm_ip, ucsm_user, ucsm_password)
    try:
        ucsm.login()
    except Exception as e:
        if 'Authentication failed' in str(e):
            raise StandardError('Failed to login to management server with the provided credentials. Please provide valid username and password')
        raise StandardError('Unable to login to management server')

    return ucsm


def set_cimc_ip_via_ucsm(ucsm_ip, ucsm_user, ucsm_password, ipmi_ip, ipmi_netmask, ipmi_gateway, serial):
    """
    Sets the out of band management ip of CIMC.
    Args:
      ucsm_ip: IP address of UCS manager.
      ucsm_user: Username for the UCS manager account.
      ucsm_password: Password for the UCS manager account.
      ipmi_ip: IP to be set to the CIMC.
      ipmi_netmask: Netmask of the CIMC IP.
      ipmi_gateway: Gateway of the CIMC IP.
      serial: Serial number of the node.
    
    Returns:
      None
    
    Raises:
      StandardError if invalid credentials are provided or if Foundation fails
      to configure the CIMC IP.
    """
    ucsm = get_ucsm_object(ucsm_ip, ucsm_user, ucsm_password)
    ucsm.set_cimc_ip(ipmi_ip, ipmi_netmask, ipmi_gateway, serial)
    time.sleep(15)


def discover_ucsm_nodes(ucsm_ip, ucsm_user, ucsm_password):
    """
    Discovers details of all servers, vlans and mac pools available in
    ucs managers.
    
    Args:
      ucsm_ip: Ip address of ucs manager.
      ucsm_user: User name to login to ucs manager.
      ucsm_password: Password to be used while logging in to ucs manager.
    
    Returns:
      Dictionary of the following form:
      {
        "mac_pools": [<list of available mac pools with details>],
        "vlans": [<list of available vlans with details>],
        "servers": [<list of servers available and its details>]
      }
    """
    ucsm = get_ucsm_object(ucsm_ip, ucsm_user, ucsm_password)
    data = {'servers': [], 'vlans': [], 'mac_pools': []}
    servers = ucsm.get_servers()
    for server in servers:
        server_dict = {}
        sp_dn = ucsm.get_service_profile_dn(server)
        sp_name = ucsm.get_service_profile_name(server)
        cimc_nw_settings = ucsm.get_cimc_oob_net_details(server)
        node_pos, model = ucsm.get_nodepos_and_model(server)
        server_dict['server_serial'] = server
        server_dict['service_profile_dn'] = sp_dn
        server_dict['service_profile_name'] = sp_name
        server_dict['cimc_settings'] = cimc_nw_settings
        server_dict['node_position'] = node_pos
        server_dict['model'] = model
        data['servers'].append(server_dict)

    data['vlans'] = ucsm.get_all_vlan_details()
    data['mac_pools'] = ucsm.get_all_mac_pools_details()
    return data