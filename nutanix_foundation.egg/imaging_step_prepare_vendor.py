# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_prepare_vendor.py
# Compiled at: 2019-02-15 12:42:10
import json, os, xml.etree.ElementTree as ElementTree
from distutils.version import LooseVersion as LV
from string import Template
import folder_central
from imaging_step import ImagingStepNodeTask
from imaging_step_type_detection import CLASS_UCSM
from remote_boot_ucsm import CiscoUCSM
CREATE_UCSM_OBJECTS = 'Creating service profile and policies for node'
ASSOCIATE_SERVICE_PROFILE = 'Associating service profile to node'
UCSM_OBJECT_NAME_LEN = 16

class ImagingStepPrepareUCSM(ImagingStepNodeTask):

    def get_progress_timing(self):
        return [
         (
          CREATE_UCSM_OBJECTS, 1),
         (
          ASSOCIATE_SERVICE_PROFILE, 14)]

    def validate_xml(self, xml, xml_type):
        """
        Checks for XML parser errors.
        Args:
          xml: XML in string format.
          xml_type: UCSM object type corresponding to this xml.
        
        Returns:
          None
        
        Raises:
          StandardError if the input xml is invalid.
        """
        try:
            r = ElementTree.fromstring(xml)
        except:
            message = 'Invalid xml type (%s) provided' % xml_type
            self.logger.exception(message)
            raise StandardError(message)

    def validate_service_profile_template(self, sp_template, index):
        """
        Validates a given service profile template.
        Args:
          sp_template: Dictionary object corresponding to service profile template.
          index: Index of the template object in the ucsm_objects list in template
              file.
        
        Returns:
          True if the template is valid and False otherwise.
        """
        keys = [
         'object_name', 'object_type', 'desc', 'name', 'xml_source']
        missing_keys = []
        empty_keys = []
        for key in keys:
            if key not in sp_template.keys():
                missing_keys.append(key)
            elif not sp_template[key]:
                empty_keys.append(key)

        return self.log_on_error(sp_template, missing_keys, empty_keys, index)

    def validate_policy_template(self, policy_template, index):
        """
        Validates a given policy template.
        Args:
          policy_template: Dictionary object corresponding to a policy template.
          index: Index of the template object in the ucsm_objects list in template
              file.
        
        Returns:
          True if the template is valid and False otherwise.
        """
        keys = [
         'object_name', 'object_type', 'desc', 'lsServer_key', 'dn_prefix',
         'xml_source']
        missing_keys = []
        empty_keys = []
        for key in keys:
            if key not in policy_template.keys():
                missing_keys.append(key)
            elif not policy_template[key]:
                empty_keys.append(key)

        return self.log_on_error(policy_template, missing_keys, empty_keys, index)

    def log_on_error(self, obj_template, missing_keys, empty_keys, index):
        """
        Logs error details in case of errors.
        Args:
          obj_template: Template corresponding to a service profile or a policy.
          missing_keys: Mandatory keys which are missing in the template.
          empty_keys: Mandatory keys which are missing in the template.
          index: Index of the template object in the ucsm_objects list in template
              file.
        
        Returns:
          True if there is no error and False in case of error.
        """
        valid = True
        if missing_keys:
            valid = False
            self.logger.error('Missing keys in policy template at index %d: %s' % (
             index, missing_keys))
        if empty_keys:
            valid = False
            self.logger.error('Values missing for keys in policy template at index %d: %s' % (
             index, empty_keys))
        if obj_template.get('xml_source') == 'inline':
            if not isinstance(obj_template.get('xml'), list):
                valid = False
                self.logger.error("Value for the key 'xml' must be a list of strings")
        else:
            if obj_template.get('xml_source') == 'file':
                xml_file = obj_template.get('xml_file_path')
                xml_file = os.path.join(folder_central.get_templates_folder(), xml_file)
                if not (xml_file and os.path.exists(xml_file) and os.path.isfile(xml_file)):
                    valid = False
                    self.logger.error('Invalid xml file: %s' % xml_file)
            else:
                valid = False
                self.logger.error("Invalid value for 'xml_source': %s" % obj_template.get('xml_source'))
        return valid

    def validate_template(self, ucsm_objects):
        """
        Validates all UCSM objects in the template file.
        Args:
          ucsm_objects: List of UCSM object templates.
        
        Returns:
          None
        
        Raises:
          StandardError if template is invalid for any object.
        """
        missing_indices = []
        for index, obj in enumerate(ucsm_objects):
            if obj.get('object_type') not in ('policy', 'service_profile_template'):
                missing_indices.append(index)

        if missing_indices:
            self.logger.error("'object_type' is missing or has an invalid value in object templates at indices: %s" % missing_indices)
        valid = True
        for index, obj in enumerate(ucsm_objects):
            if obj['object_type'] == 'policy':
                valid &= self.validate_policy_template(obj, index)
            else:
                valid &= self.validate_service_profile_template(obj, index)

        if not valid:
            raise StandardError('Failed to validate ucsm template at %s. Check logs for details' % folder_central.get_ucsm_profile_template())

    def assign_attribute_values(self, key_val_map, xml):
        """
        Modifies the attribute values in a given XML string per the key-value pairs
        in key_val_map dictionary.
        Args:
          key_val_map: Dictionary object whose keys must be present in the provided
              XML string.
          xml: XML string whose attribute values need to be modified.
        
        Returns:
          Modified XML string.
        """
        root = ElementTree.fromstring(xml)
        for key, val in key_val_map.iteritems():
            if key in root.attrib.keys():
                root.attrib[key] = val

        return ElementTree.tostring(root)

    def get_xml_template(self, obj_template):
        """
        Reads the XML template for a UCSM object from the template file itself or
        a different XML file.
        Args:
          obj_template: UCSM template dictionary.
        
        Returns:
          The XML template string for the UCSM object.
        """
        if obj_template['xml_source'] == 'file':
            template_file = obj_template['xml_file_path']
            template_file = os.path.join(folder_central.get_templates_folder(), template_file)
            if template_file and os.path.isfile(template_file):
                with open(template_file) as (fd):
                    xml_template = fd.read()
            else:
                raise StandardError('Invalid template file: %s' % template_file)
        else:
            xml_template = (' ').join(obj_template['xml'])
        return xml_template

    def is_embedded_disk_available(self, serial):
        """
        Checks whether a node has an embedded disk attached. Embedded disk is a
        disk attached to the AHCI controller.
        Args:
          serial: Node serial number of the node.
        
        Returns:
          True if an embedded disk is available. False otherwise.
        """
        ucsm = self.ucsm
        server_dn = ucsm.get_dn_from_serial(serial)
        dn = '%s/board' % server_dn
        root = ucsm.get_object(dn=dn, hierarchical=True)
        for child in root.getchildren():
            if child.tag == 'storageController':
                if child.get('rn') and 'storage-PCH' in child.get('rn') or child.get('dn') and 'storage-PCH' in child.get('dn'):
                    if child.getchildren():
                        return True
                    return False

        return False

    def modify_boot_policy(self, xml):
        """
        If the server doesn't have embedded disk (AHC disk), remove embedded disk
        from boot options.
        Args:
          xml: Boot policy XML which needs to be modified.
        
        Returns:
          A new boot policy XML which doesn't contain embedded disk if the node
          doesn't have embedded disk in it.
        """
        logger = self.config.get_logger()
        serial = self.config.ucsm_node_serial
        embedded_disk_tag = 'lsbootEmbeddedLocalDiskImage'
        root = ElementTree.fromstring(xml)
        storage_element = root.find('lsbootStorage')
        local_storage_element = storage_element.find('lsbootLocalStorage')
        if local_storage_element == None:
            logger.warning('check_embedded_disk flag is provided. But, lsbootLocalStorage element is missing in boot policy xml. Skipping policy modification')
            return ElementTree.tostring(root)
        embedded_disk = local_storage_element.find(embedded_disk_tag)
        if embedded_disk != None and not self.is_embedded_disk_available(serial):
            logger.info('Node does not have an embedded disk. Removing it from boot policy')
            local_storage_element.remove(embedded_disk)
            storage_order = storage_element.get('order')
            assert storage_order != None, 'lsbootStorage should have a boot order'
            for i, e in enumerate(list(local_storage_element)):
                e.attrib['order'] = str(int(storage_order) + i)

        return ElementTree.tostring(root)

    def create_service_profile_template(self, sp_template):
        """
        Creates a service profile template based on the input template.
        Args:
          sp_template: Dictionary object corresponding to service profile template.
        
        Returns:
          Name of the service profile template in UCS manager.
        
        Raises:
          StandardError if a service profile or an updating template with the name
          mentioned in template already exists.
        """
        assert 'object_type' in sp_template.keys()
        assert sp_template['object_type'] == 'service_profile_template'
        logger = self.logger
        ucsm = self.ucsm
        xml_template = self.get_xml_template(sp_template)
        sp_template_name = sp_template['name']
        dn = 'org-root/ls-%s' % sp_template_name
        desc = sp_template['desc']
        xml = Template(xml_template).substitute(dn=dn, description=desc)
        self.validate_xml(xml, sp_template['object_name'])
        key_val_map = {'dn': dn, 
           'descr': desc}
        xml = self.assign_attribute_values(key_val_map, xml)
        profile_type = ucsm.get_profile_type(sp_template_name)
        if not profile_type:
            logger.info('Nutanix template (%s) not found in UCS manager. Foundation will create the template' % sp_template_name)
            ucsm.set_object(dn, xml)
        else:
            if profile_type == 'instance':
                logger.error("%s is supposed to be a service profile template. But it's a service profile instance. Either user should manualy delete the service profile (%s) or change the service profile template name in %s and try again" % (
                 sp_template_name, sp_template_name,
                 folder_central.get_ucsm_profile_template()))
                raise StandardError('A service profile with name %s already exists. Check logs for possible recovery steps' % sp_template_name)
            else:
                if profile_type == 'updating-template':
                    logger.error('%s present in UCS manager is an updating-template. It is expected to be an initial template and is not supposed to be modified. Either user should manually delete the service profile template or change the service profile template name in %s and try again' % (
                     folder_central.get_ucsm_profile_template(), sp_template_name))
                    raise StandardError("A service profile template with type 'updating-template' and name %s already exists. Check logs for possible steps to recover" % sp_template_name)
                else:
                    logger.info('Found Nutanix service profile template (%s). It will be modified per the new template' % sp_template_name)
                    ucsm.set_object(dn, xml)
        return sp_template_name

    def create_service_profile_from_template(self, sp_template_name):
        """
        Creates a service profile from a service profile template. Name of the
        service profile will be of the form: "<prefix><NodeSerial>" where <prefix>
        will be taken from the template and must be of length at most 4 characters.
        Args:
          sp_template_name: Name of the service profile template.
        
        Returns:
          None
        
        Raises:
          StandardError if a service profile template with the same name as the
          service profile already exists.
        """
        ucsm = self.ucsm
        logger = self.logger
        sp_name = self.object_name
        server = self.config.ucsm_node_serial
        profile_type = ucsm.get_profile_type(sp_name)
        if profile_type:
            if profile_type == 'instance':
                assoc_server_dn = ucsm.get_server_dn_associated_to_service_profile(sp_name)
                if not assoc_server_dn:
                    logger.info('Service profile (%s) already exists and is not associated. Deleting it' % sp_name)
                    ucsm.delete_profile(sp_name)
                else:
                    server_dn = ucsm.get_dn_from_serial(server)
                    if server_dn == assoc_server_dn:
                        logger.info('Service profile (%s) already exists and is associated to the same server (%s). Deleting it' % (
                         sp_name, server))
                        ucsm.delete_profile(sp_name)
                    else:
                        raise StandardError('Service profile (%s) already exists and is associated with another server with dn %s' % (
                         sp_name, assoc_server_dn))
            elif profile_type.endswith('template'):
                raise StandardError('Service profile template with same name (%s) exists' % sp_name)
        ucsm.create_service_profile_from_template(sp_name, sp_template_name)
        logger.info('Created service profile (%s) from template (%s)' % (
         sp_name, sp_template_name))

    def apply_gpu_policy_changes(self, policy_template, xml):
        """
        Modify GPU policy XML template based on the avaialable GPU on the node.
        
        Args:
          policy_template: Dictionary object corresponding to the policy.
          xml: XML string corresponding to the policy.
        
        Returns:
          Modified XML string.
        """
        ucsm = self.ucsm
        gpu_modes = policy_template.get('gpu_modes', {})
        mode = policy_template.get('default_gpu_mode', 'any-configuration')
        for gpu, gpu_mode in gpu_modes.iteritems():
            if ucsm.has_gpu_model(self.config.ucsm_node_serial, gpu):
                mode = gpu_mode
                break

        root = ElementTree.fromstring(xml)
        if 'graphicsCardMode' in root.attrib:
            root.attrib['graphicsCardMode'] = mode
        return ElementTree.tostring(root)

    def apply_policy_specific_changes(self, policy_template, xml):
        """
        Applies modifications to xml depending on the policy type.
        
        Args:
          policy_template: Dictionary object corresponding to the policy.
          xml: XML string corresponding to the policy.
        
        Returns:
          Modified XML string.
        """
        if policy_template['object_name'] == 'graphics_card_policy':
            xml = self.apply_gpu_policy_changes(policy_template, xml)
        return xml

    def delete_policy(self, tag_name, dn):
        """
        Method to delete a policy.
        Args:
          tag_name: Tag name of the policy xml object.
          dn: Distinguished name of the policy object.
        
        Returns:
          None
        """
        ucsm = self.ucsm
        xml = '<pair key="%s"><%s dn="%s" status="deleted" /></pair>' % (
         dn, tag_name, dn)
        ucsm.set_objects(xml)

    def create_policy(self, policy_template):
        """
        Creates a policy from a policy template. Name of the policy will be of the
        form: "<prefix><NodeSerial>" where <prefix> will be taken from the template
        and must be of length at most 4 characters.
        Args:
          policy_template: Dictionary object corresponding to the policy.
        
        Returns:
          True if policy is created. False if policy creation is skipped.
        """
        assert 'object_type' in policy_template.keys()
        assert policy_template['object_type'] == 'policy'
        ucsm = self.ucsm
        logger = self.logger
        server_serial = self.config.ucsm_node_serial
        xml_template = self.get_xml_template(policy_template)
        dn_prefix = policy_template['dn_prefix']
        policy_name = self.object_name
        if not policy_template.get('policy_per_node', True):
            policy_name = policy_template.get('name')
            if not policy_name:
                raise StandardError("Since object '%s' is not a per-node-policy, 'name' field is required" % policy_template['object_type'])
            if not len(policy_name) <= 16:
                raise AssertionError('Policy name must be of length at most 16')
            dn = '%s-%s' % (dn_prefix, policy_name)
            desc = policy_template['desc']
            xml = Template(xml_template).substitute(dn=dn, description=desc, policy_name=policy_name)
            self.validate_xml(xml, policy_template['object_name'])
            min_ucsm_version = policy_template.get('min_ucsm_version', None)
            if min_ucsm_version:
                cur_ucsm_version = ucsm.get_ucs_manager_version()
                if not cur_ucsm_version:
                    logger.warn("Foundation couldn't read the ucs manager version. Assuming it is higher than the required version of %s to create the policy %s" % (
                     min_ucsm_version, policy_template['object_name']))
                else:
                    if LV(cur_ucsm_version) < LV(min_ucsm_version):
                        logger.warn('Policy (%s) requires a minimum ucs manager version of %s. Current ucs manager version is %s. Skipping policy creation' % (
                         policy_template['object_name'], min_ucsm_version,
                         cur_ucsm_version))
                        return False
            key_val_map = {'dn': dn, 'descr': desc, 
               'name': policy_name}
            xml = self.assign_attribute_values(key_val_map, xml)
            xml = self.apply_policy_specific_changes(policy_template, xml)
            if policy_template.get('check_embedded_disk', False):
                if policy_template['object_name'] == 'boot_policy':
                    xml = self.modify_boot_policy(xml)
                    if ucsm.get_object(dn) != None:
                        logger.info('Deleting existing boot policy (%s)' % policy_name)
                        ucsm.delete_boot_policy(policy_name)
                elif policy_template['object_name'] == 'scrub_policy':
                    emb_disk_present = self.is_embedded_disk_available(self.config.ucsm_node_serial)
                    if emb_disk_present:
                        logger.info('Node has an embedded disk. Skipping scrub policy creation')
                        return False
            if not (policy_template['object_name'] == 'local_disk_policy' and self.ucsm.has_flexflash_drive(server_serial)):
                logger.info('Node does not have flex flash disk. Skipping local disk policy creation')
                return False
        try:
            ucsm.set_object(dn, xml)
        except StandardError as e:
            fw_policy_error_msg = 'Individual PackImage modification is not allowed for this Host Firmware Package'
            if fw_policy_error_msg.lower() in str(e).lower():
                logger.info('UCS manager does not allow to modify existing firmware policy. Deleting existing firmware policy (%s)' % policy_name)
                self.delete_policy('firmwareComputeHostPack', dn)
                ucsm.set_object(dn, xml)
            else:
                raise

        logger.info('Created %s: %s' % (
         policy_template['object_name'], policy_name))
        return True

    def set_policy_to_service_profile(self, policy_template):
        """
        Assigns a policy to a service profile.
        Args:
          policy_template: Dictionary object corresponding to the policy.
        
        Returns:
          None
        """
        assert 'object_type' in policy_template.keys()
        assert policy_template['object_type'] == 'policy'
        ucsm = self.ucsm
        logger = self.logger
        policy_name = self.object_name
        policy_type = policy_template['object_name']
        sp_name = self.object_name
        sp_attribute = policy_template['lsServer_key']
        xml = '<lsServer %s="%s" />' % (sp_attribute, policy_name)
        sp_dn = 'org-root/ls-%s' % sp_name
        ucsm.set_object(sp_dn, xml)
        logger.info('Assigned %s (%s) to service profile (%s)' % (
         policy_type, policy_name, sp_name))

    def associate_service_profile_and_wait(self):
        """
        Associates service profile to the server and waits for the association
        to complete.
        """
        logger = self.logger
        ucsm = self.ucsm
        sp_name = self.object_name
        server = self.config.ucsm_node_serial
        cur_sp_name = ucsm.get_service_profile_name(server)
        if cur_sp_name and sp_name != cur_sp_name:
            logger.info('Server is associated to service profile %s. Disassociating' % cur_sp_name)
            ucsm.disassociate_service_profile_from_server(server)
        logger.info('Associating service profile (%s) to server (%s). This may take up to 1 hour' % (
         sp_name, server))
        ucsm.associate_service_profile_to_server(sp_name, server)
        ucsm.wait_for_service_profile_association(sp_name, server, logger=logger)
        logger.info('Successfully associated service profile (%s) to server (%s)' % (
         sp_name, server))

    def is_dn_present(self, dn):
        """
        Validates whether a distinguished name is present.
        Args:
          dn: Distinguished name of an object.
        
        Returns:
          True if dn is present, False otherwise.
        """
        ucsm = self.ucsm
        root = ucsm.get_object(dn)
        if root is None:
            return False
        return True

    def get_all_vnics_in_service_profile(self, sp_name):
        """
        Fetches all vnics in a service profile.
        Args:
          sp_name: Service profile name.
        
        Returns:
          List of vnics in a service profile.
        """
        ucsm = self.ucsm
        sp_dn = 'org-root/ls-%s' % sp_name
        root = ucsm.get_object(dn=sp_dn, hierarchical=True)
        vnics = []
        for child in list(root):
            if child.tag == 'vnicEther' and (child.get('rn') and child.get('rn').startswith('ether') or child.get('dn') and child.get('dn').startswith('%s/ether' % sp_dn)):
                vnics.append(child)

        return vnics

    def assign_mac_pool_to_all_vnics(self, sp_name, mac_pool):
        """
        Assigns a given mac pool to all vnics in a service profile.
        Args:
          sp_name: Name of the service profile.
          mac_pool: Name of the mac pool to be assigned,
        
        Returns:
          None
        
        Raises:
          StandardError if the given mac pool does not exist or if it does not have
          enough free addresses.
        """
        ucsm = self.ucsm
        sp_dn = 'org-root/ls-%s' % sp_name
        mac_pool_dn = 'org-root/mac-pool-%s' % mac_pool
        if not self.is_dn_present(mac_pool_dn):
            raise StandardError('Mac pool (%s) is not present' % mac_pool)
        free_mac_count = ucsm.get_mac_availability_in_pool(pool=mac_pool, raise_on_error=False)
        vnics = self.get_all_vnics_in_service_profile(sp_name)
        if free_mac_count < len(vnics):
            raise StandardError('Provided mac pool (%s) does not have enough mac addresses. Please add more addresses to the mac pool and try again' % mac_pool)
        for nic in vnics:
            nic_dn = nic.get('dn')
            if nic.get('rn'):
                nic_dn = '%s/%s' % (sp_dn, nic.get('rn'))
            xml = '<%s addr="derived" dn="%s" identPoolName="%s" status="created,modified" />' % (
             nic.tag, nic_dn, mac_pool)
            config = '<pair key="%s">%s</pair>' % (nic_dn, xml)
            ucsm.set_objects(config)

    def modify_vlan_on_all_nics(self, sp_name, vlan_name, action='add', native_vlan=True):
        """
        Modifies the vlan associated on all vnics in a service profile.
        Args:
          sp_name: Name of the service profile.
          vlan_name: Name of the vlan object to be assigned.
          action: Supported values are ["add", "del"]. If action is "add", the
              provided vlan is added to all nics. If action is "del", the provided
              vlan is removed from all nics.
          native_vlan: If True, vlan will be marked as native on the vnic.
        
        Returns:
          None
        
        Raises:
          StandardError if given vlan object does not exist or if an unsupported
          value is provided for argument 'action'.
        """
        valid_actions = [
         'add', 'del']
        if action not in valid_actions:
            raise StandardError("'%s' is not a supported action. Supported actions are %s" % (
             action, valid_actions))
        ucsm = self.ucsm
        sp_dn = 'org-root/ls-%s' % sp_name
        vlan_dn = 'fabric/lan/net-%s' % vlan_name
        if not self.is_dn_present(vlan_dn):
            raise StandardError('Vlan (%s) is not present' % vlan_name)
        vnics = self.get_all_vnics_in_service_profile(sp_name)
        native = 'yes'
        if not native_vlan:
            native = 'no'
        for nic in vnics:
            nic_dn = nic.get('dn')
            if nic.get('rn'):
                nic_dn = '%s/%s' % (sp_dn, nic.get('rn'))
            add_vlan_xml = '<vnicEtherIf defaultNet="%s" name="%s" rn="if-%s"></vnicEtherIf>' % (
             native, vlan_name, vlan_name)
            del_vlan_xml = '<vnicEtherIf rn="if-%s" status="deleted" ></vnicEtherIf>' % vlan_name
            if action == 'add':
                vlan_xml = add_vlan_xml if 1 else del_vlan_xml
                xml = '<vnicEther dn="%s" status="created,modified">%s</vnicEther>' % (
                 nic_dn, vlan_xml)
                config = '<pair key="%s">%s</pair>' % (nic_dn, xml)
                ucsm.set_objects(config)

    def get_cisco_vic_count(self, server_serial):
        """
        Finds the number of Cisco VIC adaptors present in the server.
        Args:
          server_serial: Serial number of the server.
        
        Returns:
          Number of Cisco VIC adaptors present in the server.
        """
        ucsm = self.ucsm
        server_dn = ucsm.get_dn_from_serial(server_serial)
        root = ucsm.get_object(server_dn, hierarchical=True)
        vic_count = 0
        for child in list(root):
            if child.tag == 'adaptorUnit' and child.get('vendor', '').lower().startswith('cisco'):
                vic_count += 1

        return vic_count

    def assign_network_settings(self, network_settings):
        """
        Assigns network settings mentioned in the template file.
        Currently this method handles only vlan and mac pool.
        Args:
          network_settings: Dictionary containing network parameters.
              Following parameters are currently supported:
              {
                 "mac_pool": "string, name of mac pool",
                 "vlan_name": "string, name of vlan object",
                 "native_vlan": "boolean, whether vlan should be native or not",
                 "policies": [<list of policies required for network>],
                 "<any extra configuration required to use these policies>"
              }
        
        Raises:
          StandardError if the vnic placement config is missing in template.
        
        Returns:
          None
        """
        if not network_settings:
            return
        logger = self.logger
        sp_name = self.object_name
        ucsm = self.ucsm
        server = self.config.ucsm_node_serial
        ucsm_params = getattr(self.config, 'ucsm_params', {})
        policies = network_settings.get('policies', [])
        for policy in policies:
            if policy.get('object_name') == 'vnic_vhba_placement_policy':
                vic_count = self.get_cisco_vic_count(server)
                vnic_placement_conf = network_settings.get('vnic_placement_configuration', {})
                if not vnic_placement_conf:
                    raise StandardError('Missing vnic placement configuration element (vnic_placement_configuration) in ucsm_network_settings')
                vic_count_applicable = vnic_placement_conf.get('vic_count_applicable', 0)
                if vic_count == vic_count_applicable:
                    logger.info('Detected %d vics. Creating placement policies and vnic mappings' % vic_count)
                    self.create_policy(policy)
                    xml_template = self.get_xml_template(vnic_placement_conf)
                    sp_dn = 'org-root/ls-%s' % sp_name
                    xml = Template(xml_template).substitute(sp_name=sp_name, dn=sp_dn)
                    self.validate_xml(xml, policy['object_name'])
                    key_val_map = {'name': sp_name, 
                       'dn': sp_dn}
                    xml = self.assign_attribute_values(key_val_map, xml)
                    config = '<pair key="%s">%s</pair>' % (sp_dn, xml)
                    ucsm.set_objects(config)
                    logger.info('Created vnic mappings')
                    ucsm.wait_for_service_profile_association(sp_name, server, logger=logger)

        mac_pool = network_settings.get('mac_pool')
        if ucsm_params.get('mac_pool', None):
            mac_pool = ucsm_params['mac_pool']
        vlan = network_settings.get('vlan_name')
        if ucsm_params.get('vlan_name', None):
            vlan = ucsm_params['vlan_name']
        native_vlan = network_settings.get('native_vlan', True)
        if ucsm_params.get('native_vlan', None) is not None:
            native_vlan = ucsm_params['native_vlan']
        if mac_pool:
            self.assign_mac_pool_to_all_vnics(sp_name, mac_pool)
            logger.info('Assigned mac pool (%s) to all vnics' % mac_pool)
            ucsm.wait_for_service_profile_association(sp_name, server, logger=logger)
        if vlan:
            self.modify_vlan_on_all_nics(sp_name, vlan, native_vlan=native_vlan)
            if vlan != 'default':
                self.modify_vlan_on_all_nics(sp_name, 'default', action='del')
            logger.info('Assigned vlan (%s) to all vnics' % vlan)
            ucsm.wait_for_service_profile_association(sp_name, server, logger=logger)
        logger.info('Applied all network settings')
        return

    def post_association_steps(self, ucsm_objects):
        logger = self.logger
        for obj in ucsm_objects:
            if obj['object_type'] == 'policy':
                if obj.get('post_association', False) and self.create_policy(obj):
                    self.set_policy_to_service_profile(obj)

        for policy in self.config.ucsm_policies_to_delete:
            policy_type, name, tag, dn = policy
            logger.info('Deleting %s policy (%s) after service profile association' % (
             policy_type, name))
            self.delete_policy(tag, dn)

        self.associate_service_profile_and_wait()

    def will_run(self):
        """
        This method returning a bool indicating whether the business logic
        will be executed or not in run().
        """
        return all([
         self.config.ucsm_managed_mode,
         self.config.image_now,
         getattr(self.config, 'type', None) == CLASS_UCSM])

    def run(self):
        logger = self.logger
        if not self.will_run():
            logger.info('PrepareVendorUCSM skipped')
            return
        self.set_status(CREATE_UCSM_OBJECTS)
        node_config = self.config
        ucsm_params = getattr(node_config, 'ucsm_params', {})
        req_keys = ['ucsm_node_serial', 'ucsm_ip', 'ucsm_user', 'ucsm_password']
        if not all(map(lambda x: hasattr(node_config, x), req_keys)):
            raise StandardError('NodeConfig object must have the attributes: %s' % req_keys)
        self.ucsm = CiscoUCSM(node_config.ucsm_ip, node_config.ucsm_user, node_config.ucsm_password)
        ucsm = self.ucsm
        ucsm.login()
        ucsm_template_file = folder_central.get_ucsm_profile_template()
        template = json.load(open(ucsm_template_file))
        if 'last_updated' not in template.keys() or 'ucsm_objects' not in template.keys() or not isinstance(template['ucsm_objects'], list):
            raise StandardError('Invalid template file: %s' % ucsm_template_file)
        ucsm_objects = template['ucsm_objects']
        self.validate_template(ucsm_objects)
        if ucsm.current_max_sessions() != str(template.get('max_sessions', 256)):
            ucsm.set_maximum_sessions_limit(template.get('max_sessions', 256))
        ucsm_version = ucsm.get_ucs_manager_version()
        logger.info('UCS manager version: %s' % ucsm_version)
        ucsm.validate_node_serial(node_config.ucsm_node_serial)
        prefix = template['ucsm_object_prefix']
        if not prefix:
            prefix = 'fdtn'
        prefix_length = UCSM_OBJECT_NAME_LEN - len(node_config.ucsm_node_serial)
        prefix = prefix[0:prefix_length]
        node_config.ucsm_object_prefix = prefix
        self.object_name = ('%s%s' % (prefix, node_config.ucsm_node_serial))[0:UCSM_OBJECT_NAME_LEN]
        sp_template = filter(lambda x: x['object_type'] == 'service_profile_template', ucsm_objects)
        if len(sp_template) > 1:
            raise StandardError('There should be only one Nutanix service profile template. But, there are %d such templates provided' % len(sp_template))
        keep_settings = template.get('keep_ucsm_settings', False)
        if ucsm_params.get('keep_ucsm_settings', None) is not None:
            keep_settings = ucsm_params['keep_ucsm_settings']
        node_config.sp_name = None
        if keep_settings:
            node_config.sp_name = ucsm.get_service_profile_name(node_config.ucsm_node_serial)
            if not node_config.sp_name:
                raise StandardError('Foundation has been asked to use existing UCSM configuration. But server (%s) does not have a service profile associated with it. Either change the setting in ucsm_template.json or ensure that the server has an associated service profile' % node_config.ucsm_node_serial)
            logger.info('Skipping UCS manager configuration. Existing service profile (%s) will be used by Foundation' % node_config.sp_name)
            return
        self.config.ucsm_policies_to_delete = []
        sp_template_name = self.create_service_profile_template(sp_template[0])
        self.create_service_profile_from_template(sp_template_name)
        for obj in ucsm_objects:
            if obj['object_type'] == 'policy':
                if not obj.get('post_association', False) and self.create_policy(obj):
                    self.set_policy_to_service_profile(obj)

        self.set_status(ASSOCIATE_SERVICE_PROFILE)
        self.associate_service_profile_and_wait()
        network_settings = template.get('ucsm_network_settings')
        self.assign_network_settings(network_settings)
        if self.ucsm.has_flexflash_drive(node_config.ucsm_node_serial):
            logger.info('Detected flex flash drive on the node. Formatting it')
            self.ucsm.format_sd_card(node_config.ucsm_node_serial)
            logger.info('Formatted flex flash drive on the node')
        self.post_association_steps(ucsm_objects)
        return


class ImagingStepPrepareVendor(ImagingStepNodeTask):

    def run(self):
        pass


class ImagingStepPrepareVendorFactory(ImagingStepNodeTask):
    """
    Vendor factory to choose the actual class object for a node.
    """

    def __new__(cls, *args, **kargs):
        config = args[0]
        if config.ucsm_managed_mode:
            cls = ImagingStepPrepareUCSM
            return cls(*args, **kargs)
        return ImagingStepPrepareVendor(*args, **kargs)