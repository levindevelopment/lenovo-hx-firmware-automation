# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/remote_boot_cimc.py
# Compiled at: 2019-02-15 12:42:10
import logging, os, requests, time, warnings, traceback, xml.etree.ElementTree as ElementTree, foundation_tools, folder_central, remote_boot
from requests.exceptions import Timeout
TICK = 10
BMC_RESET_TIMEOUT_S = TICK * 60
POWER_CHECK_CYCLES = 200
POWER_CHECK_INTERVAL_S = 3

class CiscoCIMC(object):

    def __init__(self, ip, user, password):
        self.cookie = None
        self.ip = ip
        self.user = user
        self.password = password
        return

    def __del__(self):
        self.logout()

    def __request(self, xml):
        """
        Posts XML request to the remote CIMC server. This function raises
        following warnings - InsecureRequestWarning and InsecurePlatformWarning.
        In order to suppress it, the code is executed under a warning context
        manager which ignores all warnings.
        Args:
          xml: XML string to be submitted to CIMC.
        
        Returns:
          Response from CIMC API in the form of ElementTree object.
        
        Raises:
          StandardError if cookie is invalid or BMC response throws error.
          Timeout exception if request takes more than 60 seconds.
        """
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore')
            r = requests.post('https://%s:443/nuova' % self.ip, data=xml, verify=False, timeout=60, headers={'Content-Type': 'application/xml'})
            root = ElementTree.fromstring(r.text)
            if root.attrib['response'] != 'yes':
                raise StandardError('Failed to authenticate with BMC')
            if 'errorCode' in root.attrib:
                raise StandardError('BMC request failed, error %s (%s)' % (
                 root.attrib['errorCode'], root.attrib['errorDescr']))
            r.stream = False
            return root

    def login(self):
        """
        Logs in to remote CIMC server and starts a new session.
        """
        xml = '<aaaLogin inName="%s" inPassword="%s" />' % (
         self.user, self.password)
        root = self.__request(xml)
        self.cookie = root.attrib['outCookie']

    def logout(self):
        """
        Logs out from the remote CIMC server and destroys the session.
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
        """
        hierarchical_flag = 'false'
        if hierarchical:
            hierarchical_flag = 'true'
        xml = '<configResolveDn dn="%s" cookie="%s" inHierarchical="%s" />' % (
         dn, self.cookie, hierarchical_flag)
        root = self.__request(xml)
        config = root.find('outConfig')
        if config == None:
            raise StandardError('BMC response missing outConfig element')
        children = list(config)
        if not len(children):
            return
        if len(children) != 1:
            raise StandardError('BMC response contains more than one object')
        return children[0]

    def set_object(self, dn, config, hierarchical=False):
        hierarchical_flag = 'false'
        if hierarchical:
            hierarchical_flag = 'true'
        xml = '<configConfMo cookie="%s" inHierarchical="%s" dn="%s" >\n               <inConfig> %s </inConfig>\n             </configConfMo>' % (self.cookie, hierarchical_flag, dn, config)
        self.__request(xml)

    def delete_object(self, dn):
        """
        Deletes a configuration object.
        """
        xml = '<configConfMo cookie="%s" inHierarchical="false" dn="%s" >\n               <inConfig>  </inConfig>\n             </configConfMo>' % (self.cookie, dn)
        self.__delete(xml)

    def set_vmedia_nfs(self, ip, folder, file):
        """
        Mounts the virtual media from the NFS file share.
        
        Args:
          ip: IPMI ip of the target node.
          folder: NFS share location.
          file: Name of the file in NFS share which has to be mounted.
        
        Raises:
          StandardError if mount fails.
        """
        xml = '<commVMediaMap map="nfs" volumeName="nutanix"\n               remoteShare="%s" remoteFile="%s" />' % (
         '%s:%s' % (ip, folder), file)
        self.set_object('sys/svc-ext/vmedia-svc/vmmap-nutanix', xml)
        while True:
            status = self.nutanix_vmap_status()
            if status == 'In Progress':
                continue
            if status == 'OK':
                break
            raise StandardError('Mount failed: %s' % status)

    def has_nutanix_vmap(self):
        """
        Verifies whether a virtual media is mounted or not. Returns True
        if virtual media is mounted and False otherwise.
        """
        vmap = self.get_object('sys/svc-ext/vmedia-svc/vmmap-nutanix')
        return vmap != None

    def nutanix_vmap_status(self):
        """
        Returns vritual media  mapping status.
        """
        vmap = self.get_object('sys/svc-ext/vmedia-svc/vmmap-nutanix')
        return vmap.attrib['mappingStatus']

    def del_vmedia_nfs(self):
        """
        Delete virtual media mount.
        """
        xml = '<commVMediaMap status="removed" volumeName="nutanix" />'
        self.set_object('sys/svc-ext/vmedia-svc/vmmap-nutanix', xml)

    def clear_vmedia_boot(self):
        """
        Clears any other first boot preference and sets storage
        media as the first boot device.
        """
        xml = '<lsbootDef rebootOnUpdate="no">\n               <lsbootStorage access="read-write" order="1"\n                 type="storage" rn="storage-read-write" />\n             </lsbootDef> '
        self.set_object('sys/rack-unit-1/boot-policy', xml, hierarchical=True)

    def set_vmedia_boot(self):
        """
        Set virtual media as the first boot device.
        """
        xml = '<lsbootDevPrecision dn="sys/rack-unit-1/boot-precision"\n             rebootOnUpdate="no" reapply="no">\n               <lsbootVMedia name="nutanix" type="VMEDIA"\n                 subtype="cimc-mapped-dvd" access="read-only-remote"\n                 order="1" state="Enabled" rn="vm-nutanix">\n               </lsbootVMedia>\n               <lsbootPchStorage name="bootdrive" type="PCHSTORAGE" order="2"\n                 state="Enabled" rn="pchstorage-bootdrive" >\n               </lsbootPchStorage>\n               <lsbootSd name="CiscoVDHypervisor" type="SDCARD" order="3"\n                 state="Enabled" rn="sd-CiscoVDHypervisor" >\n               </lsbootSd>\n             </lsbootDevPrecision>'
        self.set_object('sys/rack-unit-1/boot-precision', xml, hierarchical=True)

    def power_control(self, option):
        """
          Options are:
                             <xs:enumeration value="up"/>
                             <xs:enumeration value="down"/>
                             <xs:enumeration value="soft-shut-down"/>
                             <xs:enumeration value="cycle-immediate"/>
                             <xs:enumeration value="hard-reset-immediate"/>
                             <xs:enumeration value="bmc-reset-immediate"/>
                             <xs:enumeration value="bmc-reset-default"/>
                             <xs:enumeration value="cmos-reset-immediate"/>
                             <xs:enumeration value="diagnostic-interrupt"/>
        """
        xml = '<computeRackUnit adminPower="%s" />' % option
        self.set_object('sys/rack-unit-1', xml)

    def get_power_status(self):
        """
         Possible results:
                             <xs:enumeration value="unknown"/>
                             <xs:enumeration value="on"/>
                             <xs:enumeration value="test"/>
                             <xs:enumeration value="off"/>
                             <xs:enumeration value="online"/>
                             <xs:enumeration value="offline"/>
                             <xs:enumeration value="offduty"/>
                             <xs:enumeration value="degraded"/>
                             <xs:enumeration value="power-save"/>
                             <xs:enumeration value="error"/>
                             <xs:enumeration value="not-supported"/>
        """
        vmap = self.get_object('sys/rack-unit-1')
        return vmap.attrib['operPower']

    def get_cimc_version(self):
        """
        Returns the CIMC version of the node.
        """
        firmware = self.get_object('sys/rack-unit-1/mgmt/fw-system', True)
        return firmware.attrib.get('version') or None

    def get_flexflash_firmware(self):
        """
        Return the flexflash firmware version on the node.
        """
        flexflash = self.get_object('sys/rack-unit-1/board/storage-flexflash-FlexFlash-0', True)
        if flexflash is None:
            return
        for element in flexflash.getchildren():
            if 'controllerName' in element.attrib and element.get('fwVersion'):
                return element.get('fwVersion')

        return

    def set_boot_mode(self, mode='Legacy', ignore_error=False):
        """
        Sets boot mode to legacy or uefi. This method doesn't reboot the server.
        The mode will be set after the node is power cycled.
        
        Args:
          mode: Boot mode. Default is "Legacy. For uefi, value should be "Uefi".
          ignore_error: If True, any error will be ignored. If False, error will
            be raised to the caller.
        """
        dn = 'sys/rack-unit-1/boot-precision'
        xml = '<lsbootDevPrecision configuredBootMode="%s" />' % mode
        try:
            self.set_object(dn, xml)
        except StandardError:
            if ignore_error:
                logging.exception('Failed to set boot mode to %s. Ignoring error' % mode)
            else:
                raise


class RemoteBootCIMC(remote_boot.RemoteBoot):

    def __init__(self, node_config):
        remote_boot.RemoteBoot.__init__(self, node_config)
        self.cimc = None
        return

    def get_cimc(self):
        """
        Returns a CIMC object.
        """
        if self.cimc and self.cimc.cookie:
            return self.cimc
        cimc = CiscoCIMC(self.node_config.ipmi_ip, self.node_config.ipmi_user, self.node_config.ipmi_password)
        cimc.login()
        self.cimc = cimc
        return cimc

    def reset_bmc(self):
        cimc = self.get_cimc()
        try:
            cimc.power_control('bmc-reset-immediate')
        except Timeout as e:
            pass
        else:
            cimc.cookie = None
            logger = self.node_config.get_logger()
            time.sleep(TICK * 3)
            st = time.time()
            while time.time() - st < BMC_RESET_TIMEOUT_S:
                logger.debug('[%d/%d s] Waiting for CIMC', time.time() - st, BMC_RESET_TIMEOUT_S)
                time.sleep(TICK)
                _, _, ret = foundation_tools.system(self.node_config, [
                 'ping', '-c3', '-W3', self.node_config.ipmi_ip], log_on_error=False, throw_on_error=False)
                if ret != 0:
                    continue
                time.sleep(TICK)
                logger.debug('Logging in to CIMC')
                cimc = self.get_cimc()
                logger.info('Reset CIMC completed')
                break

            raise StandardError('Cannot reach CIMC after reset')

        return

    def boot(self, iso, do_reset=True):
        """
        Method for booting node specific iso.
        """
        cimc = self.get_cimc()
        cimc.power_control('up')
        self.wait_for_poweron()
        nfs_path = folder_central.get_nfs_path_from_tmp_path(iso)
        nfs_folder, nfs_file = os.path.split(nfs_path)
        foundation_ip = foundation_tools.get_my_ip(self.node_config.ipmi_ip)
        cimc.set_boot_mode(ignore_error=True)
        if cimc.has_nutanix_vmap():
            cimc.del_vmedia_nfs()
        cimc.set_vmedia_nfs(foundation_ip, nfs_folder, nfs_file)
        cimc.set_vmedia_boot()
        if do_reset:
            cimc.power_control('up')
            self.wait_for_poweron()
            cimc.power_control('hard-reset-immediate')

    def retry_boot_from_iso(self, iso):
        logger = self.node_config.get_logger()
        logger.info('Retrying to boot from iso')
        self.reset_bmc()
        self.boot(iso)

    def stop(self):
        """
        Method for stopping virtual media process (if any).
        """
        cimc = self.get_cimc()
        if cimc.has_nutanix_vmap():
            cimc.del_vmedia_nfs()

    def poweroff(self):
        """
        Method for powering off node.
        """
        cimc = self.get_cimc()
        cimc.power_control('down')

    def wait_for_poweroff(self):
        """
        Method for waiting for node to power down.
        """
        cimc = self.get_cimc()
        for _ in range(POWER_CHECK_CYCLES):
            status = cimc.get_power_status()
            if status == 'off':
                break
            time.sleep(POWER_CHECK_INTERVAL_S)
        else:
            raise StandardError("Node did not shut down in a timely manner. Power status of node is '%s'" % status)

    def wait_for_poweron(self):
        """
        Method for waiting for node to power on.
        """
        cimc = self.get_cimc()
        for _ in range(POWER_CHECK_CYCLES):
            status = cimc.get_power_status()
            if status == 'on':
                break
            time.sleep(POWER_CHECK_INTERVAL_S)
        else:
            raise StandardError("Node did not turn on in a timely manner. Power status of node is '%s'" % status)

    def set_first_boot_device(self):
        """
        Virtual method for setting satadom / raid as first boot device
        """
        pass

    def set_bios_config(self, bios_config=None):
        """
        This method is used to configure BIOS settings.
        """
        if not bios_config:
            return
        config_change = False
        try:
            cimc = self.get_cimc()
            config = cimc.get_object('sys/rack-unit-1/bios/bios-settings', True)
            for element in config.getchildren():
                for param in element.keys():
                    if param in bios_config:
                        element.set(param, bios_config[param])
                        config_change = True

            if config_change:
                cimc.set_object('sys/rack-unit-1/bios/bios-settings', ElementTree.tostring(config), True)
        except Exception:
            raise StandardError('Unable to configure BIOS :\n%s' % traceback.format_exc())

    def _flexflash_info(self, category):
        """
        This method is used to get flexflash information for the given category
        """
        try:
            info = {}
            cimc = self.get_cimc()
            flexflash = cimc.get_object('sys/rack-unit-1/board/storage-flexflash-FlexFlash-0', True)
            for element in flexflash.getchildren():
                if category in element.keys():
                    name = element.get(category)
                    info[name] = {}
                    for key in element.keys():
                        info[name][key] = element.get(key)

            return info
        except Exception:
            raise StandardError('Unable to get flexflash info :\n%s' % traceback.format_exc())

    def get_flexflash_virtualdrive_info(self):
        """
        This method is used to get flexflash virtual drive info
        """
        return self._flexflash_info('virtualDrive')

    def get_flexflash_physicaldrive_info(self):
        """
        This method is used to get the flexflash physical drive info
        """
        return self._flexflash_info('physicalDrive')

    def get_flexflash_controller_info(self):
        """
        This method is used to get the flexflash controller info
        """
        return self._flexflash_info('controllerName')

    def enable_flexflash_virtualdrive(self):
        """
        This method is used to enable flexflash virtual drive
        """
        try:
            cimc = self.get_cimc()
            enable_vd = '<storageFlexFlashVirtualDrive adminAction="enable-vd" dn="sys/rack-unit-1/board/storage-flexflash-FlexFlash-0/vd-1"/>'
            cimc.set_object('sys/rack-unit-1/board/storage-flexflash-FlexFlash-0/vd-1', enable_vd, True)
        except Exception:
            raise StandardError('Unable to enable Virtual drive:\n%s' % traceback.format_exc())

    def sync_flexflash_virtualdrive(self):
        """
        This method is used to sync flexflash virtual drive
        """
        try:
            virtualdrive_info = self.get_flexflash_virtualdrive_info()
            if virtualdrive_info['Hypervisor']['driveStatus'] == 'Degraded' and virtualdrive_info['Hypervisor']['operationInProgress'] == 'NA':
                cimc = self.get_cimc()
                sync_vd = '<storageFlexFlashVirtualDrive adminAction="sync-vd" dn="sys/rack-unit-1/board/storage-flexflash-FlexFlash-0/vd-1"/>'
                cimc.set_object('sys/rack-unit-1/board/storage-flexflash-FlexFlash-0/vd-1', sync_vd, True)
        except Exception as e:
            raise StandardError('Unable to sync Virtual drive:\n%s' % traceback.format_exc())