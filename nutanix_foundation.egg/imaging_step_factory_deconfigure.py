# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_factory_deconfigure.py
# Compiled at: 2019-02-15 12:42:10
import shlex, time, foundation_settings, foundation_tools
from imaging_step import ImagingStepNodeTask
import set_smc_ipmi_ip
STATE_DECONFIGURING = 'Setting IPs to DHCP and powering down'
STATE_DECONFIGURING_DONE = 'IP deconfiguration and power down done'
HYPERV_IF_NAME = 'vEthernet (ExternalSwitch)'
DECONF_RETRY_LIMIT = 3
SSH_RETRY_DELAY = 3

class DeconfigureBase(ImagingStepNodeTask):

    def get_progress_timing(self):
        return [
         (
          STATE_DECONFIGURING, 3)]

    def get_finished_message(self):
        return STATE_DECONFIGURING_DONE

    def _cvm_ssh(self, command, throw_on_error=True, escape_cmd=False):
        node_config = self.config
        return foundation_tools.ssh(node_config, node_config.cvm_ip, command, throw_on_error=throw_on_error, user='nutanix', password='nutanix/4u', escape_cmd=escape_cmd)

    def _centos_dhcp_sed(self, iface, with_root=True, persistent_dhclient=False):
        iface_path = '/etc/sysconfig/network-scripts/ifcfg-%s' % iface
        sudo = 'sudo' if with_root else ''
        cmd = ('"{sudo} sed -i \'/IPADDR/d\' {path};{sudo} sed -i \'/NETMASK/d\' {path};{sudo} sed -i \'/GATEWAY/d\' {path};{sudo} sed -i \'s/BOOTPROTO=.*/BOOTPROTO=dhcp/g\' {path}').format(path=iface_path, sudo=sudo)
        if persistent_dhclient:
            cmd += ';%s echo PERSISTENT_DHCLIENT=1 >> %s"' % (sudo, iface_path)
        else:
            cmd += '"'
        return shlex.split(cmd)

    def _get_ifcfg(self, iface):
        return [
         'cat', '/etc/sysconfig/network-scripts/ifcfg-%s' % iface]

    def _deconfigure_cvm(self):
        logger = self.logger
        for retry in range(DECONF_RETRY_LIMIT):
            logger.info('[%s/%s] Setting CVM to DHCP', retry + 1, DECONF_RETRY_LIMIT)
            out, err, ret = self._cvm_ssh(self._centos_dhcp_sed('eth0'), throw_on_error=False)
            if ret:
                logger.warn('Setting CVM to DHCP failed. Stdout:\n%s\nStderr:\n%s\nRetrying...' % (
                 out, err))
                time.sleep(SSH_RETRY_DELAY)
                continue
            out, err, ret = self._cvm_ssh(self._get_ifcfg('eth0'), throw_on_error=False)
            if ret:
                logger.warn('Failed to ssh to CVM, this might be a network issue, Retrying...')
                time.sleep(SSH_RETRY_DELAY)
            elif 'dhcp' not in out:
                logger.warn('Didn\'t find "dhcp" in CVM network script:\n%s\nRetrying...' % out)
                time.sleep(SSH_RETRY_DELAY)
            else:
                logger.debug('ifcfg for %s is \n%s', 'eth0', out)
                break
        else:
            raise StandardError('Setting CVM to DHCP failed.')

        logger.info('Syncing CVM')
        for retry in range(DECONF_RETRY_LIMIT):
            out, err, ret = self._cvm_ssh(['sync; sync; sync'], throw_on_error=False)
            if ret:
                logger.warn('Failed to ssh to CVM, this might be a network issue, Retrying...')
                time.sleep(SSH_RETRY_DELAY)
            else:
                logger.debug('Syncing CVM completed')
                break
        else:
            raise StandardError('Failed to Sync CVM')

        logger.info('CVM is deconfigured')

    def _deconfigure_ipmi(self):
        logger = self.logger
        node = self.config
        logger.info('Setting IPMI interface to DHCP')
        ipv6_iface = foundation_settings.get_settings()['ipv6_interface']
        set_smc_ipmi_ip.set_ipmi_ip(node.ipmi_mac, ipv6_iface, node.ipmi_user, node.ipmi_password, '0.0.0.0', '255.255.0.0', '0.0.0.0', dhcp=True)

    def _wait_for_host_poweroff(self):
        logger = self.logger
        node = self.config
        for retry in range(120):
            out, err, ret = foundation_tools.ipmitool(node, ['power', 'status'], throw_on_error=False)
            if ret == 0 and 'off' in out.lower():
                logger.info('Successfully powered down via the OS.')
                break
            else:
                time.sleep(1)
        else:
            logger.warn('Failed to power down via the OS after two minutes; forcing power off via IPMI.')
            foundation_tools.ipmitool(node, ['power', 'down'])
            for retry in range(60):
                out, err, ret = foundation_tools.ipmitool(node, ['power', 'status'], throw_on_error=False)
                if ret == 0 and 'off' in out.lower():
                    logger.info('Successfully powered down via IPMI.')
                    break
                else:
                    time.sleep(1)
            else:
                raise StandardError('Failed to power down via OS and IPMI.')

    def _poweroff_host(self):
        raise NotImplementedError()

    def _deconfigure_host(self):
        raise NotImplementedError()

    def run(self):
        logger = self.logger
        logger.info('Deconfiguring node')
        self.set_status(STATE_DECONFIGURING)
        erased = getattr(self.config, 'erase_disks', None)
        try:
            if not erased:
                self._deconfigure_host()
                self._deconfigure_cvm()
                self._poweroff_host()
            else:
                logger.info('This node has been erased, will deconf IPMI only')
            self._wait_for_host_poweroff()
            self._deconfigure_ipmi()
        except Exception:
            logger.exception('Unexpected exception in deconfiguring node')
            raise
        finally:
            cmd = [
             'sudo', 'ip', 'neigh', 'flush', 'all']
            foundation_tools.system(None, cmd, throw_on_error=False, log_on_error=False)

        return


class ImagingStepFactoryDeconfigureKVM(DeconfigureBase):

    def _host_ssh(self, command, throw_on_error=True):
        node_config = self.config
        return foundation_tools.ssh(node_config, node_config.hypervisor_ip, command, throw_on_error=throw_on_error, user='root', password='nutanix/4u')

    def _deconfigure_host(self):
        logger = self.logger
        for retry in range(DECONF_RETRY_LIMIT):
            logger.info('[%s/%s] Setting host to DHCP', retry + 1, DECONF_RETRY_LIMIT)
            out, err, ret = self._host_ssh(self._centos_dhcp_sed('br0', with_root=False, persistent_dhclient=True), throw_on_error=False)
            if ret:
                logger.warn('Setting host to DHCP failed. Stdout:\n%s\nStderr:\n%s\nRetrying...' % (
                 out, err))
                time.sleep(SSH_RETRY_DELAY)
                continue
            out, err, ret = self._host_ssh(self._get_ifcfg('br0'), throw_on_error=False)
            if ret:
                logger.warn('Failed to ssh to host, this might be a network issue, Retrying...')
                time.sleep(SSH_RETRY_DELAY)
            elif 'dhcp' not in out:
                logger.warn('Didn\'t find "dhcp" in host network script:\n%s\nRetrying...' % out)
                time.sleep(SSH_RETRY_DELAY)
            else:
                logger.debug('ifcfg for %s is \n%s', 'br0', out)
                break
        else:
            raise StandardError('Setting host to DHCP failed.')

        logger.info('Syncing host')
        for retry in range(DECONF_RETRY_LIMIT):
            _, _, ret = self._host_ssh(['sync; sync; sync'], throw_on_error=False)
            if ret:
                logger.warn('Failed to ssh to host, this might be a network issue, Retrying...')
                time.sleep(SSH_RETRY_DELAY)
            else:
                logger.debug('Syncing host completed')
                break
        else:
            raise StandardError('Failed to Sync host')

        logger.info('host is deconfigured')

    def _poweroff_host(self):
        logger = self.logger
        logger.info('Shutting down host')
        self._host_ssh(['poweroff'], throw_on_error=False)


class ImagingStepFactoryDeconfigureHYPERV(DeconfigureBase):

    def _winsh(self, command, throw_on_error=True):
        command = ['/usr/local/nutanix/bin/winsh'] + command
        return self._cvm_ssh(command, throw_on_error=throw_on_error, escape_cmd=True)

    def _poweroff_host(self):
        self._winsh(['shutdown /s /t 5'])

    def _deconfigure_host(self):
        winsh_cmd = '"Get-DnsClient | Set-DnsClientServerAddress -ResetServerAddresses"'
        self._winsh([winsh_cmd])
        winsh_cmd = 'Set-NetIPInterface -InterfaceAlias "\'%s\'" -AddressFamily "IPv4" -Dhcp Enabled' % HYPERV_IF_NAME
        self._winsh([winsh_cmd])
        self._winsh(['sync'])


class ImagingStepFactoryDeconfigureFactory(ImagingStepNodeTask):
    """
    Factory class to spawn different class to deconfigure a node.
    Deconfigure = Set DHCP and Power off.
    """
    class_mapping = dict(kvm=ImagingStepFactoryDeconfigureKVM, hyperv=ImagingStepFactoryDeconfigureHYPERV)

    def __new__(cls, *args, **kargs):
        config = args[0]
        mapping = ImagingStepFactoryDeconfigureFactory.class_mapping
        assert hasattr(config, 'hypervisor') and config.hypervisor in mapping, 'Unknown hypervisor %s' % config.hypervisor
        cls = ImagingStepFactoryDeconfigureFactory.class_mapping[config.hypervisor]
        instance = cls(*args, **kargs)
        return instance