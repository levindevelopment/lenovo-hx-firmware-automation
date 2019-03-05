# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_hypervisor.py
# Compiled at: 2019-02-15 12:42:10
from foundation.imaging_step import ImagingStepNodeTask
from foundation.imaging_step_phoenix import STATE_RUNNING_PHOENIX
STATE_START_QEMU = 'Starting host installer'
STATE_INSTALL_KVM = 'Installing AHV'
STATE_REBOOT_KVM = 'Rebooting AHV'
STATE_INSTALL_ESX = 'Installing ESXi'
STATE_REBOOT_ESX = 'Installed ESXi successfully'
STATE_INSTALL_HYPERV = 'Installing Windows'
STATE_REBOOT_HYPERV = 'Windows Installed'
STATE_INSTALL_LINUX = 'Linux_installing'
STATE_REBOOT_LINUX = 'Linux_rebooting'
STATE_INSTALLED_LINUX = 'Linux_installed'
STATE_INSTALL_XEN = 'XenServer installing'
STATE_REBOOT_XEN = 'XenServer rebooting'
HYP_HB = 60

class InstallHypervisorKVM(ImagingStepNodeTask):

    def get_progress_timing(self):
        return [
         (
          STATE_START_QEMU, 2),
         (
          STATE_INSTALL_KVM, 8),
         (
          STATE_REBOOT_KVM, 1)]

    def run(self):
        if not self.config.image_now:
            self.logger.info('%s skipped', __name__)
            return
        self.set_status(STATE_START_QEMU)
        self.wait_for_event(STATE_RUNNING_PHOENIX)
        self.wait_for_event(STATE_INSTALL_KVM, timeout=900)
        self.wait_for_event(STATE_REBOOT_KVM, timeout=1200, hb_timeout=HYP_HB, hb_callback=lambda _: self.logger.warn('Hypervisor installation takes longer than usual'))


class InstallHypervisorESX(ImagingStepNodeTask):

    def get_progress_timing(self):
        return [
         (
          STATE_START_QEMU, 2),
         (
          STATE_INSTALL_ESX, 7),
         (
          STATE_REBOOT_ESX, 1)]

    def run(self):
        if not self.config.image_now:
            self.logger.info('%s skipped', __name__)
            return
        self.set_status(STATE_START_QEMU)
        self.wait_for_event(STATE_RUNNING_PHOENIX)
        self.wait_for_event(STATE_INSTALL_ESX, timeout=900)
        self.wait_for_event(STATE_REBOOT_ESX, timeout=840, hb_timeout=HYP_HB, hb_callback=lambda _: self.logger.warn('Hypervisor installation takes longer than usual'))


class InstallHypervisorHYPERV(ImagingStepNodeTask):

    def get_progress_timing(self):
        return [
         (
          STATE_START_QEMU, 2),
         (
          STATE_INSTALL_HYPERV, 12),
         (
          STATE_REBOOT_HYPERV, 1)]

    def run(self):
        if not self.config.image_now:
            self.logger.info('%s skipped', __name__)
            return
        self.set_status(STATE_START_QEMU)
        self.wait_for_event(STATE_RUNNING_PHOENIX)
        self.wait_for_event(STATE_INSTALL_HYPERV, timeout=1800)
        self.wait_for_event(STATE_REBOOT_HYPERV, timeout=1800, hb_timeout=HYP_HB, hb_callback=lambda _: self.logger.warn('Hypervisor installation takes longer than usual'))


class InstallHypervisorLINUX(ImagingStepNodeTask):

    def get_progress_timing(self):
        return [
         (
          STATE_START_QEMU, 2),
         (
          STATE_INSTALL_LINUX, 7),
         (
          STATE_REBOOT_LINUX, 2),
         (
          STATE_INSTALLED_LINUX, 2)]

    def run(self):
        if not self.config.image_now:
            self.logger.info('%s skipped', __name__)
            return
        self.set_status(STATE_START_QEMU)
        self.wait_for_event(STATE_RUNNING_PHOENIX)
        self.wait_for_event(STATE_INSTALL_LINUX, timeout=900)
        self.wait_for_event(STATE_REBOOT_LINUX, timeout=3900)
        self.wait_for_event(STATE_INSTALLED_LINUX, timeout=900)


class InstallHypervisorXEN(ImagingStepNodeTask):

    def get_progress_timing(self):
        return [
         (
          STATE_START_QEMU, 2),
         (
          STATE_INSTALL_XEN, 7),
         (
          STATE_REBOOT_XEN, 1)]

    def run(self):
        if not self.config.image_now:
            self.logger.info('%s skipped', __name__)
            return
        self.set_status(STATE_START_QEMU)
        self.wait_for_event(STATE_RUNNING_PHOENIX)
        self.set_status(STATE_INSTALL_XEN)
        self.set_status(STATE_REBOOT_XEN)


class InstallHypervisorFactory(ImagingStepNodeTask):
    """
    Factory class to spawn different class to wait for callbacks to track
    progress of hypervisor installation.
    """
    class_mapping = dict(kvm=InstallHypervisorKVM, esx=InstallHypervisorESX, hyperv=InstallHypervisorHYPERV, linux=InstallHypervisorLINUX, xen=InstallHypervisorXEN)

    def __new__(cls, *args, **kargs):
        config = args[0]
        mapping = InstallHypervisorFactory.class_mapping
        assert hasattr(config, 'hypervisor') and config.hypervisor in mapping, 'Unknown hypervisor %s' % config.hypervisor
        cls = InstallHypervisorFactory.class_mapping[config.hypervisor]
        instance = cls(*args, **kargs)
        return instance