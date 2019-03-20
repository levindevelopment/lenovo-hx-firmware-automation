# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_prepare_dell.py
# Compiled at: 2019-02-15 12:42:10
import re, racadm
from imaging_step import ImagingStepNodeTask
from imaging_step_type_detection import CLASS_IDRAC7, CLASS_IDRAC8, CLASS_IDRAC9
AHCI_SATA_DISK_REGEX = re.compile('Disk\\.Direct\\S*:AHCI\\S*')
AHCI_MARVELL_BOSS_CARD = re.compile('AHCI\\.(Integrated|Slot)\\.\\S+')
INTERNAL_SD_CARD_REGEX = re.compile('Disk\\.SDInternal\\S*')
SATADOM_REGEX = re.compile('Disk\\.SATAEmbedded\\S*')
STATE_SET_BOOT_MODE = 'Setting boot mode to Bios'
STATE_SET_BOOT_SEQ = 'Setting Hdd boot sequence'
STATE_FIX_BIOS_SETTINGS = 'Fixing BIOS settings'

class ImagingStepPrepareDell(ImagingStepNodeTask):

    def will_run(self):
        return getattr(self.config, 'type', None) in [
         CLASS_IDRAC7, CLASS_IDRAC8, CLASS_IDRAC9] and racadm.get_model(self.config).startswith('PowerEdge')

    def get_progress_timing(self):
        return [
         (
          STATE_SET_BOOT_MODE, 6),
         (
          STATE_SET_BOOT_SEQ, 6),
         (
          STATE_FIX_BIOS_SETTINGS, 6)]

    def run(self):
        logger = self.logger
        if not self.will_run():
            logger.info('%s skipped' % self.__class__.__name__)
            return
        self.set_status(STATE_SET_BOOT_MODE)
        boot_mode = racadm.get_biosbootsettings_bootmode(self.config)
        logger.debug('Current boot mode: %s' % boot_mode)
        if boot_mode.lower() != 'bios':
            logger.debug('Changing boot mode to Bios')
            racadm.set_biosbootsettings_bootmode(self.config, 'Bios')
            racadm.execute_bios_settings_reboot_job(self.config)
            new_boot_mode = racadm.get_biosbootsettings_bootmode(self.config)
            if new_boot_mode.lower() != 'bios':
                raise StandardError('Failed to change boot mode to Bios')
        self.set_status(STATE_SET_BOOT_SEQ)
        hw_inventory = racadm.get_hwinventory(self.config)
        boss_card_present = any([ AHCI_MARVELL_BOSS_CARD.match(hw['InstanceID']) for hw in hw_inventory
                                ])
        logger.debug('BOSS card present: %s' % boss_card_present)
        satadom_present = any([ AHCI_SATA_DISK_REGEX.match(hw['InstanceID']) for hw in hw_inventory
                              ])
        logger.debug('SATADOM present: %s' % satadom_present)
        current_boot_seq = racadm.get_harddrive_boot_seq(self.config)
        logger.debug('Current boot sequence: %s' % current_boot_seq)
        sd_card_index = None
        sd_card_hd = None
        satadom_index = None
        satadom_hd = None
        boss_card_index = None
        boss_card_hd = None
        for i, hd in enumerate(current_boot_seq):
            if INTERNAL_SD_CARD_REGEX.match(hd):
                sd_card_index = i
                sd_card_hd = hd
            if SATADOM_REGEX.match(hd):
                satadom_index = i
                satadom_hd = hd
            if AHCI_MARVELL_BOSS_CARD.match(hd):
                boss_card_index = i
                boss_card_hd = hd

        def validate_boot_order(expected_boot_order):
            boot_order = racadm.get_harddrive_boot_seq(self.config)
            if boot_order != expected_boot_order:
                raise StandardError('Failed to change boot order to %s' % expected_boot_order)

        if boss_card_present:
            if boss_card_index is not None and boss_card_index != 0:
                current_boot_seq.pop(boss_card_index)
                current_boot_seq.insert(0, boss_card_hd)
                logger.debug('New boot sequence: %s' % current_boot_seq)
                racadm.set_harddrive_boot_seq(self.config, current_boot_seq)
                racadm.execute_bios_settings_reboot_job(self.config)
                validate_boot_order(current_boot_seq)
            else:
                logger.debug('No need to change boot sequence')
        else:
            if satadom_present:
                if satadom_index is not None and satadom_index != 0:
                    current_boot_seq.pop(satadom_index)
                    current_boot_seq.insert(0, satadom_hd)
                    logger.debug('New boot sequence: %s' % current_boot_seq)
                    racadm.set_harddrive_boot_seq(self.config, current_boot_seq)
                    racadm.execute_bios_settings_reboot_job(self.config)
                    validate_boot_order(current_boot_seq)
                else:
                    logger.debug('No need to change boot sequence')
            else:
                if sd_card_index is not None and sd_card_index != 0:
                    current_boot_seq.pop(sd_card_index)
                    current_boot_seq.insert(0, sd_card_hd)
                    logger.debug('New boot sequence: %s' % current_boot_seq)
                    racadm.set_harddrive_boot_seq(self.config, current_boot_seq)
                    racadm.execute_bios_settings_reboot_job(self.config)
                    validate_boot_order(current_boot_seq)
                else:
                    logger.debug('No need to change boot sequence')
        self.set_status(STATE_FIX_BIOS_SETTINGS)
        bios_settings = {'bios.ProcSettings.ProcX2Apic': 'Enabled', 
           'bios.SataSettings.WriteCache': 'Enabled', 
           'bios.IntegratedDevices.IoatEngine': 'Enabled', 
           'bios.IntegratedDevices.SriovGlobalEnable': 'Enabled', 
           'bios.IntegratedDevices.MmioAbove4Gb': 'Disabled'}
        if self.config.type == CLASS_IDRAC9:
            bios_settings['bios.MemSettings.CorrEccSmi'] = 'Disabled'
            bios_settings['bios.IntegratedDevices.MmioAbove4Gb'] = 'Enabled'
            bios_settings['bios.IntegratedDevices.MemoryMappedIOH'] = '12TB'
        else:
            bios_settings['bios.SysProfileSettings.SysProfile'] = 'PerfPerWattOptimizedOs'
        reboot_required = False
        for key, value in bios_settings.iteritems():
            reboot_required |= racadm.set_bios_property_if_required(self.config, key, value)

        if reboot_required:
            racadm.execute_bios_settings_reboot_job(self.config)
        return