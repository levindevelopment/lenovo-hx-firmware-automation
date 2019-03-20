# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_factory_bioscfg.py
# Compiled at: 2019-02-15 12:42:10
import logging, tempfile, io, re
from ConfigParser import ConfigParser
from lxml import etree
from foundation import factory_mode
from foundation import folder_central
from foundation import foundation_tools as tools
from foundation.imaging_step import ImagingStepNodeTask, ImagingStepClusterTask
STATE_SUM_UPDATING = 'Updating BiosCfg'
STATE_SUM_VERIFYING = 'Verifying BiosCfg'
TYPE_CURRENT = 'GetCurrentBiosCfg'
TYPE_DEFAULT = 'GetDefaultBiosCfg'
CMD_CHANGE = 'ChangeBiosCfg'
SUM_BIN = folder_central.get_smc_sum_path()
SETTINGS_KEY = 'sum_bios_settings_map'
BOARD_KEY = 'Board model'
DEFAULT_LOGGER = logging.getLogger(__name__)

class BiosCfgBase(object):

    class BiosRule(object):

        def __init__(self, cfg, path, name):
            self.cfg = cfg
            self.path = path
            self.name = name

        @property
        def value(self):
            raise NotImplementedError

        @value.setter
        def value(self, new_value):
            raise NotImplementedError

    def __init__(self, node_config):
        self.node_config = node_config

    def sum_cmd(self, cmd, filename, overwrite=False):
        cmd = [SUM_BIN,
         '-i', self.node_config.ipmi_ip,
         '-u', self.node_config.ipmi_user,
         '-p', self.node_config.ipmi_password,
         '-c', cmd,
         '--file', filename]
        if overwrite:
            cmd.append('--overwrite')
        tools.system(self.node_config, cmd)

    def read_raw_cfg(self, cfg_type=TYPE_CURRENT):
        """
        Read current BiosCfg
        
        Return:
          BiosCfg as str
        """
        prefix = 'sumcfg_%s' % self.node_config.ipmi_ip
        with tempfile.NamedTemporaryFile(prefix=prefix) as (cfg_file):
            self.sum_cmd(cfg_type, cfg_file.name, overwrite=True)
            return cfg_file.read()

    def write_raw_cfg(self, new_cfg):
        """
        Write BiosCfg to BMC
        
        Args:
          new_cfg: BiosCfg as str
        """
        prefix = 'sumcfg_%s' % self.node_config.ipmi_ip
        with tempfile.NamedTemporaryFile(prefix=prefix) as (cfg_file):
            cfg_file.write(new_cfg)
            cfg_file.flush()
            self.sum_cmd(CMD_CHANGE, cfg_file.name)

    def loads(self, cfg_str):
        """
        Return the parsed cfg object
        """
        raise NotImplementedError

    def dumps(self, cfg_obj):
        """
        Dump the cfg object to str
        """
        raise NotImplementedError

    def execute(self, rules, check_only=False):
        """
        Execute the bioscfg check or config logic
        
        Return:
          False if values are not matching rules.
        """
        logger = self.node_config.get_logger()
        logger.debug('BiosCfg: fetching current config')
        cfg_obj = self.loads(self.read_raw_cfg())
        check_pass = True
        is_dirty = False
        for path, name_values in rules.items():
            for name, value in name_values.items():
                rule_obj = self.BiosRule(cfg_obj, path, name)
                if rule_obj.value == value:
                    logger.debug('BiosCfg: %s:%s is already set to %s', path, name, value)
                elif check_only:
                    logger.warn('BiosCfg: %s:%s is not set to the desired value: %s (was %s)', path, name, value, rule_obj.value)
                    check_pass = False
                else:
                    logger.warn('BiosCfg: will change %s:%s from %s to %s', path, name, rule_obj.value, value)
                    rule_obj.value = value
                    is_dirty = True

        if check_only:
            return check_pass
        if is_dirty:
            cfg_str = self.dumps(cfg_obj)
            logger.info('Flushing new BiosCfg settings, %s bytes', len(cfg_str))
            self.write_raw_cfg(cfg_str)
        else:
            logger.debug('No changes')
        return is_dirty


class BiosCfgIni(BiosCfgBase):

    class BiosRule(BiosCfgBase.BiosRule):

        @property
        def value(self):
            ini, section, option = self.cfg, self.path, self.name
            assert ini.has_section(section), 'Secition not found: %s' % section
            return ini.get(section, option)

        @value.setter
        def value(self, new_value):
            ini, section, option = self.cfg, self.path, self.name
            ini.set(section, option, new_value)

    def loads(self, cfg_str):
        cfg = ConfigParser()
        cfg.optionxform = str
        cfg.readfp(io.BytesIO(cfg_str))
        for section in cfg.sections():
            for option in cfg.options(section):
                value = cfg.get(section, option)
                value = value.split('//')[0].strip()
                cfg.set(section, option, value)

        return cfg

    def dumps(self, cfg_obj):
        bio = io.BytesIO()
        cfg_obj.write(bio)
        return bio.getvalue()


class BiosCfgXml(BiosCfgBase):

    class BiosRule(BiosCfgBase.BiosRule):

        def get_elem(self):
            root, path = self.cfg, self.path
            match = root.xpath(path)
            assert len(match), 'No match found for rule %s' % path
            assert len(match) == 1, 'Mulitple matches found for rule %s' % path
            return match[0]

        @property
        def value(self):
            attr = self.name
            elem = self.get_elem()
            assert attr in elem.attrib, 'Missing attribute: %s, %s' % (
             attr, elem.attrib)
            return elem.attrib[attr]

        @value.setter
        def value(self, new_value):
            attr = self.name
            elem = self.get_elem()
            elem.attrib[attr] = new_value

    def loads(self, cfg_str):
        parser = etree.XMLParser(strip_cdata=False)
        return etree.XML(cfg_str, parser)

    def dumps(self, cfg_obj):
        return etree.tostring(cfg_obj, pretty_print=True, xml_declaration=True, encoding='ISO-8859-1', standalone='yes')


def get_rules_for_model(board_model):
    factory_config = factory_mode.get_config()
    rules = factory_config.get(SETTINGS_KEY, {})
    match_rules = []
    for rule_key, rule in rules.items():
        if re.search(rule_key, board_model):
            match_rules.append(rule)

    return match_rules


class ImagingStepBiosCfgBase(ImagingStepNodeTask):
    """
    Base ImagingStep to fetch current cfg, new cfg, do diff and action
    """

    def run(self):
        node_config = self.config
        logger = self.logger
        assert hasattr(node_config, 'fru_dict'), 'fru_dict is missing, this step must run after FruCheck'
        board_model = node_config.fru_dict[BOARD_KEY]
        match_rules = get_rules_for_model(board_model)
        if not match_rules:
            logger.debug('SUM: no rule matches this model(%s)', board_model)
            return
        logger.info('SUM: %d rules match model(%s)', len(match_rules), board_model)
        bioscfg_cls = BiosCfgIni
        for rules in match_rules:
            for key, values in rules.items():
                logger.debug('SUM: using rule %s: %s', key, values)
                if key.startswith('//'):
                    bioscfg_cls = BiosCfgXml

        logger.debug('Using %s as BiosCfg class', bioscfg_cls)
        bioscfg_obj = bioscfg_cls(node_config)
        self.action(bioscfg_obj, match_rules)

    def action(self, bioscfg_obj, match_rules):
        raise NotImplementedError


class ImagingStepBiosCfgUpdate(ImagingStepBiosCfgBase):
    """
    ImagingStep to update BiosCfg from sum_settings_map
    """

    def get_progress_timing(self):
        return [
         (
          STATE_SUM_UPDATING, 1)]

    def get_finished_message(self):
        return 'BiosCfg is updated'

    def action(self, bioscfg_obj, match_rules):
        for rules in match_rules:
            bioscfg_obj.execute(rules, check_only=False)


class ImagingStepBiosCfgVerify(ImagingStepBiosCfgBase):
    """
    ImagingStep to verify BiosCfg from sum_settings_map
    """

    def get_progress_timing(self):
        return [
         (
          STATE_SUM_VERIFYING, 1)]

    def get_finished_message(self):
        return 'BiosCfg is verified'

    def action(self, bioscfg_obj, match_rules):
        logger = self.logger
        for rules in match_rules:
            ok = bioscfg_obj.execute(rules, check_only=True)
            if not ok:
                raise StandardError('Failed to verify BiosCfg')

        logger.debug('All values matches the desired value in BiosCfg')


class ImagingStepBiosCfgBarrier(ImagingStepClusterTask):

    def run(self):
        pass