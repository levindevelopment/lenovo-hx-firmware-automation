# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_disk_check.py
# Compiled at: 2019-02-15 12:42:10
import json, os, re, shlex, shutil, tarfile, tempfile, time, folder_central, foundation_tools
from imaging_step import ImagingStepNodeTask
STATE_CHECKING_DISKS = 'Checking disk quantity and size'
STATE_CHECKING_DISKS_DONE = 'Disk check passed'
DISK_RE = re.compile('\\d+\\s+/dev/(?:sd|nvme).*?(\\d+(?:\\.\\d+)?) ([GT])B')
BLOCK_SERIAL_RE = re.compile('Product Serial\\s+:\\s+(\\S+)')
CVM_SSH_RETRY = 60
LIST_DISK_RETRY = 6
TICK = 10

def get_latest_hcl(nos_package):
    disk_hcl_nos = None
    using_hcl_from_nos = False
    with open(folder_central.get_hcl_path()) as (fh):
        disk_hcl = json.load(fh)
    temp_dir = tempfile.mkdtemp()
    if not os.path.exists(nos_package) and nos_package.endswith('.tar.gz'):
        nos_package = nos_package[:-3]
    nos_tarball = tarfile.open(nos_package)
    hcl_member = foundation_tools.get_packages_path_in_tar(nos_tarball, path_suffix='hcl.json', raise_on_error=False)
    if hcl_member:
        nos_tarball.extract(hcl_member, path=temp_dir)
        hcl_path = os.path.join(temp_dir, hcl_member)
        with open(hcl_path) as (fd):
            disk_hcl_nos = json.load(fd)
    if disk_hcl_nos and disk_hcl_nos['last_edit'] > disk_hcl['last_edit']:
        disk_hcl = disk_hcl_nos
        using_hcl_from_nos = True
    shutil.rmtree(temp_dir)
    return (
     disk_hcl, using_hcl_from_nos)


def get_disk_check_configs():
    with open(folder_central.get_disk_check_config_path()) as (fd):
        return json.load(fd)


class ImagingStepDiskCheck(ImagingStepNodeTask):

    def get_progress_timing(self):
        return [
         (
          STATE_CHECKING_DISKS, 0.1)]

    def get_finished_message(self):
        return STATE_CHECKING_DISKS_DONE

    def run(self):
        node_config = self.config
        logger = self.logger
        self.set_status(STATE_CHECKING_DISKS)
        disk_hcl, hcl_from_nos = node_config._cache.get(get_latest_hcl, node_config.nos_package)
        if hcl_from_nos:
            logger.info('Using hcl.json from NOS tarball')
        ssd_models = []
        nvme_models = []
        for disk in disk_hcl['SSD']:
            if disk['interface'] == 'PCIe':
                nvme_models.append(disk['model'])
            else:
                ssd_models.append(disk['model'])

        logger.debug('Loaded %s SSD models and %s NVME models', len(ssd_models), len(nvme_models))
        logger.info('Checking disk quantity and capacity')
        stdout, stderr, retval = foundation_tools.ipmitool(node_config, [
         'fru'], throw_on_error=True)
        block_serial_match = BLOCK_SERIAL_RE.search(stdout)
        fru_block_serial = block_serial_match.groups()[0].strip().lower()
        xnode = 'smxs' in fru_block_serial or 'sxxs' in fru_block_serial
        gold_block = 'gold' in node_config.block_id.lower()
        skip_size_check = xnode or gold_block
        if skip_size_check:
            logger.warn('This node is a xnode or gold, will only do drive qty checked')
        for retry in range(CVM_SSH_RETRY):
            _, _, ret = foundation_tools.ssh(node_config, node_config.cvm_ip, ['true'], throw_on_error=False, log_on_error=False)
            if not ret:
                break
            else:
                logger.debug('[%s/%ss] Connecting to CVM', TICK * retry, TICK * CVM_SSH_RETRY)
                time.sleep(TICK)
        else:
            raise StandardError('Failed to connect to CVM, please check if CVM is running')

        hardware_config, _, _ = foundation_tools.ssh(node_config, node_config.cvm_ip, ['cat', '/etc/nutanix/hardware_config.json'])
        node_config.hardware_config = json.loads(hardware_config)
        model = node_config.hardware_config['node']['model_string']
        config = get_disk_check_configs()[model]
        list_disks_cmd = shlex.split('bash -lc "list_disks"')
        for attempt in range(LIST_DISK_RETRY):
            try:
                out, err, ret = foundation_tools.ssh(node_config, node_config.cvm_ip, list_disks_cmd)
                break
            except StandardError as e:
                logger.warn('[%d/%ds] Failed to execute list_disks on CVM, error: %s', TICK * attempt, TICK * LIST_DISK_RETRY, e)
                time.sleep(TICK)

        else:
            raise StandardError('Failed to execute list_disks on CVM')

        disks = out.splitlines()
        logger.info('Disk check list_disks: \n%s' % out)
        ssds = 0
        hdds = 0
        nvmes = 0
        for disk in disks:
            if 'Slot' in disk or '---' in disk:
                continue
            if not DISK_RE.match(disk):
                logger.warn('unrecognized entry in list_disks: %s', disk)
                continue
            size, unit = DISK_RE.match(disk).groups()
            if unit == 'T':
                size = int(float(size) * 1000)
            else:
                size = int(size)
            if any([ nvme_model in disk for nvme_model in nvme_models ]):
                nvmes += 1
                if size < config.get('min_nvme_size', 0) and not skip_size_check:
                    raise StandardError('Found NVME SSD of inadequate size. Expected %d GB. Here are the disks found:\n%s' % (
                     config['min_nvme_size'], out))
            elif any([ ssd_model in disk for ssd_model in ssd_models ]):
                ssds += 1
                if size < config.get('min_ssd_size', 0) and not skip_size_check:
                    raise StandardError('Found SSD of inadequate size. Expected %d GB. Here are the disks found:\n%s' % (
                     config['min_ssd_size'], out))
            else:
                hdds += 1
                if size < config.get('min_hdd_size', 0) and not skip_size_check:
                    raise StandardError('Found HDD of inadequate size. Expected %d GB. Here are the disks found:\n%s' % (
                     config['min_hdd_size'], out))

        if nvmes < config.get('min_nvme', 0):
            raise StandardError('Found too few NVME SSDs. Expected %d.Here are the disks found:\n%s' % (
             config['min_ssd'], out))
        if ssds < config.get('min_ssd', 0):
            raise StandardError('Found too few SSDs. Expected %d. Here are the disks found:\n%s' % (
             config['min_ssd'], out))
        if hdds < config.get('min_hdd', 0):
            raise StandardError('Found too few HDDs. Expected %d. Here are the disks found:\n%s' % (
             config['min_hdd'], out))
        logger.info('Disk check passed')