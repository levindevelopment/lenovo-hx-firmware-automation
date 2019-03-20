# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/generate_phoenix.py
# Compiled at: 2019-02-15 12:42:10
import logging, os, shutil, sys, tarfile, uuid, folder_central, foundation_tools, phoenix_prep, shared_functions
from foundation import features
from foundation import kvm_prep
from consts import ARCH_PPC, ARCH_X86
BOND_MODES = [
 'dynamic', 'static']
BOND_LACP_RATES = ['fast', 'slow']
SUPPORTED_MODES = ['Installer', 'RescueShell', 'NDPRescueShell']
SUPPORTED_ARCHS = [ARCH_PPC, ARCH_X86]
default_logger = logging.getLogger('console')

class Options(object):
    pass


def get_foundation_version():
    """
    Returns the current foundation version.
    """
    version = foundation_tools.read_foundation_version()
    if version:
        return version
    return 'unknown_version'


def update_phoenix_boot_args(options, phoenix_dir):
    """
    Updates phoenix boot confs with boot args based on input options
    
    Args:
      options (Options): Input options for generating phoenix
      phoenix_dir (string): Directory with phoenix
    
    Returns:
      None
    """

    def _get_arg_string(arg_name, value):
        return ('=').join([arg_name, str(value)])

    def _update_phoenix_boot_confs(additional_args, phoenix_dir):
        cmd_to_append = (' ').join(additional_args)
        boot_conf_init_regex_map = [
         ('boot/isolinux/isolinux.cfg', 'append initrd'),
         ('boot/EFI/BOOT/grub.cfg', 'linuxefi'),
         ('grub.cfg', 'linux')]
        for boot_file, regex in boot_conf_init_regex_map:
            boot_file_path = os.path.join(phoenix_dir, boot_file)
            if os.path.exists(boot_file_path):
                lines = []
                with open(boot_file_path, 'r') as (fd):
                    for line in fd:
                        if regex in line:
                            line = line.strip('\n') + ' ' + cmd_to_append
                        lines.append(line.strip('\n'))

                with open(boot_file_path, 'w') as (fd):
                    fd.write(('\n').join(lines))

    key_args_value_map = [
     (
      'ip', 'PHOENIX_IP', lambda x: x),
     (
      'netmask', 'MASK', lambda x: x),
     (
      'gateway', 'GATEWAY', lambda x: x),
     (
      'vlan', 'VLAN', lambda x: x),
     (
      'bond_mode', 'BOND_MODE',
      lambda x: 4 if x == 'dynamic' else 0),
     (
      'bond_lacp_rate', 'BOND_LACP_RATE',
      lambda x: 0 if x == 'slow' else 1),
     (
      'bond_uplinks', 'BOND_UPLINKS', lambda x: (',').join(x)),
     (
      'test_ip', 'FOUND_IP', lambda x: x)]
    additional_args = []
    for key, arg_name, func in key_args_value_map:
        value = getattr(options, key, None)
        if value is not None:
            additional_args.append(_get_arg_string(arg_name, func(value)))

    if additional_args:
        _update_phoenix_boot_confs(additional_args, phoenix_dir)
    return


def generate_phoenix_iso(options, logger, genesis=False):
    """
    Generates a phoenix iso.
    
    Args:
      options: Input options for generating iso.
      logger: Logger object.
    
    Raises:
      StandardError if any invalid option is provided.
    
    Returns:
      Path to iso if successful. Otherwise None is returned.
    """
    if options.aos_package:
        nos_package = os.path.expanduser(options.aos_package)
        if not os.path.exists(nos_package):
            logger.error("Couldn't find the AOS package at %s" % nos_package)
            return
    else:
        nos_package = None
    if not os.path.exists(options.temp_dir):
        logger.error('The temporary dir specified %s does not exist' % options.temp_dir)
        return
    if not os.path.isdir(options.temp_dir):
        logger.error('The temporary dir specified %s is not a dir' % options.temp_dir)
        return
    if options.mode not in SUPPORTED_MODES:
        logger.error("Unsupported mode '%s' is provided" % options.mode)
        return
    if options.arch not in SUPPORTED_ARCHS:
        logger.error("Unsupported arch '%s' is provided" % options.arch)
        return
    if options.arch == ARCH_PPC and (options.esx or options.hyperv or options.xen):
        logger.error('Only AHV is supported on ppc64le')
        return
    if getattr(options, 'vlan', None) and options.vlan not in range(1, 4095):
        logger.error('Vlan id %s is not >=1 and < 4095', options.vlan)
        return
    if getattr(options, 'ip', None) and not (getattr(options, 'test_ip', None) or getattr(options, 'gateway', None)):
        logger.error("Specify 'test_ip' to test phoenix connectivity")
        return
    phoenix_dir = folder_central.get_phoenix_dir(arch=options.arch)
    if not os.path.exists(phoenix_dir):
        logger.error("Couldn't find default phoenix at %s" % phoenix_dir)
        return
    if options.kvm:
        kvm_path = os.path.expanduser(options.kvm)
        if not os.path.exists(kvm_path):
            logger.error("Couldn't find kvm package at %s" % kvm_path)
            return
        if kvm_path.endswith('.tar.gz'):
            if options.arch == ARCH_PPC:
                raise StandardError('File type tar.gz not supported for arch ppc64le')
            kvm_path = kvm_prep.generate_kvm_iso(kvm_path, options.temp_dir, logger)
        else:
            if not kvm_path.endswith('.iso'):
                raise StandardError('File type not supported. Supported formats are .tar.gz and .iso only. Download a new AHV tarball from the Nutanix portal.')
        hypervisor = {'type': 'kvm', 'path': kvm_path}
    else:
        if options.hyperv:
            hyperv_path = os.path.expanduser(options.hyperv)
            if not os.path.exists(hyperv_path):
                logger.error("Couldn't find hyperv package at %s" % hyperv_path)
                return
            hypervisor = {'type': 'hyperv', 'path': hyperv_path}
        else:
            if options.esx:
                esx_path = os.path.expanduser(options.esx)
                if not os.path.exists(esx_path):
                    logger.error("Couldn't find esx package at %s" % esx_path)
                    return
                hypervisor = {'type': 'esx', 'path': esx_path}
            else:
                if options.xen:
                    xen_path = os.path.expanduser(options.xen)
                    if not os.path.exists(xen_path):
                        logger.error("Couldn't find xen package at %s" % xen_path)
                        return
                    hypervisor = {'type': 'xen', 'path': xen_path}
                else:
                    if options.kvm_from_aos:
                        if not options.aos_package:
                            logger.error('AOS package is not provided. Provide an AOS package using --aos-package <path to AOS package>.')
                            return
                        if options.arch == ARCH_PPC:
                            logger.error('kvm_from_aos option is not supported for arch ppc64le.')
                            return
                        anaconda_tarball = folder_central.get_anaconda_tarball()
                        kvm_path = os.path.join(options.temp_dir, 'kvm.iso')
                        shared_functions.prepare_kvm_from_rpms(anaconda_tarball, kvm_path, nos_pkg_path=os.path.expanduser(options.aos_package))
                        hypervisor = {'type': 'kvm', 'path': kvm_path}
                    else:
                        hypervisor = None
    if hypervisor and not hypervisor['path'].endswith('.iso'):
        raise StandardError('File type not supported. hypervisor image file must ends with .iso (lowercase) as extension name.')
    stat_data = os.statvfs(options.temp_dir)
    partition_free_space = stat_data.f_bsize * stat_data.f_bavail
    if nos_package:
        nos_size = os.path.getsize(nos_package)
    else:
        nos_size = 0
    phoenix_size = 100 * 1048576
    if hypervisor:
        hypervisor_size = os.path.getsize(hypervisor['path'])
    else:
        hypervisor_size = 0
    if not options.skip_space_check:
        size_threshold = 1.25 * (2.0 * (nos_size + phoenix_size + hypervisor_size))
        if partition_free_space < size_threshold:
            logger.error('Partition hosting target directory (%s) is low on free space (%.2f GB space remaining). Please specify a separate directory to write to with --temp_dir=/path . If you are confident ignoring this warning, you may skip the space check with --skip-space-check' % (
             options.temp_dir,
             1.0 * partition_free_space / 1073741824))
            return
    image_dir = '%s/%s' % (options.temp_dir, str(uuid.uuid4()))
    image_images_dir = os.path.join(image_dir, 'images')
    try:
        logger.info('Copying phoenix files to %s', image_dir)
        shutil.copytree(phoenix_dir, image_dir)
        features.load_features_from_json(folder_central.get_foundation_features_path())
        if features.is_enabled(features.CENTOS):
            distro = 'squashfs'
            os.unlink('%s/livecd.tar' % image_dir)
        else:
            distro = 'gentoo'
            foundation_tools.system(None, ['tar', 'xf', '%s/livecd.tar' % image_dir,
             '-C', image_dir])
            os.unlink('%s/livecd.tar' % image_dir)
            os.remove('%s/squashfs.img' % image_dir)
        logger.info('Phoenix will run in %s mode.' % distro)
        logger.info('Copying phoenix updates to %s', image_dir)
        phoenix_prep.create_phoenix_updates_dir(image_dir)
        if any([ features.is_enabled(feature) for feature in features.get_phoenix_pluggable_components()
               ]):
            phoenix_prep.create_phoenix_components_dir(image_dir)
        if not genesis and not options.arch == ARCH_PPC:
            logger.info('Adding hypervisor drivers: kvm')
            shutil.copytree(os.path.join(folder_central.get_driver_dir('kvm'), 'rpms'), os.path.join(image_images_dir, 'rpms'))
            logger.info('Adding hypervisor drivers: esx')
            shutil.copytree(os.path.join(folder_central.get_driver_dir('esx'), 'vibs'), os.path.join(image_images_dir, 'vibs'))
            logger.info('Adding hypervisor drivers: hyperv')
            shutil.copyfile(os.path.join(folder_central.get_driver_dir('hyperv'), 'hyperv_binaries.zip'), os.path.join(image_images_dir, 'hyperv_binaries.zip'))
            logger.info('Adding hypervisor drivers: xen')
            xen_package = folder_central.get_xen_package()
            shutil.copyfile(xen_package, reduce(os.path.join, [image_dir, 'images', 'xen_package.tar.gz']))
        iso_name = 'phoenix-%s' % get_foundation_version()
        if nos_package:
            nos_package_dst = image_dir + '/images/svm'
            if not os.path.exists(nos_package_dst):
                os.makedirs(nos_package_dst)
            logger.info('Copying the AOS from %s to %s' % (
             nos_package, nos_package_dst))
            shutil.copy(nos_package, nos_package_dst)
            nos_archive = os.path.join(nos_package_dst, os.path.basename(nos_package))
            try:
                tf = tarfile.open(nos_archive, 'r:gz')
                tf.close()
                logger.info('Unzipping AOS %s' % nos_archive)
                foundation_tools.system(None, ['gunzip', nos_archive])
            except tarfile.ReadError:
                pass

            iso_name += '_AOS'
        if hypervisor:
            hyp_dir = image_dir + '/images/hypervisor/%s' % hypervisor['type']
            if not os.path.exists(hyp_dir):
                os.makedirs(hyp_dir)
            logger.info('Copying the hypervisor to phoenix')
            shutil.copy(hypervisor['path'], hyp_dir)
            iso_name += '-%s' % hypervisor['type']
        update_phoenix_boot_args(options, image_dir)
        iso_name += '-%s' % options.arch
        logger.info('Preparing phoenix iso in %s mode' % options.mode)
        foundation_tools.system(None, ['%s/make_iso.sh' % image_dir, iso_name,
         options.mode, '1', options.arch, distro])
        logger.info('%s.iso generated in %s/' % (iso_name, options.temp_dir))
        iso_path = os.path.join(options.temp_dir, iso_name + '.iso')
        return iso_path
    except Exception:
        logger.exception('Error while preparing phoenix iso')
        return
    finally:
        logger.info('Cleaning up')
        if image_dir:
            shutil.rmtree(image_dir)
        logger.info('Done')

    return


def generate_phoenix_iso_cli(options, logger):
    """
    Entry point for phoenix iso preparation from CLI.
    
    Args:
      options: CLI options for generating iso.
    """
    iso = generate_phoenix_iso(options, logger)
    if iso:
        sys.exit(1)
    sys.exit(0)


def generate_phoenix_iso_http(params, logger=None):
    """
    Entry point for phoenix iso preparation from rest api.
    
    Args:
      params: Dict of parameters for generating phoenix.
      logger: Logger object.
    
    Raises:
      StandardError if iso generation fails.
    
    Returns:
      Relative path to the tmp file server of foundation.
    """
    logger = logger or default_logger
    if 'mode' not in params:
        params['mode'] = 'NDPRescueShell'
    if params['mode'] not in SUPPORTED_MODES:
        raise StandardError("Given mode '%s' is not supported" % params['mode'])
    if 'arch' not in params:
        params['arch'] = ARCH_X86
    if params['arch'] not in SUPPORTED_ARCHS:
        raise StandardError("Given arch '%s' is not supported" % params['arch'])
    if params.get('ip') and not params.get('test_ip'):
        raise StandardError("Specify 'test_ip' to test phoenix connectivity")
    if 'bond_mode' in params and params['bond_mode'] == 'dynamic' and 'bond_lacp_rate' not in params:
        params['bond_lacp_rate'] = 'fast'
    options = Options()
    required_params = [
     'aos_package', 'temp_dir', 'kvm', 'hyperv', 'esx', 'xen',
     'kvm_from_aos', 'skip_space_check', 'mode', 'arch', 'ip',
     'netmask', 'gateway', 'vlan', 'bond_mode', 'bond_lacp_rate',
     'bond_uplinks', 'test_ip']
    for param in required_params:
        setattr(options, param, params.get(param))

    temp_dir = folder_central.get_tmp_folder(session_id=None)
    options.temp_dir = os.path.join(temp_dir, str(uuid.uuid4()))
    os.mkdir(options.temp_dir)
    options.skip_space_check = False
    options.mode = params['mode']
    options.arch = params['arch']
    iso = generate_phoenix_iso(options, logger, genesis=True)
    if not iso:
        raise StandardError('Failed to generate phoenix iso')
    return iso