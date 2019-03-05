# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/update_manager.py
# Compiled at: 2019-02-15 12:42:10
import json, logging, os, platform, subprocess, threading, urllib, urllib2, consts, folder_central, foundation_tools, foundation_settings
UPDATE_LINK = 'http://release-api.nutanix.com/api/v1/foundation?api_key=bnV0YW5peDpudXRhbml4LzR1'
PPC_FILTER = '&arch=ppc64le'
api_logger = logging.getLogger('foundation.api')

def is_update_available():
    url = UPDATE_LINK
    upgrade_override_url = foundation_settings.get_settings().get('upgrade_override_url')
    if upgrade_override_url:
        url = upgrade_override_url
    if platform.machine() == consts.ARCH_PPC:
        url += PPC_FILTER
    response = urllib.urlopen(url)
    data = json.loads(response.read())
    releases = data.get('releases', [])
    latest_release = None
    if len(releases) == 0:
        return False
    comparator = foundation_tools.compare_foundation_version_strings
    latest_release = sorted(releases, key=lambda x: x['version_id'], cmp=comparator)[-1]
    if latest_release:
        version_cmp = foundation_tools.compare_foundation_version_strings(latest_release.get('version_id', 0), foundation_tools.read_foundation_version())
        if version_cmp == 1:
            return latest_release
        return False
    else:
        return False
    return


def download_update(tar_url, md5sum=None):
    dest_dir = folder_central.get_update_foundation_dir()
    if not os.path.exists(dest_dir):
        os.makedirs(dest_dir)
    file_name = tar_url.split('/')[-1]
    dest_file = os.path.join(dest_dir, file_name)
    u = urllib2.urlopen(tar_url)
    f = open(dest_file, 'wb')
    meta = u.info()
    file_size = int(meta.getheaders('Content-Length')[0])
    file_size_dl = 0
    block_sz = 8192
    while True:
        buffer = u.read(block_sz)
        if not buffer:
            break
        file_size_dl += len(buffer)
        f.write(buffer)

    f.close()
    if dest_file and md5sum:
        downloaded_md5 = foundation_tools.get_md5sum(dest_file)
        if md5sum != downloaded_md5:
            raise StandardError('Foundation update failed. Downloaded update was         corrupt.')
    return dest_file


def get_last_update_log_path():
    upgrade_dir = folder_central.get_update_foundation_dir()
    return os.path.join(upgrade_dir, 'upgrade.log')


def get_last_update_status():
    log_file = get_last_update_log_path()
    if not os.path.exists(log_file):
        return 'No auto update in progress'
    log_handle = open(log_file, 'r')
    lines = log_handle.read()
    success = lines.find('Successfully completed upgrading foundation')
    failure = lines.find('Foundation upgrade failed')
    if success >= 0:
        return 'Success'
    if failure >= 0:
        return 'Failure'
    return 'In Progress'


def inititate_foundation_update(update_tar):
    upgrade_script = folder_central.get_upgrade_foundation_script()
    _, tarname = os.path.split(update_tar)
    upgrade_dir = folder_central.get_update_foundation_dir()
    if not os.path.exists(upgrade_dir):
        os.makedirs(upgrade_dir)
    log_file = os.path.join(upgrade_dir, 'upgrade.log')
    if os.path.exists(log_file):
        os.remove(log_file)
    open(log_file, 'a').close()
    api_logger.info('Starting foundation upgrade with a delay at %s ' % upgrade_script)
    cmd = [
     str(upgrade_script), '-t', str(update_tar), '-d', '2', '-a',
     str(True), '-l', str(log_file)]
    if os.name == 'posix':
        subprocess.Popen(cmd, close_fds=True, preexec_fn=os.setsid)
    else:
        subprocess.Popen(cmd, close_fds=True, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)


def kick_off_foundation_update(update_tar, delay=5.0):
    api_logger.info('Kickoff foundation update')
    upgrade_dir = folder_central.get_update_foundation_dir()
    if not os.path.exists(upgrade_dir):
        os.makedirs(upgrade_dir)
    log_file = os.path.join(upgrade_dir, 'upgrade.log')
    if os.path.exists(log_file):
        os.remove(log_file)
    open(log_file, 'a').close()
    t = threading.Timer(delay, inititate_foundation_update, [update_tar])
    t.start()


def restart_foundation():
    subprocess.call(['service', 'foundation_service', 'restart'])


def kick_off_restart_foundation(delay=2.0):
    api_logger.info('Restarting foundation service')
    t = threading.Timer(delay, restart_foundation)
    t.start()