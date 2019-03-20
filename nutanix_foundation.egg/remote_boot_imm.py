# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/remote_boot_imm.py
# Compiled at: 2019-02-15 12:42:10
import re, subprocess, tempfile, folder_central, foundation_tools
MAX_MOUNT_TIME_S = 60
import logging, os, time, urllib
from threading import Lock, Thread
from pyghmi.ipmi.oem.lenovo.imm import IMMClient
import remote_boot_ipmi
from foundation.ipmi_util import ipmi_context
from foundation.lenovo_util import LenovoUtil
logger = logging.getLogger(__file__)
API_IMAGES = '/designs/imm/dataproviders/imm_rp_images.php'
API_IMAGE_UPLOAD = '/designs/imm/upload/rp_image_upload.esp'
API_UPLOAD_STATUS = '/designs/imm/upload/rp_image_upload_status.esp'
API_DATA_SET = '/data?set'
DEF_NAME = 'phoenix.iso'
SUCC = 'Success'
SLEEP_TICK = 10
TICK = 2
ATTEMPT = 5
_rdmount_lock = Lock()

class RemoteBootASU(remote_boot_ipmi.RemoteBootIPMI):

    def set_first_boot_device(self):
        pass

    def boot(self, iso, do_reset=True):
        logger = self.node_config.get_logger()
        asu_path = folder_central.get_lenovo_asu_path()
        self.stop()
        time.sleep(1)
        with tempfile.NamedTemporaryFile() as (tmp_file):
            cmd = 'sudo "%s" -s "%s" -d "%s" -l "%s" -p "%s" > %s 2>&1' % (
             os.path.join(asu_path, 'rdcli-x86_64/rdmount'),
             self.node_config.ipmi_ip, iso, self.node_config.ipmi_user,
             self.node_config.ipmi_password, tmp_file.name)
            with _rdmount_lock:
                process = subprocess.Popen(cmd, shell=True)
                process.communicate()
            with open(tmp_file.name) as (f):
                output = f.read()
        if not ('Success.' in output or 'successful.' in output):
            logger.info(output)
            raise StandardError('rdmount failed to create mount')
        if not self._get_rdmount_token():
            raise StandardError('rdmount failed to create mount - sanity test failed')
        if do_reset:
            out, err, ret = foundation_tools.ipmitool_with_retry(self.node_config, ['chassis', 'power', 'off'], ipmitool_=self.ipmitool)
            out, err, ret = foundation_tools.ipmitool_with_retry(self.node_config, ['chassis', 'power', 'on'], ipmitool_=self.ipmitool)

    def _get_rdmount_token(self):
        asu_path = folder_central.get_lenovo_asu_path()
        cmd = ['sudo',
         os.path.join(asu_path, 'rdcli-x86_64/rdmount'),
         '-q']
        with _rdmount_lock:
            stdout, stderr, return_code = foundation_tools.system(self.node_config, cmd, throw_on_error=False, timeout=10)
        for line in stdout.splitlines():
            match = re.search('Token (\\d+): drive path (\\S+) mounted to SP (\\S+)', line)
            if match:
                token = match.group(1)
                iso = match.group(2)
                ip = match.group(3)
                if ip == self.node_config.ipmi_ip:
                    return token

        return

    def stop(self):
        asu_path = folder_central.get_lenovo_asu_path()
        token = self._get_rdmount_token()
        if not token:
            return
        cmd = ['sudo',
         os.path.join(asu_path, 'rdcli-x86_64/rdumount'),
         token]
        stdout, stderr, return_code = foundation_tools.system(self.node_config, cmd, throw_on_error=False, timeout=10)


wc_lock = Lock()

class IMM2Client(IMMClient):

    def __init__(self, *args):
        super(IMM2Client, self).__init__(*args)
        self._keep_alive = False

    def keep_alive_thread(self):
        while self._keep_alive:
            self.list_remote_media()
            time.sleep(SLEEP_TICK)

    def list_remote_media(self):
        return self.wc.grab_json_response(API_IMAGES)

    def _allocate_loc(self, name=DEF_NAME):
        """
        Allocate a path for upload
        
        Return:
        {"return" : "Success",
         "slotId" : 0,
         "filePath" : "/pstorage/remote_disk/phoenix_buildroot.iso",
         "available" : 52428800
        }
        """
        resp = self.wc.grab_json_response(API_DATA_SET, 'RP_VmAllocateLoc(%s,%s,1):' % (self.username, name))
        assert resp['return'] == SUCC, 'failed to allocate: %s' % resp
        return resp

    def _upload_status(self, file_path):
        """
        Check upload status
        
        Return:
        { # not mounted
        "originalFileSize":29460800,
        "rpImgUploadResult":"false"
        }
        
        { # mounted
        "originalFileSize":29460800,
        "rpImgUploadResult":"1519768187670-Success"  # &checksum=1519768187670
        }
        """
        return self.wc.grab_json_response(API_UPLOAD_STATUS + '?' + urllib.urlencode({'filePath': file_path}))

    def attach_remote_media(self, iso, name=DEF_NAME, logout=False, keep_alive=True):
        cur_media = self.list_remote_media()
        free_sz = cur_media['items'][0]['available']
        iso_sz = os.path.getsize(iso)
        assert free_sz > iso_sz, "%s(%s) is larger than imm2's available space(%s)" % (
         iso, iso_sz, free_sz)
        logger.debug('Allocating path for %s', iso)
        alloc_resp = self._allocate_loc(name)
        logger.debug('Uploading %s', iso)
        checksum = str(int(time.time()))
        file_path = alloc_resp['filePath']
        upload_api = API_IMAGE_UPLOAD + '?' + urllib.urlencode({'checksum': checksum, 'filePath': file_path, 
           'available': alloc_resp['available']})
        with wc_lock:
            self.wc.upload(upload_api, name, data=open(iso, 'rb'))
        upload_status = self._upload_status(file_path)
        assert upload_status['originalFileSize'] >= iso_sz, 'upload failed, local: %s, remote: %s' % (iso_sz, upload_status)
        remote_sz = upload_status['originalFileSize']
        logger.debug('Updating size %s, %s', iso, remote_sz)
        update_resp = self.wc.grab_json_response(API_DATA_SET, data='RP_VmUpdateSize(0, %s)' % remote_sz)
        assert update_resp['return'] == SUCC, 'failed to upload %s: %s' % (
         iso, update_resp)
        marker = '%s-%s' % (checksum, SUCC)
        for i in range(ATTEMPT):
            upload_status = self._upload_status(file_path)
            if upload_status['rpImgUploadResult'] == marker:
                break
            else:
                logger.debug('Checking upload %s: %s', iso, upload_status)
                time.sleep(TICK)
        else:
            raise StandardError('Failed to comfirm upload status, please reset IMM and retry: %s' % upload_status)

        mount_resp = self.wc.grab_json_response(API_DATA_SET, data='RP_VmMount(0)')
        assert mount_resp['return'] == SUCC, 'failed to mount %s: %s' % (
         iso, mount_resp)
        for i in range(ATTEMPT):
            image_status = self.list_remote_media()
            file_status = image_status['items'][0]['images'][0]['status']
            if file_status == 5:
                logger.info('Mounted %s', iso)
                break
            else:
                if file_status == 3:
                    logger.debug('Mouting %s', iso)
            time.sleep(TICK)
        else:
            raise StandardError('Failed to mount the iso, please reset IMM and retry: %s' % file_status)

        if keep_alive:
            self._keep_alive = True
            thread = Thread(target=self.keep_alive_thread)
            thread.daemon = True
            thread.start()
        if logout:
            self.weblogout()

    def detach_remote_media(self, logout=True):
        self._keep_alive = False
        mnt = self.wc.grab_json_response('/designs/imm/dataproviders/imm_rp_images.php')
        slots = set()
        for item in mnt.get('items', []):
            if 'images' in item:
                for image in item['images']:
                    if image['status']:
                        logger.debug('Removing %s', image['filename'])
                        slots.add(image['slotId'])

        for slot in slots:
            params = ('RP_RemoveFile({0},0)').format(slot)
            result = self.wc.grab_json_response('/data?set', params)
            if result['return'] != SUCC:
                logger.error('failed to umount: %s', result)

        if logout:
            self.weblogout()


class RemoteBootIMM2(remote_boot_ipmi.RemoteBootIPMI):

    def _init_session(self):
        self.util = LenovoUtil(self.node_config.ipmi_ip, self.node_config.ipmi_user, self.node_config.ipmi_password)
        self.util.get_session()
        self.session = self.util.session
        self.imm = IMM2Client(self.session)

    def set_first_boot_device(self):
        pass

    def set_power(self, state, wait=False):
        with ipmi_context(self.node_config) as (ipmi):
            ipmi.set_power(state, wait=wait)

    def boot(self, iso, do_reset=True):
        if not hasattr(self, 'session'):
            self._init_session()
        self.stop()
        self.set_power('off', wait=True)
        self.imm.attach_remote_media(iso)
        if do_reset:
            self.set_power('on', wait=True)

    def poweroff(self):
        self.set_power('off', wait=True)

    def stop(self):
        if hasattr(self, 'imm'):
            self.imm.detach_remote_media()


def mount(ip, username, password, iso):
    logging.basicConfig(level=logging.DEBUG)
    util = LenovoUtil(ip, username, password)
    util.get_session()
    session = util.session
    imm = IMM2Client(session)
    imm.detach_remote_media(logout=False)
    print 'Mounting', iso, 'to', ip
    imm.attach_remote_media(iso)
    ans = raw_input('umount? (y/n)')
    if ans != 'n':
        print 'Unmounting'
        imm.detach_remote_media()


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 5:
        print 'usage: %s IP USER PASS path/to/iso'
    else:
        mount(*sys.argv[1:])