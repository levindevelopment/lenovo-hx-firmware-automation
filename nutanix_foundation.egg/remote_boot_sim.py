# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/remote_boot_sim.py
# Compiled at: 2019-02-15 12:42:10
import remote_boot, threading, time, urllib2
from urllib import quote
from foundation_settings import settings as foundation_settings
from foundation.imaging_step_phoenix import STATE_LAST_REBOOT

class RemoteBootSim(remote_boot.RemoteBoot):

    def __init__(self, node_config):
        remote_boot.RemoteBoot.__init__(self, node_config)
        self.boot_called = False
        self.stop_called = False

    def boot(self, iso, do_reset=True):
        if self.boot_called:
            raise StandardError('Internal error: boot called twice')
        self.boot_called = True
        self.stop_called = False
        self.thread = threading.Thread(target=self.sim_thread)
        self.thread.start()

    def stop(self):
        if self.stop_called:
            raise StandardError('Internal error: stop called twice')
        self.stop_called = True
        self.boot_called = False
        self.thread.join()

    def post_log_text(self, node_id, step, offset, text):
        headers = {'Content-Type': 'application/text; charset=utf-8'}
        url = 'http://localhost:%d/foundation/log?node_id=%s&step=%s&offset=%d' % (
         foundation_settings['http_port'], node_id, step, offset)
        req = urllib2.Request(url, text, headers)
        result = urllib2.urlopen(req)
        if result.getcode() != 200:
            raise StandardError('post_log_text received HTTP error')

    def sim_thread(self):
        time.sleep(1)
        node_id = self.node_config.cvm_ip
        if self.node_config.should_fail:
            self.post_log_text(node_id, 'fatal', 0, 'some fatal error')
        else:
            self.post_log_text(node_id, quote(STATE_LAST_REBOOT), 0, 'all done')

    def poweroff(self):
        pass

    def wait_for_poweroff(self):
        pass