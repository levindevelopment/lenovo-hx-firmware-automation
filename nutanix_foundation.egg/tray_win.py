# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/tray_win.py
# Compiled at: 2019-02-15 12:42:10
import os, webbrowser, cherrypy
from infi.systray import SysTrayIcon
from foundation import folder_central as fc
from foundation import foundation_tools
from foundation.foundation_tools import subprocess
ICO_PATH = 'app-extension\\assets\\images-ext\\favicon\\favicon.ico'

def do_open(systray):
    port = cherrypy.server.socket_port
    url = 'http://localhost:%s/' % port
    webbrowser.open_new_tab(url)


def do_open_dir(dir_):
    subprocess.call(['explorer', dir_])


def get_tray():
    icon = os.path.join(fc.get_standalone_gui_path(), ICO_PATH)
    menu_options = (
     (
      'Open Foundation', None, do_open),
     (
      'Folders', None,
      (
       (
        'AOS', None, lambda _: do_open_dir(fc.get_nos_folder())),
       (
        'Hypervisor', None,
        lambda _: do_open_dir(fc.get_hypervisor_isos_folder(''))),
       (
        'Logs', None, lambda _: do_open_dir(fc.get_log_folder())))))
    version = foundation_tools.read_foundation_version()
    systray = SysTrayIcon(icon, 'foundation %s' % version, menu_options)
    return systray


def start():
    tray = get_tray()
    tray.start()
    tray._message_loop_thread.join()