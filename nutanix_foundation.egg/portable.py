# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/portable.py
# Compiled at: 2019-02-15 12:42:10
import sys, platform
from foundation import folder_central

def is_win():
    return platform.system() == 'Windows'


def is_mac():
    return platform.system() == 'Darwin'


def is_portable():
    return is_win() or is_mac()


def redirect_to_service_log():
    log_path = folder_central.get_service_log_path()
    log_fd = open(log_path, 'a')
    sys.stdout = sys.stderr = log_fd