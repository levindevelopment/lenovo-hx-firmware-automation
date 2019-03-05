# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/iso_whitelist.py
# Compiled at: 2019-02-15 12:42:10
import json
from foundation import folder_central
whitelist = {}
mandatory_fields = ('iso_whitelist', 'last_modified')

def load_whitelist():
    global whitelist
    with open(folder_central.get_iso_whitelist()) as (fp):
        whitelist = json.load(fp)
        verify_whitelist(whitelist)


def verify_whitelist(a_whitelist):
    for field in mandatory_fields:
        if field not in a_whitelist:
            raise StandardError("Whitelist doesn't contain mandatory field %s" % field)


def update_whitelist(new_whitelist, update_on_disk=True):
    global whitelist
    verify_whitelist(new_whitelist)
    new_timestamp = new_whitelist['last_modified']
    current_timestamp = whitelist['last_modified']
    if new_timestamp < current_timestamp:
        raise StandardError('The whitelist you uploaded was last updated %s, making it older than the current whitelist, updated %s' % (
         new_timestamp, current_timestamp))
    whitelist = new_whitelist
    if update_on_disk:
        with open(folder_central.get_iso_whitelist(), 'w') as (fp):
            json.dump(new_whitelist, fp, indent=2)


def md5_in_whitelist(md5):
    return md5 in whitelist['iso_whitelist']


def filesize_in_whitelist(filesize):
    if not filesize:
        return False
    for entry in whitelist['iso_whitelist'].itervalues():
        if filesize == entry.get('filesize'):
            return True

    return False


load_whitelist()