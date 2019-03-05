# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/foundation_settings.py
# Compiled at: 2019-02-15 12:42:10
import json, os, shutil, traceback, folder_central
ipv6_interface = '2'
settings = {}
overwrite_keys = [
 'version']

def load_settings():
    global settings
    settings_path = folder_central.get_foundation_settings_path()
    template_path = folder_central.get_foundation_settings_template_path()
    if not os.path.exists(template_path):
        raise StandardError('%s does not exist' % template_path)
    if not os.path.exists(settings_path):
        message = '%s does not exist. Using %s for default values' % (
         settings_path, template_path)
        shutil.copy(template_path, settings_path)
    try:
        template = json.load(open(template_path))
    except Exception as e:
        message = 'Failed to read %s. Encountered exception: %s' % (
         template_path, str(e))
        raise StandardError(message)
    else:
        try:
            settings = json.load(open(settings_path))
            req_keys = ['http_port', 'ipv6_interface']
            missing_keys = []
            for key in req_keys:
                if key not in settings:
                    missing_keys.append(key)

            if missing_keys:
                print 'Missing mandatory keys (%s) in %s' % (missing_keys, settings_path)
        except:
            message = 'An exception occurred while trying to read %s. Please make sure the file exists and is a valid json. The exception encountered is \n%s' % (
             settings_path, traceback.format_exc())
            raise StandardError(message)

    if 'version' not in settings or settings['version'] < template['version'] or missing_keys:
        overwrote_keys = []
        for key in template:
            if key in overwrite_keys and key in missing_keys:
                settings[key] = template[key]
                overwrote_keys.append(key)
            elif key in settings:
                continue
            elif key in missing_keys:
                settings[key] = template[key]
                overwrote_keys.append(key)
            else:
                settings[key] = template[key]
                overwrote_keys.append(key)

        print 'Upgraded keys %s in %s' % (overwrote_keys, settings_path)
        shutil.copy(settings_path, settings_path + '.bak')
        print 'Setting file is backuped at %s.bak ' % settings_path
        json.dump(settings, open(settings_path, 'w'), indent=2)


def get_settings():
    return settings


load_settings()