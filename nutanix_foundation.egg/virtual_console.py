# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/virtual_console.py
# Compiled at: 2019-02-15 12:42:10
import json, string, os.path, folder_central, foundation_tools, http_server, imaging_step_type_detection as type_detection
from config_manager import NodeConfig
from foundation_settings import settings as foundation_settings

def launch(node_config):
    """Returns url which can be used to launch virtual console"""
    nc = NodeConfig()
    nc.ipmi_ip = node_config['ipmi_ip']
    nc.ipmi_user = node_config['ipmi_user']
    nc.ipmi_password = node_config['ipmi_password']
    result, device_class = type_detection.detect_device_type(nc)
    if result != type_detection.RESULT_SUCCESS:
        raise StandardError(type_detection.error_message(result, ipmi_ip))
    template_file_name = None
    if device_class in [type_detection.CLASS_SMC_WA, type_detection.CLASS_SMC_W]:
        template_file_name = folder_central.get_templates_folder() + '/smc_console.jnlp'
    else:
        if device_class == type_detection.CLASS_IDRAC7:
            template_file_name = folder_central.get_templates_folder() + '/idrac7_console.jnlp'
        if template_file_name:
            return _instantiate_template(template_file_name, nc, nc.ipmi_ip, nc.ipmi_user, nc.ipmi_password)
        if device_class == type_detection.CLASS_ILO:
            return _get_ilo_console_url(nc.ipmi_ip, nc.ipmi_user, nc.ipmi_password)
    raise StandardError("Unrecognized device class '%s'" % device_class)
    return


def _instantiate_template(template_file_name, node_config, ipmi_ip, ipmi_user, ipmi_password):
    with open(template_file_name) as (fh):
        text = fh.read()
    text = string.Template(text).substitute(locals())
    fname = os.path.basename(template_file_name)
    fname = fname.rstrip('.jnlp') + '_' + ipmi_ip.replace('.', '_') + '.jnlp'
    fpath = folder_central.get_http_files_folder() + '/'
    with open(fpath + fname, 'w') as (fh):
        fh.write(text)
    node_config.foundation_ip = foundation_tools.get_my_ip(ipmi_ip)
    path = 'foundation/%s/%s' % (folder_central.get_relative_files_path(), fname)
    url = http_server.FileServer.make_url_and_hash(path, node_config)
    return url


def _get_ilo_console_url(ipmi_ip, ipmi_user, ipmi_password):
    body = '{\n               "method":"login",\n               "user_login":"%s",\n               "password":"%s"\n         }' % (ipmi_user, ipmi_password)
    url = 'https://%s/json/login_session' % ipmi_ip
    cmd = [folder_central.get_curl_path(), '-X', 'post', '--data', body, '-k',
     url]
    stdout, _, _ = foundation_tools.system(None, cmd, throw_on_error=True, log_on_error=False)
    json_result = json.loads(stdout)
    return 'https://%s/html/java_irc.html?lang=en&sessionKey=%s' % (
     ipmi_ip, json_result['session_key'])