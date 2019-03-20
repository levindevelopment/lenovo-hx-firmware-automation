# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/set_inspur_bmc_ip.py
# Compiled at: 2019-02-15 12:42:10
import json, logging, requests
from foundation.foundation_tools import get_ipv6_link_local_from_mac
default_logger = logging.getLogger(__file__)

def set_inspur_ip(mac, interface, username, password, ipv4, netmask, gateway):
    """
    Sets BMC IP for Inspur servers
    
    Args:
      mac: MAC address of ILO interface in aa:bb:cc:dd:ee:ff format.
      interface: Interface number of link to use. An integer.
      ipmi_username: User name to use for authentication.
      ipmi_password: Password to use for authentication.
      ipmi_ip: IPv4 address to be configured.
      ipmi_netmask: Netmask to be configured.
      ipmi_gateway: Gateway to be configured.
    """
    ipv6_ip = '[%s%%%s]' % (get_ipv6_link_local_from_mac(mac), interface)
    uri = '/redfish/v1/Managers/BMC/EthernetInterfaces/%s' % mac
    ipv4_settings = {'IPv4DHCPEnable': 0, 'IPv4Addresses': ipv4, 'IPv4NetMask': netmask, 
       'IPv4Gateway': gateway}
    status, response = redfish_request(ipv6_ip, username, password, uri, 'POST', None, ipv4_settings)
    return


def redfish_request(ipv6_ip, username, password, uri, method, request_headers, request_body):
    """
    Method does rest call and handles the response.
    Args:
      ipv6_ip: IPv6 address of the server
      username:  BMC username
      password: BMC password
      uri: RESt URI
      method: RESt call method (GET/POST/PATCH)
      request_headers: Header for the request
      request_body: Request params
    Returns:
      tuple (status, response)
    """
    request_headers = request_headers or {}
    request_body = request_body or {}
    response_text = None
    try:
        session_url = 'https://%s/redfish/v1/SessionService/Sessions' % ipv6_ip
        session_auth = {'UserName': username, 'Password': password}
        with requests.session() as (s):
            s.verify = False
            s.headers = {'Content-Type': 'application/json'}
            r = s.post(session_url, data=json.dumps(session_auth))
            s.headers.update({'X-Auth-Token': r.json()['Id']})
            if method == 'GET':
                req = requests.Request(method, 'https://%s%s' % (ipv6_ip, uri))
            else:
                req = requests.Request(method, 'https://%s%s' % (ipv6_ip, uri), data=json.dumps(request_body))
            prepped = s.prepare_request(req)
            response = s.send(prepped)
            response_status = response.status_code
            response_text = response.text
    except Exception:
        default_logger.debug('API failed %s, params %s' % (uri, request_body))
        raise StandardError('Unable to connect to Inspur BMC, request failed')
    else:
        response_body = {}
        if response_text:
            try:
                response_body = json.loads(response_text)
            except Exception:
                raise StandardError('Unable to process the response')

        if response_status >= 200 and response_status < 300:
            return

    default_logger.debug('BMC response status %d' % response_status)
    raise StandardError('Request failed with status %d' % response_status)
    return