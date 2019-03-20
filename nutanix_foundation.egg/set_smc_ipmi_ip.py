# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/set_smc_ipmi_ip.py
# Compiled at: 2019-02-15 12:42:10
import cookielib, errno, urllib, urllib2, xml.etree.ElementTree
from foundation_tools import get_ipv6_link_local_from_mac
SMC_TIMEOUT_S = 5

class AddHeaderHandler(urllib2.BaseHandler):
    """
    Add custom headers for every out going requests.
    
    Args:
      headers: key value pairs for custom headers.
    """
    handler_order = urllib2.BaseHandler.handler_order - 1

    def __init__(self, headers=None):
        self.headers = headers if headers else {}

    def http_request(self, request):
        for k, v in self.headers.iteritems():
            request.add_header(k, v)

        return request


def set_ipmi_ip(mac, interface, ipmi_username, ipmi_password, ipmi_ip, ipmi_netmask, ipmi_gateway, dhcp=False, scheme='https'):
    """
    mac: MAC address of IPMI interface in aa:bb:cc:dd:ee:ff format.
    interface: Interface number of link to use. An integer.
    ipmi_username: User name to use for authentication.
    ipmi_password: Password to use for authentication.
    ipmi_ip: IPv4 address to configure IPMI to.
    ipmi_netmask: Netmask to configure IPMI to.
    ipmi_gateway: Gateway to configure IPMI to.
    """
    ipv6_ip = '%s%%25%s' % (get_ipv6_link_local_from_mac(mac), interface)
    ipv6_ip = str(ipv6_ip)
    host_ipv4 = ipmi_ip
    get_url = lambda uri: '%s://[%s]%s' % (scheme, ipv6_ip, uri)
    cj = cookielib.CookieJar()
    ahh = AddHeaderHandler({'host': host_ipv4})
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj), ahh)
    request = urllib2.Request(get_url('/'))
    request.get_method = lambda : 'HEAD'
    try:
        response = opener.open(request, timeout=SMC_TIMEOUT_S)
        if response.geturl().startswith('https'):
            scheme = 'https'
    except urllib2.URLError as e:
        if e.args[0].errno == errno.ECONNREFUSED:
            scheme = 'http'
            get_url = lambda uri: '%s://[%s]%s' % (scheme, ipv6_ip, uri)
            request = urllib2.Request(get_url('/'))
            response = opener.open(request)
        else:
            raise
    else:
        args = urllib.urlencode({'name': ipmi_username, 'pwd': ipmi_password})
        try:
            response = opener.open(get_url('/cgi/login.cgi'), args)
        except urllib2.HTTPError as e:
            raise StandardError('IPMI authentication request failed with HTTP error %d' % e.code)
        else:
            if cj.__len__() == 0:
                raise StandardError('IPMI authentication failed. No cookies returned')
            args = 'op=CONFIG_INFO.XML&CONFIG_INFO.XML=(0,0)'
            try:
                response = opener.open(get_url('/cgi/ipmi.cgi'), args)
            except urllib2.HTTPError as e:
                raise StandardError('Network configuration get request failed with HTTP error %d' % e.code)

        root = xml.etree.ElementTree.ElementTree(file=response)
        config = root.find('./CONFIG_INFO')
        lan = config.find('LAN')
        bmcip = lan.attrib['BMC_IP']
        bmcmask = lan.attrib['BMC_NETMASK']
        gatewayip = lan.attrib['GATEWAY_IP']
        en_vlan = 'off'
        vlanID = str(int(lan.attrib['VLAN_ID'], 16))
        rmcpport = str(int(lan.attrib['RMCP_PORT'], 16))
        service = config.find('SERVICE')
        dns = config.find('DNS')
        if dns is not None:
            dns_server = config.find('DNS').attrib['DNS_SERVER']
        else:
            if service is not None:
                dns_server = service.attrib['DNS_ADDR']
            else:
                dns_server = '0.0.0.0'
        bmcipv6_dns_server = ''
        bmcipv6_addr = ''
        bmcipv6_opt = 'add'
        bmcipv6_autoconf = 'on'
        dhcpv6_mode = 'stateless'
        lan_if = config.find('LAN_IF')
        lan_interface = lan_if.attrib['INTERFACE']
        link_info = config.find('LINK_INFO')
        link_conf = link_info.get('MII_LINK_CONF')
        hostname_elem = config.find('HOSTNAME')
        hostname = hostname_elem.attrib['NAME']
        bmcip = ipmi_ip
        bmcmask = ipmi_netmask
        gatewayip = ipmi_gateway
        args = 'bmcip=%s' % bmcip
        args += '&bmcmask=%s' % bmcmask
        args += '&gatewayip=%s' % gatewayip
        args += '&en_dhcp=%s' % ('on' if dhcp else 'off')
        args += '&en_vlan=%s' % en_vlan
        args += '&vlanID=%s' % vlanID
        args += '&rmcpport=%s' % rmcpport
        args += '&dns_server=%s' % dns_server
        args += '&bmcipv6_dns_server=%s' % bmcipv6_dns_server
        args += '&bmcipv6_addr=%s' % bmcipv6_addr
        args += '&bmcipv6_opt=%s' % bmcipv6_opt
        args += '&bmcipv6_autoconf=%s' % bmcipv6_autoconf
        args += '&dhcpv6_mode=%s' % dhcpv6_mode
        args += '&lan_interface=%s' % lan_interface
        if link_conf:
            args += '&link_conf=%s' % link_conf
        args += '&hostname=%s' % hostname
        try:
            response = opener.open(get_url('/cgi/config_lan.cgi'), args)
        except urllib2.HTTPError as e:
            if e.code == 404:
                response = opener.open(get_url('/cgi/op.cgi'), str('op=config_lan&' + args))
            else:
                raise StandardError('Network configuration set request failed with HTTP error %d' % e.code)

    if 'ok' not in response.read():
        raise StandardError("Network configuration request did not return 'ok'")
    return


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 4:
        print 'usage: %s MAC IP NETMASK GATEWAY' % sys.argv[0]
        print 'eg.  : %s 0C:C4:7A:3C:CB:E6 10.1.87.241 255.255.252.0 10.1.84.1' % sys.argv[0]
    set_ipmi_ip(sys.argv[1], 2, 'ADMIN', 'ADMIN', sys.argv[2], sys.argv[3], sys.argv[4])