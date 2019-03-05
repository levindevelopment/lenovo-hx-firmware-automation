# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/fc_rest_client.py
# Compiled at: 2019-02-15 12:42:10
import json, logging, socket, ssl, time, urllib2
from foundation import foundation_settings
DEFAULT_TIMEOUT = 60
DEFAULT_LOGGER = logging.getLogger(__file__)

class FCRestClient:
    """
    FoundationRestClient object
    """

    def __init__(self, fc_ip, api_key):
        self.fc_ip = fc_ip
        self.api_key = api_key
        fc_settings_dict = foundation_settings.get_settings().get('fc_settings', {})
        self.port = fc_settings_dict.get('foundation_central_port', 9440)
        self.protocol = 'https'
        if fc_settings_dict.get('use_http', False):
            self.protocol = 'http'

    def rest_call(self, resource='', method='', body=None, content_type='application/json', max_retries=5, retry_interval=5):
        url = ('{protocol}://{host}:{port}/api/fc/v1/{resource}').format(protocol=self.protocol, host=self.fc_ip, port=self.port, resource=resource)
        if body and content_type == 'application/json':
            body = json.dumps(body)
            DEFAULT_LOGGER.debug('Making %s request to %s with data %s' % (
             method, url, body))
        else:
            DEFAULT_LOGGER.debug('Making %s request to %s' % (method, url))
        request = urllib2.Request(url, data=body)
        request.add_header('x-api-key', '%s' % self.api_key)
        request.add_header('Content-Type', '%s' % content_type)
        request.get_method = lambda : method
        ctx = ssl.create_default_context()
        if self.protocol == 'https':
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        num_retries = 0
        while num_retries < max_retries:
            try:
                response = urllib2.urlopen(request, timeout=DEFAULT_TIMEOUT, context=ctx)
                result = response.read()
                code = response.code
                if code in (200, 202):
                    if result:
                        try:
                            result = json.loads(result)
                        except:
                            pass
                        finally:
                            DEFAULT_LOGGER.debug('API return code: %s and response: %s' % (
                             code, result))
                            return (
                             code, result)

                    else:
                        DEFAULT_LOGGER.debug('API return code: %s and response: %s' % (
                         code, result))
                        return (
                         code, result)
                else:
                    DEFAULT_LOGGER.error('Error making %s request to %s. Ret code: %s. Response: %s. Retrying after 5s...' % (
                     method, url, code, result))
                    time.sleep(retry_interval)
            except socket.timeout:
                DEFAULT_LOGGER.error('A timeout occurred while making %s request to %sResponse: %s. Retrying after 5s...' % (
                 method, url, result))
                code = 408
                result = None
                time.sleep(retry_interval)
            except Exception:
                DEFAULT_LOGGER.exception('Encountered exception while making %s request to %s' % (
                 method, url))
                code = None
                result = None
                time.sleep(retry_interval)
            else:
                num_retries += 1

        DEFAULT_LOGGER.debug('API return code: %s and response: %s' % (
         code, result))
        return (
         code, result)