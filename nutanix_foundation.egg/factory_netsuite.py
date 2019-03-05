# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/factory_netsuite.py
# Compiled at: 2019-02-15 12:42:10
import json, logging, warnings, requests
from requests.exceptions import HTTPError
import foundation_settings
DEFAULT_LOGGER = logging.getLogger(__name__)
BASE_API_URL = 'https://connect.boomi.com/ws/rest/factorydata/factorydata/'
settings = foundation_settings.get_settings()
if 'NS_BASE_API' in settings:
    warnings.warn('NS_BASE_API is deprecated, use BOOMI_BASE_API', DeprecationWarning)
if 'BOOMI_BASE_API' in settings:
    BASE_API_URL = settings['BOOMI_BASE_API']
MOCK_MAGIC = 'MOCK_NETSUITE_LOOKUP_ORDER_INFO'

def netsuite_lookup_order_lines(nssearchresult, line_number):
    """
    NetSuite Order lines:
      Here's an example of an SO with 3x NX- top-level lines and each NX- line's
      associated C- lines:
    
        Line Number Part Number
        1           NX-
        2           C-
        3           C-
        4           C-
        5           NX-
        6           C-
        7           C-
        8           C-
        9           C-
        10          NX-
        11          C-
        12          C-
        13          C-
        14          C-
        15          C-
    
      For line_number=1, returns line(item) [1, 2, 3, 4],
      for line_number=5, returns line [5 - 9]
      for line_number=10, returns line[10 - 15].
      for line_number not in range [1-15], raise exception
    """
    is_lineid_found = False
    for item in nssearchresult:
        if 'No Data found' in item:
            raise StandardError('NetSuite returned %s' % item)
        item['lineid'] = int(item['lineid'])
        if item['lineid'] == line_number:
            is_lineid_found = True

    if not is_lineid_found:
        raise StandardError('Failed to locate lineid %s in %s' % (line_number, nssearchresult))
    order_lines = []
    sorted_results = sorted(nssearchresult, key=lambda item: item['lineid'])
    for item in sorted_results:
        if item['lineid'] == line_number:
            order_lines.append(item)
        elif not order_lines:
            pass
        elif order_lines and item.get('itemname', '').startswith('C-'):
            order_lines.append(item)
        else:
            break

    return order_lines


def netsuite_lookup_order_info(sales_order, line_number):
    """
    Lookup order information by sales_order and line_number from NetSuite.
    
    Returns:
      List of Order Information
    Raises:
      Exception when no order found
    
    """
    logger = DEFAULT_LOGGER
    if settings.get(MOCK_MAGIC):
        logger.warn('MOCK_MAGIC %s set, using value from settings')
        return settings.get(MOCK_MAGIC)
    username = settings.get('BOOMI_USERNAME')
    password = settings.get('BOOMI_PASSWORD')
    line_number = int(line_number)
    if not username or not password:
        raise StandardError('Please specify BOOMI_USERNAME and BOOMI_PASSWORD in foundation_settings.json')
    headers = {'Content-Type': 'application/json'}
    query = {'orderid': sales_order}
    logger.debug('lookup order: %s', query)
    response = requests.post(BASE_API_URL, data=json.dumps(query), headers=headers, auth=(
     username, password), verify=False)
    try:
        response.raise_for_status()
        result = response.json()
    except (HTTPError, ValueError):
        logger.exception('Failed to lookup order %s', sales_order)
        raise StandardError('Failed to lookup order %s, please check credentials and retry' % sales_order)

    nssearchresult = result.get('nssearchresult', [])
    return netsuite_lookup_order_lines(nssearchresult, line_number)


def main(sales_order, line_number):
    import pprint
    print 'Looking for order %s, line %s' % (sales_order, line_number)
    order_lines = netsuite_lookup_order_info(sales_order, line_number)
    print 'Order Lines:'
    pprint.pprint(order_lines)


if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) != 3:
        print 'Usage: %s <sales_order> <line_number>' % sys.argv[0]
    else:
        sales_order, line_number = sys.argv[1:]
        main(sales_order, line_number)