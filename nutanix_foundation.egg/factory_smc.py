# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/factory_smc.py
# Compiled at: 2019-02-15 12:42:10
import datetime, logging
from xml.sax import SAXParseException
from suds import WebFault
from suds.client import Client
import foundation_settings
from factory_netsuite import netsuite_lookup_order_info
from foundation import factory_mode
from foundation.factory_mode import get_station_id
DEFAULT_LOGGER = logging.getLogger(__name__)
logging.getLogger('suds').setLevel(logging.INFO)
BASE_API_URL = 'https://bizportal.supermicro.com:1446/Nutanix.asmx?WSDL'
settings = foundation_settings.get_settings()
if 'SMC_BASE_API' in settings:
    BASE_API_URL = settings['SMC_BASE_API']
MOCK_MAGIC = 'MOCK_SMC_LOOKUP_ORDER_INFO'
POST_MAGIC = 'POST UUT IMAGING RESULT SUCCESSFULLY'
SMCSO_MAGIC = '6U88'

def is_in_smc_factory():
    factory_config = factory_mode.get_config()
    if factory_config.get('factory_type') in [factory_mode.FACTORY_SMC,
     factory_mode.FACTORY_SMC_PROD]:
        return True
    return False


def is_in_smc_prod_factory():
    factory_config = factory_mode.get_config()
    if factory_config.get('factory_type') in [factory_mode.FACTORY_SMC_PROD]:
        return True
    return False


def get_creds(settings):
    username = settings.get('SMC_USERNAME')
    password = settings.get('SMC_PASSWORD')
    if not username or not password:
        raise StandardError('Please specify SMC_USERNAME and SMC_PASSWORD in foundation_settings.json')
    return (
     username, password)


def get_smc_client(api):
    try:
        return Client(api)
    except SAXParseException:
        DEFAULT_LOGGER.exception('Exception in creating SMC SOAP client')
        raise StandardError('Failed to connect to SMC API, please check network connection and retry')


def smc_lookup_order_info(block_id):
    """
    Lookup order information by Block ID at SMC.
    
    Returns:
      Order Information
    Raises:
      Exception when no order number found
    """
    logger = DEFAULT_LOGGER
    if settings.get(MOCK_MAGIC):
        logger.warn('MOCK_MAGIC %s set, using value from settings')
        return settings.get(MOCK_MAGIC)
    username, password = get_creds(settings)
    client = get_smc_client(BASE_API_URL)
    cred = client.factory.create('UserCredential')
    cred.UserName, cred.Password = username, password
    r_result = client.factory.create('RequestResult')
    r_result.ResultCode = 'Succeeded'
    try:
        so_reply = client.service.GetSMCSONumber(cred, block_id, r_result)
    except WebFault:
        logger.exception('Exception in GetSMCSONumber')
        raise StandardError("Failed to lookup SMCSO for block: %s, please check if it's a valid block_id" % block_id)
    else:
        if so_reply.TheRequestResult.ResultCode == 'Failed':
            error_msg = 'Failed to lookup SMCSO for block: %s' % block_id
            for error in so_reply.TheRequestResult.ErrorNodeList.ErrorNode:
                error_msg += ', ' + error.ErrorDescription

            raise StandardError(error_msg)
        smc_so = so_reply.GetSMCSONumberResult
        logger.info('SMCSO for block %s is %s', block_id, smc_so)
        if not smc_so.startswith(SMCSO_MAGIC):
            logger.debug('Skipping lookup for X-Node block %s/%s', block_id, smc_so)
            return []
        try:
            asm_reply = client.service.GetSMCSOAssemblyRecord(cred, smc_so, r_result)
        except WebFault:
            logger.exception('Exception in GetSMCSOAssemblyRecord')
            raise StandardError('Failed to lookup SMCSOAssemblyRecord for SO#: %s' % smc_so)

    if asm_reply.TheRequestResult.ResultCode == 'Failed':
        error_msg = 'Failed to lookup SMCSOAssemblyRecord for block: %s' % block_id
        for error in asm_reply.TheRequestResult.ErrorNodeList.ErrorNode:
            error_msg += ', ' + error.ErrorDescription

        raise StandardError(error_msg)
    block_items = filter(lambda item: item.SerialNumber == block_id, asm_reply.GetSMCSOAssemblyRecordResult.ProductLineItemList.ProductLineItem)
    if len(block_items) != 1:
        message = 'Mulitple ProductLineItem with same block_id SN found'
        logger.error(message + ': ' + str(block_items))
        raise StandardError(message)
    sales_order = asm_reply.GetSMCSOAssemblyRecordResult.CustomerPONumber
    line_number = block_items[0].CustomerPOLineNumber
    logger.info('Looking for line %s in order %s', line_number, sales_order)
    return netsuite_lookup_order_info(sales_order, line_number)


def post_uut_imaging_result(sn, model, cluster_id, nos_version, result, desc='N/A', logger=None):
    """
    Posting imaging result to SMC PROD API
    
    Args:
      sn: NodeSerialNumber, eg. OM17BS019071
      model: Product Part Number, eg. NX-3155G-G5
      cluster_id: Product Asset Tag, eg. 103868
      nos_version: eg. 5.1.3
      result: one of 'START' 'PASS' 'FAIL'
      desc: short description of failures, max 500 chars.
    
    Raises:
      StandardError: if failed to post the imaging result
    """
    logger = logger if logger else DEFAULT_LOGGER
    username, password = get_creds(settings)
    client = get_smc_client(BASE_API_URL)
    cred = client.factory.create('UserCredential')
    cred.UserName, cred.Password = username, password
    station_id = get_station_id()
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        post_reply = client.service.PostUUTImagingResult(cred, sn, model, cluster_id, nos_version, station_id, result, '', desc, timestamp)
    except WebFault:
        logger.exception('Exception in PostUUTImagingResult')
        raise StandardError('Failed to post imaging result for node: %s' % sn)

    if post_reply.PostUUTImagingResultResult != POST_MAGIC:
        raise StandardError('API responded with unexpected reply: %s' % post_reply)
    logger.info('Posted PostUUTImagingResult for node %s/%s', sn, model)


def main_lookup(block_id):
    import pprint
    print 'Is in SMC factory:', is_in_smc_factory()
    print 'Looking up order info for block_id %s at SMC' % block_id
    order_lines = smc_lookup_order_info(block_id)
    print 'Order Lines:'
    pprint.pprint(order_lines)


if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.DEBUG)
    func_map = {'lookup': main_lookup, 'post': post_uut_imaging_result}
    if len(sys.argv) <= 2 or sys.argv[1] not in func_map:
        print 'Usage: %s lookup <block_id>' % sys.argv[0]
        print 'Usage: %s post sn model cluster_id nos_version result desc' % sys.argv[0]
    else:
        func_map[sys.argv[1]](*sys.argv[2:])