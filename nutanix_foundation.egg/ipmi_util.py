# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/ipmi_util.py
# Compiled at: 2019-02-15 12:42:10
import logging, threading, time
from contextlib import contextmanager
import pyghmi.ipmi.command as cmd
from pyghmi.exceptions import PyghmiException, IpmiException
logger = logging.getLogger(__file__)
PYGHMI_LOCK = threading.Lock()
PYGHMI_TICK = 5

def get_session(ip, username, password, attempts=3):
    """
    Returns a pyghmi session.
    
    Args:
      ip: ip address (IPv4 or IPv6).
      username: username for the BMC.
      password: password for the BMC.
      attempts: number of attempts to get a session.
    
    Returns: cmd.Command object from pyghmi.
    
    Raises: StandardError if it fails.
    
    """
    for _ in range(attempts):
        try:
            with PYGHMI_LOCK:
                return cmd.Command(ip, username, password)
        except PyghmiException:
            logger.exception('Failed to get BMC session ')

    else:
        raise StandardError('Failed to get BMC session %s times' % attempts)


@contextmanager
def ipmi_context(node_config, attempts=3):
    """ ipmi_context with PYGHMI_LOCK """
    with PYGHMI_LOCK:
        for _ in range(attempts):
            try:
                ipmi = cmd.Command(node_config.ipmi_ip, node_config.ipmi_user, node_config.ipmi_password)
                ipmi.get_channel_info()
            except IpmiException as e:
                error_to_ignore = [
                 'timeout', 'no longer connected']
                args = e.args
                if not args[0] or any(map(lambda s: s in args[0], error_to_ignore)):
                    logger.debug('Ignoring exception %s and retry', e)
                    time.sleep(PYGHMI_TICK)
                    continue
                else:
                    raise
            else:
                yield ipmi
                ipmi.ipmi_session._mark_broken()
                raise StopIteration

        raise StandardError('Failed to get BMC session after %s attempts' % attempts)


def get_identity(node_config):
    """
    
    Args:
      node_config: same as ipmi_context
    
    Returns: Manufactured ID.
    
    Raises: StandardError if it fails.
    
    """
    system_fru = get_system_fru(node_config)
    mfg_id = system_fru['Manufacturer ID']
    return mfg_id


def get_system_fru(node_config):
    """
    
    Args:
      node_config: same as ipmi_context
    
    Returns: Fru.
    
    Raises: StandardError if it fails.
    
    """
    with ipmi_context(node_config) as (ipmi):
        return ipmi.get_inventory_of_component('System')


def get_component_fru(node_config, component):
    """
    
    Args:
      node_config: same as ipmi_context
      component: string name of the component eg. CPU1
    
    Returns: Fru of component
    
    Raises: StandardError if it fails.
    """
    with ipmi_context(node_config) as (ipmi):
        return ipmi.get_inventory_of_component(component)


def get_net_configuration(node_config):
    """
    
    Args:
      node_config: same as ipmi_context
    
    Returns: network config.
    
    Raises: StandardError if it fails.
    
    """
    with ipmi_context(node_config) as (ipmi):
        return ipmi.get_net_configuration()


if __name__ == '__main__':
    import sys, pprint
    if len(sys.argv) != 4:
        print 'usage: %s <IP> <USER> <PASSWORD>' % sys.argv[0]
    else:
        nc = lambda : None
        nc.ipmi_ip, nc.ipmi_user, nc.ipmi_password = sys.argv[1:]
        pprint.pprint(get_system_fru(nc))