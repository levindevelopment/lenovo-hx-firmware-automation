# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/tinyrpc.py
# Compiled at: 2019-02-15 12:42:10
from sshtunnel import SSHTunnelForwarder
from util.net.rpc import RpcError
from util.net.http_rpc import HttpJsonRpcClient
GENESIS_PORT = 2100
GENESIS_JSONRPC_URL = '/jsonrpc'
GENESIS_RPC_TIMEOUT_SECS = 6

def call_genesis_method(cvm_ip, method, args=tuple(), _port=GENESIS_PORT, timeout_secs=None, valid=lambda x: not isinstance(x, RpcError), raise_=False, **kwargs):
    """
    A copy of genesis_utils.call_genesis_method
    
    NOTE: 1. This function only takes one node at a time,
          write your own loop or use tmap.
          2. When calling from outside of the subnet, use the
          call_genesis_method_over_tunnel, it will setup ssh tunnel before call
          the RPC.
    """
    if kwargs is None:
        kwargs = {}
    timeout_secs = timeout_secs or GENESIS_RPC_TIMEOUT_SECS
    genesis_proxy = HttpJsonRpcClient(host=cvm_ip, port=_port, url=GENESIS_JSONRPC_URL, timeout=timeout_secs)
    service = genesis_proxy.import_service(method.im_class)
    ret = getattr(service, method.im_func.func_name)(*args, **kwargs)
    if not valid(ret):
        if not raise_:
            return ret
        if ret.exception:
            raise ret.exception
        else:
            raise StandardError(ret)
    return ret


def call_genesis_method_over_tunnel(cvm_ip, *args, **kwargs):
    """
    Call genesis method over ssh tunnel
    """
    localhost = 'localhost'
    try:
        with SSHTunnelForwarder(cvm_ip, ssh_username='nutanix', ssh_password='nutanix/4u', remote_bind_address=(
         localhost, GENESIS_PORT), local_bind_address=(
         localhost, 0)) as (tunnel):
            port = tunnel.local_bind_port
            return call_genesis_method(localhost, _port=port, *args, **kwargs)
    except TypeError:
        raise
    except Exception as e:
        return RpcError('Error in creating ssh tunnel', e)


def test(cvm_ip):
    from cluster.genesis.node_manager import NodeManager
    print call_genesis_method(cvm_ip, NodeManager.discover_unconfigured_nodes, ('IPv4', ), timeout_secs=10)
    print call_genesis_method_over_tunnel(cvm_ip, NodeManager.discover_unconfigured_nodes, ('IPv4', ), timeout_secs=10)


if __name__ == '__main__':
    import sys
    if len(sys.argv) == 2:
        test(sys.argv[1])
    else:
        print 'usage: %s <cvm_ip>' % sys.argv[0]