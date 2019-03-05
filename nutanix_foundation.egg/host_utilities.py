# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/host_utilities.py
# Compiled at: 2019-02-15 12:42:10
import logging, os, foundation_tools as tools
from util.net.remote_shell import BasicRemoteShell
SCP_RETRIES = 3
DEFAULT_LOGGER = logging.getLogger(__file__)

def ssh_on_hyperv_host(command, host_ip, logger=DEFAULT_LOGGER, log_on_error=True, raise_on_error=False, timeout_secs=10):
    """
    Execute ssh commands on target HyperV host. Cluster must be
    configured and NutanixHostAgent must be running on participating
    nodes/hosts for this function to work.
    
    Args:
      command: Command to be executed. Must be string.
      host_ip: IP address of the target HyperV host.
      logger: Logging object to be used for logging.
      log_on_error: Logs error if True, not logged otherwise.
      raise_on_error: If True, exception is reaise in case of errors while
          executing ssh command. If False, exception is not raised.
      timeout_secs: Timeout in seconds for ssh command execution.
    
    Raises:
      AssertionError if command is not string.
      StandardError if ssh command fails  and raise_on_error is True.
    
    Returns:
      Output of ssh command, error message if any, return status of ssh command.
    """
    assert isinstance(command, basestring), 'Command must be string'
    assert isinstance(host_ip, basestring), 'host_ip must be string'
    try:
        client = BasicRemoteShell(host_ip)
        ret, out, err = client.execute(script=command, timeout_secs=timeout_secs)
    except Exception as e:
        err_msg = 'Connection to %s failed: %s' % (host_ip, str(e))
        if log_on_error:
            logger.error(err_msg)
        if raise_on_error:
            raise StandardError(err_msg)
        return ('', err_msg, 1)

    if ret:
        message = 'Failed to execute command (%s) on HyperV host with error:\n%s' % (
         command, err)
        if log_on_error:
            logger.error(message)
        if raise_on_error:
            raise StandardError(message)
    return (
     out, err, ret)


def scp_to_hyperv_host(host_ip, src_target_map, logger=DEFAULT_LOGGER, raise_on_error=False, timeout_secs=10):
    """
    Utility function to scp files to target HyperV host. Cluster must be
    configured and NutanixHostAgent must be running on participating nodes/hosts
    for this function to work.
    
    Args:
      node_config: NodeConfig object for the target node.
      src_target_map: Dictionary which maps source files to destination files.
          Example:
          {
             "path_to_source_file1" : "Target_path_on_hyperv",
             "path_to_source_file2" : "Target_path_on_hyperv",
             ...
          }
          Target path can be directory or absolute path of the destination file.
      raise_on_error: If True, raises exception in case scp fail for any file.
      timeout_secs: Time out for ssh command execution on target host.
    
    Raises:
      AssertionError if src_target_map is not a dictionary.
      StandardError if scp fails for any file and raise_on_error is True.
    
    Returns:
      True if scp is successful for all files.
      False if scp fails and raise_on_error is False.
    """
    assert isinstance(src_target_map, dict), 'src_target_map must be dictionary'
    assert isinstance(host_ip, basestring), 'host_ip must be string'
    out, err, ret = ssh_on_hyperv_host(command='ls C:\\/', host_ip=host_ip, logger=logger, log_on_error=True, raise_on_error=False, timeout_secs=timeout_secs)
    if ret:
        message = 'Foundation is unable to talk to target HyperV host Verify that NutanixHostAgent is running on target host and cluster is configured.'
        logger.error(message)
        if raise_on_error:
            raise StandardError(message)
        return False
    result = True
    client = BasicRemoteShell(host_ip)
    for src, target in src_target_map.iteritems():
        logger.info('Copying source file %s to path %s in target HyperV host' % (
         src, target))
        sha256sum_src = tools.get_sha256sum(src)
        for _ in range(SCP_RETRIES):
            ret, err = client.upload_file(src_path=src, dst_path=target, force=True)
            if ret:
                logger.debug('Failed to scp file %s to path %s in target HyperV host with error:\n%s\nRetrying' % (
                 src, target, err))
                continue
            cmd = 'Test-Path -PathType Container %s' % target
            ret, out, err = client.execute(script=cmd, timeout_secs=timeout_secs)
            if ret:
                logger.debug('Failed to determine target file type for %s with error:\n%s\nRetrying' % (
                 target, err))
                continue
            if 'True' in out:
                scp_target = '%s\\/%s' % (target, os.path.basename(src))
            else:
                scp_target = target
            cmd = 'Get-FileHash -Path %s -Algorithm SHA256  | Format-List -Property Hash' % scp_target
            ret, out, err = client.execute(script=cmd, timeout_secs=timeout_secs)
            if ret:
                logger.debug('Failed to calculate the sha256sum of %s in target host with error:\n%s\nRetrying' % (
                 err, scp_target))
                continue
            sha256sum_target = out.split(':')[1].strip().lower()
            if sha256sum_src == sha256sum_target:
                break
            else:
                logger.debug('sha256sum of %s in target changed during scp transfer.  Retrying' % scp_target)
        else:
            result = False
            message = 'Failed to scp source file %s to %s in target HyperV host in %s attempts' % (
             src, target, SCP_RETRIES)
            logger.error(message)
            if raise_on_error:
                raise StandardError(message)
            break

    return result