# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_cluster_init.py
# Compiled at: 2019-02-15 12:42:10
import calendar, logging, json, os, time
from tempfile import NamedTemporaryFile
from threading import Thread
from cluster.genesis.cluster_manager import ClusterManager
from cluster.genesis.node_manager import NodeManager
from util.net.rpc import RpcError
from foundation import config_persistence
from foundation import config_validator as cv
from foundation import cvm_utilities as cvm_utils
from foundation import factory_mode
from foundation import folder_central
from foundation import foundation_tools as tools
from foundation import imaging_context
from foundation.imaging_step import ImagingStepClusterTask
from shared_functions import AUTOMATION_FRAMEWORK_KEY
from foundation.cluster_genesis_mixin import GenesisMixin
STATE_INITIALIZING_CLUSTER = 'Initializing cluster'
STATE_INITIALIZING_CLUSTER_DONE = 'Initializing cluster complete'
STATE_WAIT_FOR_CVM = 'Waiting for CVM to boot'
STATE_WAIT_FOR_CVM_DONE = 'CVM has booted'
STATE_UPLOAD_ISO = 'Copying hypervisor iso to all nodes for future use'
STATE_CLUSTER_CREATION_DONE = 'Cluster creation complete'
CHECK_INTERVAL_S = 30
CVM_READY_TIMEOUT = 300
NODE_DISCOVERY_BACKOFF_S = 60
DEFAULT_GENESIS_RPC_RETRY_TIMEOUT = 60
NODE_DISCOVERY_RETRIES = 10
CLUSTER_INIT_TIMEOUT_BASE = 600
CLUSTER_INIT_TIMEOUT_PER_NODE = 10
CLUSTER_INIT_TIMEOUT_PER_SED = 30
CLUSTER_INIT_BACKOFF_S = 30
CLUSTER_INIT_RETRIES = 2
CLUSTER_READY_BACKOFF_S = 20
CLUSTER_READY_RETRIES = 30
CVM_TIME_OFFSET_S = -120
UPLOAD_RETRY = 6
GENESIS_PORT = 2100
default_logger = logging.getLogger(__file__)

class ImagingStepClusterInit(ImagingStepClusterTask, GenesisMixin):

    def __init__(self, *args, **kwargs):
        super(ImagingStepClusterInit, self).__init__(*args, **kwargs)

    def get_progress_timing(self):
        return [
         (
          STATE_WAIT_FOR_CVM, 2),
         (
          STATE_INITIALIZING_CLUSTER, 3),
         (
          STATE_UPLOAD_ISO, 1)]

    def get_finished_message(self):
        return STATE_CLUSTER_CREATION_DONE

    def get_cluster_init_timeout(self):
        cluster_config = self.config
        cluster_members = cluster_config.cluster_members
        timeout = CLUSTER_INIT_TIMEOUT_BASE
        timeout += CLUSTER_INIT_TIMEOUT_PER_NODE * len(cluster_members)
        sed_max = max(map(lambda nc: getattr(nc, 'sed_count', 0), cluster_members))
        timeout += CLUSTER_INIT_TIMEOUT_PER_SED * sed_max
        return timeout

    def ssh(self, cvm_ip, command, config, throw_on_error=True, log_on_error=True, timeout=360, escape_cmd=False):
        return tools.ssh(config, cvm_ip, command, throw_on_error=throw_on_error, log_on_error=log_on_error, timeout=timeout, escape_cmd=escape_cmd)

    def _set_cvm_time(self, cvm_ip, foundation_time, cluster_config):
        logger = self.logger
        try:
            self.ssh(cvm_ip, ['sudo', 'date', '--utc', '"--set=%s"' % foundation_time], cluster_config, escape_cmd=True)
            return True
        except:
            logger.exception('Failed to set date on CVM %s', cvm_ip)
            return False

    def _set_cvm_timezone(self, node_config, timezone):
        logger = self.logger
        ret, err = tools.set_timezone(node_config, timezone)
        if not ret:
            logger.warn('Failed to set timezone on CVM %s, Details: %s', node_config.cvm_ip, err)
        return ret

    def _set_cvm_times(self, cluster_config):
        """
        Synchronizes CVM time to Foundation VM time in preparation of
        cluster init.
        """
        logger = self.logger
        cluster_members = cluster_config.cluster_members
        cvm_ip_list = list(map(lambda m: m.cvm_ip, cluster_members))
        foundation_time = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(calendar.timegm(time.gmtime()) + CVM_TIME_OFFSET_S))
        logger.info('Setting CVM time to %s UTC' % foundation_time)
        work = [ (cvm_ip, foundation_time, cluster_config) for cvm_ip in cvm_ip_list
               ]
        results = tools.tmap(self._set_cvm_time, work)
        if not all(results):
            logger.warn('Setting CVM time Failed on some nodes')
        if getattr(cluster_config, 'timezone', None):
            timezone = cluster_config.timezone
            logger.info('Setting CVM timezone to %s ' % timezone)
            work = map(lambda x: (x, timezone), cluster_members)
            results = tools.tmap(self._set_cvm_timezone, work)
            if not all(results):
                logger.warn('Setting CVM time Failed on some nodes')
        return

    def set_and_verify_hypervisor_ntp_dns_server(self):
        """
        Sets and verifies the hypervisor NTP or DNS servers. If Foundation fails
        to set the ntp/dns servers, a warning is logged and user will have to set
        it manually.
        
        Note: On HyperV host, genesis RPC fails to set the NTP servers. User
          has to set it manually.
        """
        genesis_set_func = None
        genesis_get_func = None
        servers_list = None
        cluster_config = self.config
        cvm_ip_list = list(map(lambda m: m.cvm_ip, cluster_config.cluster_members))
        servers_type = None
        thread_responses = {}

        def setup_ntp_dns_servers(cvm_ip, index):
            self.logger.info('Setting hypervisor %s servers (%s) for node %s' % (
             servers_type, servers_list, cvm_ip))
            result = self._call_genesis_method(cvm_ip, genesis_set_func, (servers_list,))
            thread_responses[cvm_ip] = result
            if result and not isinstance(result, RpcError):
                servers_present = self._call_genesis_method(cvm_ip, genesis_get_func)
                if isinstance(servers_present, RpcError) or not set(servers_list).issubset(servers_present):
                    self.logger.warning('Foundation could not set the hypervisor %s servers for node with CVM ip %s. It needs to be set manually after cluster creation' % (
                     servers_type, cvm_ip))
            else:
                if isinstance(result, RpcError):
                    self.logger.warning('Setting hypervisor %s servers failed for node with cvm ip %s with %s' % (
                     servers_type, cvm_ip, result))
                else:
                    self.logger.warning('Setting hypervisor %s servers failed for node with cvm_ip %s. Please check genesis logs for more details' % (
                     servers_type, cvm_ip))

        def setup_threaded_config():
            threads = []
            thread_responses.clear()
            for i, cvm_ip in enumerate(cvm_ip_list):
                threads.append(Thread(target=setup_ntp_dns_servers, args=(
                 cvm_ip, i + 1)))

            map(lambda x: x.start(), threads)
            map(lambda x: x.join(), threads)
            for cvm_ip in cvm_ip_list:
                if cvm_ip not in thread_responses.keys():
                    self.logger.warning('Failed to set hypervisor %s servers for %s' % (
                     servers_type, cvm_ip))

        if getattr(cluster_config, 'hypervisor_nameserver', None):
            servers_list = cluster_config.hypervisor_nameserver.split(',')
            genesis_set_func = NodeManager.set_hypervisor_dns_servers
            genesis_get_func = NodeManager.hypervisor_dns_nameservers
            servers_type = 'DNS'
            setup_threaded_config()
        return

    def load_hardware_attributes(self, node_config, cluster_config):
        cmd = [
         'cat', '/etc/nutanix/hardware_config.json']
        stdout, stderr, rc = self.ssh(node_config.cvm_ip, cmd, cluster_config, throw_on_error=False, timeout=10)
        if rc:
            raise StandardError('Failed to read hardware_config.json on node with CVM IP %s. Check cluster logs for more details' % node_config.cvm_ip)
        try:
            hc = json.loads(stdout)
            node_config.hardware_config = hc
        except ValueError as ve:
            raise StandardError('Failed to parse hardware_config.json for node with CVM IP %s. Check cluster logs for more details' % node_config.cvm_ip)

    def check_and_maybe_set_rack_ids(self):
        logger = self.logger
        cluster_members = self.config.cluster_members
        aux_file = '/etc/nutanix/auxiliary_config.json'
        with NamedTemporaryFile() as (fd):
            tmp_file = fd.name

        def write_rack_id(node, rack_id):
            cmd = [
             'mkdir', '-p', os.path.dirname(tmp_file)]
            tools.ssh(node, node.cvm_ip, cmd, throw_on_error=True, escape_cmd=True)
            cmd = ['echo', '\'{"rack_id" : "%s"}\'' % rack_id, '>', tmp_file]
            tools.ssh(node, node.cvm_ip, cmd, throw_on_error=True, escape_cmd=True)
            cmd = ['sudo', 'mv', tmp_file, aux_file]
            tools.ssh(node, node.cvm_ip, cmd, throw_on_error=True)

        for node in cluster_members:
            rack_id = getattr(node, 'rack_id', None)
            cmd = ['cat', aux_file]
            out, err, ret = tools.ssh(node, node.cvm_ip, cmd, throw_on_error=False)
            if ret:
                if rack_id is None:
                    logger.warning('rack_id missing for %s' % node.cvm_ip)
                    return False
                write_rack_id(node, rack_id)
            else:
                out = json.loads(out)
                if rack_id != out.get('rack_id', None):
                    write_rack_id(node, rack_id)

        return True

    def copy_eos_metadata_to_cvm(self):
        """
        Copies the eos_metadata ,if available to the CVM
        """
        eos_metadata = getattr(self.config, 'eos_metadata', {})
        eos_metadata_path = folder_central.get_cvm_eos_metadata_path()
        with NamedTemporaryFile() as (fd):
            tmp_file = fd.name
        with open(tmp_file, 'w') as (fd):
            fd.write(json.dumps(eos_metadata, indent=2))
        for node in self.config.cluster_members:
            if not node.image_now:
                cmd = [
                 'mkdir', '-p', os.path.dirname(tmp_file)]
                _, _, ret = self.ssh(node.cvm_ip, cmd, self.config, throw_on_error=False)
                if ret:
                    self.logger.warning('Failed to create temp directory %s in CVM %s, hence skipping Eos metadata creation' % (
                     os.path.dirname(tmp_file), node.cvm_ip))
                    continue
                _, _, ret = tools.scp(self.config, node.cvm_ip, tmp_file, tmp_file, throw_on_error=False)
                if ret:
                    self.logger.warning('Failed to send Eos metadata to CVM %s, henceskipping Eos metadata creation' % node.cvm_ip)
                    continue
                cmd = [
                 'sudo', 'mv', tmp_file, eos_metadata_path]
                _, _, ret = self.ssh(node.cvm_ip, cmd, self.config, throw_on_error=False)
                if ret:
                    self.logger.warning('Failed to save Eos metadata on CVM %s' % node.cvm_ip)

        if os.path.exists(tmp_file):
            os.remove(tmp_file)

    def _copy_genesis_log(self, node_configs):
        genesis_log_path = '/home/nutanix/data/logs/genesis.out.*'
        logger = self.logger
        for node in node_configs:
            log_path = folder_central.get_session_log_folder(node._session_id)
            if imaging_context.get_context() == imaging_context.FIELD_IPMI:
                out, err, ret = tools.ssh(node, node.cvm_ip, ['ls', genesis_log_path], throw_on_error=False)
                if ret:
                    logger.error("Couldn't find genesis logs in CVM %s. The stdout is %s\n and stderr is\n%s" % (
                     node.cvm_ip, out, err))
                else:
                    out = out.split()
                    for genesis_log in out:
                        out, err, ret = tools.ssh(node, node.cvm_ip, ['cat', genesis_log], throw_on_error=False)
                        if ret:
                            logger.error("Failed to read genesis log '%s' from CVM %s. The stdout is %s\nand stderr is\n%s" % (
                             genesis_log, node.cvm_ip, out, err))
                        else:
                            log_name = '%s_%s' % (genesis_log.split('/')[-1], node.cvm_ip)
                            file_path = os.path.join(log_path, log_name)
                            with open(file_path, 'w') as (fd):
                                fd.write(out)

    def _create_cluster(self):
        cluster_config = self.config
        cluster_members = cluster_config.cluster_members
        logger = self.logger
        node_config = cluster_members[0]
        cvm_ip_list = list(map(lambda m: m.cvm_ip, cluster_members))
        self.set_status(STATE_INITIALIZING_CLUSTER)
        logger.info('Creating Cluster %s with the following nodes:' % cluster_config.cluster_name)
        for node in cluster_members:
            logger.info('CVM(%s) BLOCK_ID(%s) NODE_SN(%s)' % (
             node.cvm_ip,
             getattr(node, 'block_id', None),
             getattr(node, 'node_serial', None)))

        logger.info('Setting CVM time')
        self._set_cvm_times(cluster_config)
        try:
            logger.info('Waiting for node discovery to settle')
            for i in range(NODE_DISCOVERY_RETRIES):
                logger.info('Discovery attempt: %d' % (i + 1))
                results = self._call_genesis_method(node_config.cvm_ip, NodeManager.discover_unconfigured_nodes, ('IPv4', ), timeout_secs=self._rpc_timeout)
                if not isinstance(results, RpcError):
                    logger.info('Found %d nodes' % len(results))
                    not_found = []
                    for ip in cvm_ip_list:
                        for result in results:
                            if ip == result['ip']:
                                break
                        else:
                            not_found.append(ip)

                    if not len(not_found):
                        break
                    logger.info('Nodes not yet discovered: %s' % (',').join(not_found))
                else:
                    logger.warn('Got RpcError %s. Retrying' % results)
                logger.info('Restarting Genesis')
                restart_response = self._restart_genesis(cvm_ip_list, wait=True)
                if not restart_response:
                    raise StandardError('Genesis did not come up after restart')
            else:
                raise StandardError('Node discovery failed to settle for cluster %s' % cluster_config.cluster_name)

            logger.info('Node discovery settled')
            self.set_and_verify_hypervisor_ntp_dns_server()
            logger.info('Creating cluster')
            cvm_ip_arg = (',').join(cvm_ip_list)
            nos_version = tools.get_nos_version_from_cvm(node_config.cvm_ip, cluster_config)
            external_ip = []
            redundancy_factor = []
            if cluster_config.cluster_external_ip and nos_version >= [4.0]:
                external_ip = ['--cluster_external_ip=%s' % cluster_config.cluster_external_ip]
            if cluster_config.redundancy_factor and nos_version >= [4.0]:
                redundancy_factor = ['--redundancy_factor=%d' % cluster_config.redundancy_factor]
            if nos_version > [3, 5, 2, 1]:
                skip_discovery = '--skip_discovery'
            else:
                skip_discovery = '-f'
            ntp_args = []
            dns_args = []
            ntp_dns_via_create_cmd = False
            results = self._call_genesis_method(node_config.cvm_ip, ClusterManager.are_dns_ntp_flags_supported, timeout_secs=self._rpc_timeout)
            if not isinstance(results, RpcError):
                if results:
                    logger.info('Cluster supports NTP and DNS server flags with init')
                    ntp_dns_via_create_cmd = True
                else:
                    logger.info('Cluster does not accept NTP and DNS server flags. Will attempt to set NTP and DNS servers after creation')
            else:
                logger.info('Got an RpcError detecting NTP and DNS server flag support. Will attempt to set NTP and DNS servers after cluster creation')
            if getattr(cluster_config, 'cvm_ntp_servers', None) and ntp_dns_via_create_cmd:
                ntp_args = [
                 '--ntp_servers=%s' % cluster_config.cvm_ntp_servers]
            if getattr(cluster_config, 'cvm_dns_servers', None) and ntp_dns_via_create_cmd:
                dns_args = [
                 '--dns_servers=%s' % cluster_config.cvm_dns_servers]
            nw_seg_args = []
            enable_ns = getattr(cluster_config, 'enable_ns', False)
            if enable_ns:
                nw_seg_args = ['--backplane_subnet=%s' % cluster_config.backplane_subnet,
                 '--backplane_netmask=%s' % cluster_config.backplane_netmask,
                 '--backplane_vlan=%s' % cluster_config.backplane_vlan,
                 '--backplane_network']
            else:
                logger.info('Network Segmentation will not be enabled')
            hc = getattr(node_config, 'hardware_config', None)
            if not hc:
                self.load_hardware_attributes(node_config, cluster_config)
            single_node_cluster = getattr(cluster_config, 'single_node_cluster', False)
            if single_node_cluster:
                if enable_ns:
                    error = "Network Segmentation can't be enabled on a single node cluster"
                    logger.error(error)
                    raise StandardError(error)
                redundancy_factor = ['--redundancy_factor=%d' % cluster_config.redundancy_factor]
                hw_attr = node_config.hardware_config['node'].get('hardware_attributes')
                if hw_attr and hw_attr.get('backup_target_node', False):
                    redundancy_factor = [
                     '--redundancy_factor=2']
            cluster_name = cluster_config.cluster_name
            if hasattr(cluster_config, 'cluster_name_unicode'):
                cluster_name = cluster_config.cluster_name_unicode.decode('utf8')
            hw_attr = node_config.hardware_config['node'].get('hardware_attributes')
            two_node_cluster_allowed = hw_attr.get('two_node_cluster', False) or hasattr(node_config, AUTOMATION_FRAMEWORK_KEY)
            if two_node_cluster_allowed and len(cluster_members) == 2:
                cluster_create_subcommand = [
                 'cluster/bin/cluster', '--cluster_name="%s"' % cluster_name, '--cluster_function_list="two_node_cluster"'] + external_ip + redundancy_factor + ntp_args + dns_args + [
                 '--svm_ips=%s' % cvm_ip_arg, skip_discovery]
            else:
                cluster_create_subcommand = ['cluster/bin/cluster', '--cluster_name="%s"' % cluster_name] + external_ip + redundancy_factor + ntp_args + dns_args + [
                 '--svm_ips=%s' % cvm_ip_arg, skip_discovery]
            if single_node_cluster:
                cmd = 'echo -n Y |'
                cluster_create_subcommand.insert(0, cmd)
            if hasattr(node_config, AUTOMATION_FRAMEWORK_KEY):
                logger.info('Skipping One and Two node checks since AUTOMATION_FRAMEWORK_KEY is set')
            else:
                if not single_node_cluster and not hw_attr.get('backup_target_node', False):
                    if len(cluster_members) == 2:
                        for node in cluster_members:
                            hc = getattr(node, 'hardware_config', None)
                            if not hc:
                                self.load_hardware_attributes(node, cluster_config)
                            hw_attr = node.hardware_config['node'].get('hardware_attributes')
                            if not hw_attr.get('two_node_cluster', False):
                                raise StandardError("This platform doesn't support two-node clusters.")

                    elif len(cluster_members) == 1:
                        for node in cluster_members:
                            hc = getattr(node, 'hardware_config', None)
                            if not hc:
                                self.load_hardware_attributes(node, cluster_config)
                            hw_attr = node.hardware_config['node'].get('hardware_attributes')
                            if not hw_attr.get('one_node_cluster', False):
                                raise StandardError("This platform doesn't support one-node clusters.")

            if self.check_and_maybe_set_rack_ids():
                logger.info('Rack-awareness would be enabled')
                cluster_create_subcommand.append('--rack_aware=true')
            else:
                logger.info('Rack-awareness will not be enabled')
            init_timeout = self.get_cluster_init_timeout()
            for i in range(CLUSTER_INIT_RETRIES):
                if i > 0:
                    cluster_create_subcommand.append('--debug')
                if enable_ns:
                    ns_ipconfig = cluster_create_subcommand + nw_seg_args + ['ipconfig']
                    logger.debug('Configuring backplane by executing %s on %s' % (
                     ns_ipconfig, node_config.cvm_ip))
                    _, _, ret = self.ssh(node_config.cvm_ip, ns_ipconfig, cluster_config, throw_on_error=False, escape_cmd=True, log_on_error=True)
                    if ret:
                        logger.warn('cluster ipconfig for network segmentation failed')
                        time.sleep(CLUSTER_INIT_BACKOFF_S)
                        continue
                    else:
                        logger.info('cluster ipconfig succeeded')
                cluster_create_command = cluster_create_subcommand + nw_seg_args + [
                 'create']
                nohup_cluster_create_subcommand = [
                 'nohup'] + cluster_create_command + [
                 '>', '/tmp/cluster_create.stdout', '2>',
                 '/tmp/cluster_create.stderr', '&', 'echo $!', '>',
                 '/tmp/cluster_create.pid']
                logger.debug("Executing '%s' on '%s'" % (
                 (' ').join(nohup_cluster_create_subcommand), node_config.cvm_ip))
                stdout, stderr, retval = self.ssh(node_config.cvm_ip, nohup_cluster_create_subcommand, cluster_config, throw_on_error=False, escape_cmd=True)
                if retval == 0:
                    max_tries = int((init_timeout + CVM_READY_TIMEOUT) / CHECK_INTERVAL_S)
                    all_up = True
                    for j in range(max_tries):
                        all_up = True
                        logger.info('[%s/%s] Checking whether all cluster services are up', j, max_tries)
                        results = self._call_genesis_method(node_config.cvm_ip, ClusterManager.status, timeout_secs=self._rpc_timeout)
                        if not isinstance(results, RpcError) and results['svms']:
                            service_up, service_all = (0, 0)
                            default_logger.debug('Service status: %s' % results)
                            for svm in results['svms']:
                                for service in results['svms'][svm]['services']:
                                    service_all += 1
                                    if not service['pids']:
                                        all_up = False
                                        name = service['service']
                                        last_error = service['last_error']
                                        if last_error:
                                            logger.error("service %s failed to start on %s, with last_error as '%s'" % (
                                             name, svm, last_error))
                                    else:
                                        service_up += 1

                            if all_up:
                                logger.info('All %s cluster services are up', service_all)
                                break
                            else:
                                logger.debug('[%s/%s] services are up, will check again', service_up, service_all or '?')
                        else:
                            default_logger.debug("Couldn't get status for services from genesis: %s" % results)
                        time.sleep(CHECK_INTERVAL_S)

                    if all_up:
                        break
                    else:
                        logger.error('Failed waiting for all services to come up')
                        _, _, _ = self.ssh(node_config.cvm_ip, [
                         'kill', '-9', '`cat /tmp/cluster_create.pid`'], cluster_config, throw_on_error=False, escape_cmd=True)
                if i + 1 == CLUSTER_INIT_RETRIES:
                    self._copy_genesis_log(cluster_members)
                logger.warn('Cluster init attempt %d failed. ' % i)
                stdout, stderr, retval = self.ssh(node_config.cvm_ip, [
                 'cluster/bin/cluster', 'stop'], cluster_config, throw_on_error=False, log_on_error=False)
                logger.warn('Cluster stop returned:\nReturn code: %d\n\nstdout :\n%s\n\nstderr :\n%s\n\n' % (
                 retval, stdout, stderr))
                ret = self._destroy_cluster(node_config.cvm_ip)
                logger.warn('Cluster destroy returned %s', ret)
                logger.info('Restarting genesis.')
                restart_response = self._restart_genesis(cvm_ip_list, wait=True)
                if not restart_response:
                    raise StandardError('Genesis did not come up after restart')
            else:
                raise StandardError('Cluster init failed multiple times on cluster %s' % cluster_config.cluster_name)

            for i in range(CLUSTER_READY_RETRIES):
                stdout, stderr, retval = self.ssh(node_config.cvm_ip, [
                 'bash', '-lc', '"ncli host list"'], cluster_config, throw_on_error=False, escape_cmd=True, timeout=30)
                if node_config.cvm_ip in stdout:
                    break
                logger.info('Waiting for cluster to be ready...')
                time.sleep(CLUSTER_READY_BACKOFF_S)
            else:
                raise StandardError("Cluster %s didn't come up" % cluster_config.cluster_name)

            logger.info('Cluster created')
            if not ntp_dns_via_create_cmd:
                cvm_ip = cvm_ip_list[0]
                cvm_ntp_server_list = []
                cvm_dns_server_list = []
                if getattr(cluster_config, 'cvm_ntp_servers', None):
                    cvm_ntp_server_list.extend(cluster_config.cvm_ntp_servers.split(','))
                if getattr(cluster_config, 'cvm_dns_servers', None):
                    cvm_dns_server_list.extend(cluster_config.cvm_dns_servers.split(','))
                result = self._call_genesis_method(cvm_ip, ClusterManager.set_dns_ntp_server_list, (
                 cvm_ntp_server_list, cvm_dns_server_list))
                if not isinstance(result, RpcError):
                    logger.info('Configured NTP and DNS server for CVM')
                else:
                    logger.warn('Failed to configure NTP and DNS server, please do it manually')
                logger.info('Cluster setup complete')
            if factory_mode.factory_mode():
                logger.info('Not persist cluster init result in factory')
            else:
                config_persistence.post_cluster_init_result(node_config.cvm_ip, True)
        except:
            logger.exception('Failed in creating cluster')
            self._copy_genesis_log(cluster_members)
            config_persistence.post_cluster_init_result(node_config.cvm_ip, False)
            raise

        return

    def detect_hyperv_marker_for_dell(self, node_config, timeout=10):
        """
        On DELL nodes, hyperv firstboot success marker is present in
        <drive>:\\dell\x0cirstboot\\markers.
        This function searches for hyperv frstboot_success marker in all drives.
        
        Args:
          node_config: NodeConfig of the node on which marker has to be searched.
          timeout: Time out for executing each ssh command. Default value is
              10 seconds.
        
        Returns:
          0 if hyperv firstboot_success marker is found in any drive.
          1 otherwise.
        """
        marker_files = [
         'dell\\/firstboot\\/markers\\/firstboot_success']
        host = cvm_utils.HypervHost(node_config)
        drive = host.find_drive(marker_files, timeout=timeout)
        if drive:
            return 0
        return 1

    def _ready_for_cluster_creation(self, cluster_members):
        """
        Ensure the CVM is ready for cluster creation by making a genesis RPC.
        """
        waiting = []
        configured = []
        unconfigured = []
        for node in cluster_members:
            response = self._call_genesis_method(node.cvm_ip, NodeManager.configured, timeout_secs=self._rpc_timeout)
            if isinstance(response, RpcError):
                waiting.append(node)
            elif response:
                configured.append(node)
            else:
                unconfigured.append(node)

        return (
         waiting, configured, unconfigured)

    def _wait_on_cluster(self, cluster_config, timeout):
        """
        This method waits for all cluster members to be up.
        Args:
          cluster_config : An instance of ClusterConfig
          timeout        : The total timeout in seconds to wait for all nodes
        Raises:
          StandardError if not all CVMs answer to a genesis RPC within the timeout
        """
        timeout = time.time() + timeout
        cluster_members = cluster_config.cluster_members
        logger = self.logger
        logger.info('Checking whether the CVMs are ready for cluster creation')
        while time.time() < timeout:
            try:
                logger.info('[%0.0f/%0.0fs] attempt', time.time() - timeout + CVM_READY_TIMEOUT, CVM_READY_TIMEOUT)
                waiting, configured, unconfigured = self._ready_for_cluster_creation(cluster_members)
            except Exception as err:
                if 'Failed to create ssh tunnel' in str(err):
                    logger.debug('An exception was raised while trying to check if             cluster was up. Will retry: %s', err)
                    time.sleep(CHECK_INTERVAL_S)
                    continue
                else:
                    logger.exception('An uncaught exception occured while trying to check if cluster was up')
                    raise
            else:
                if len(configured):
                    raise StandardError('CVMs %s are already part of a cluster. Please remove or deconfigure them and retry cluster creation.' % (', ').join([ node.cvm_ip for node in configured ]))
                if len(waiting):
                    logger.info('Still waiting for CVMs %s to report ready' % (', ').join([ node.cvm_ip for node in waiting ]))
                    time.sleep(CHECK_INTERVAL_S)
                    continue
                logger.info('All CVMs up and ready for cluster creation')
                break
        else:
            raise StandardError('Timed out waiting for CVMs to come up')

    def copy_files(self, node_config):
        logger = node_config.get_logger()
        whitelist_path = folder_central.get_iso_whitelist()
        if os.path.exists(whitelist_path):
            logger.info('Uploading iso whitelist')
            tools.update_whitelist_on_cvm(node_config, whitelist_path)
        installer_iso = node_config.hypervisor_iso.copy()
        if getattr(node_config, 'kvm_from_nos', False):
            if 'kvm' in installer_iso.keys():
                installer_iso['kvm'] = ''
        else:
            if getattr(node_config, 'kvm_rpm', False):
                installer_iso['kvm'] = node_config.kvm_rpm
        for installer_type, installer_path in installer_iso.items():
            if os.path.exists(installer_path):
                if installer_type == 'kvm':
                    file_type = 'tarball'
                else:
                    file_type = 'iso'
                logger.info('Uploading %s %s(%s) to %s:%s' % (
                 file_type, installer_type, installer_path,
                 node_config.cvm_ip, installer_path))
                tools.upload(installer_type=installer_type, local_file=installer_path, remote_file=None, target_config=node_config)

        return

    def upload_hypervisor_iso(self):
        """
        Uploads hypervisor iso files to the target nodes which were imaged as part
        of cluster creation. In case of AHV, the original RPM tarball is uploaded.
        """
        self.set_status(STATE_UPLOAD_ISO)
        cluster_members = self.config.cluster_members
        if not filter(lambda nc: nc.image_now, cluster_members):
            self.logger.info('Skipping hypervisor upload since no nodes were imaged')
            return
        foundation_ip = tools.get_my_ip(cluster_members[0].cvm_ip)
        for node_config in cluster_members:
            if node_config.cvm_ip != foundation_ip:
                self.logger.info('Uploading hypervisor iso to %s' % node_config.cvm_ip)
                self.copy_files(node_config)

    def run(self):
        cluster_config = self.config
        cluster_name = cluster_config.cluster_name
        logger = self.logger
        if not cluster_config.cluster_init_now:
            return
        cluster_members = cluster_config.cluster_members
        node_config = cluster_members[0]
        if self._use_tunnel:
            logger.warn("The Foundation IP is not in the CVM's subnet. Since the CVM by default does not allow RPCs from outside of its subnet, foundation will create ssh tunnel for cluster creation")
        self.set_status(STATE_WAIT_FOR_CVM)
        if getattr(self.config, 'eos_metadata', None):
            self.copy_eos_metadata_to_cvm()
        try:
            self._wait_on_cluster(cluster_config, CVM_READY_TIMEOUT)
        except StandardError as err:
            self._copy_genesis_log(cluster_members)
            raise StandardError('Failed while waiting for cvms to come up before cluster creation.Error: %s' % err)
        else:
            if len(cluster_config.cluster_members) > 1:
                for node in cluster_config.cluster_members:
                    hc = getattr(node, 'hardware_config', None)
                    if not hc:
                        cmd = ['cat', '/etc/nutanix/hardware_config.json']
                        stdout, stderr, rc = self.ssh(node.cvm_ip, cmd, cluster_config, throw_on_error=False, timeout=10)
                        if rc:
                            raise StandardError('Failed to read hardware_config.json on node with CVM IP %s. Check cluster logs for more details' % node.cvm_ip)
                        try:
                            hc = json.loads(stdout)
                            node.hardware_config = hc
                        except ValueError as ve:
                            logger.exception('Exception in loading contents of hardware_config.json as json for CVM IP %s' % node.cvm_ip)
                            raise StandardError('Failed to parse hardware_config.json for node with CVM IP %s. Check cluster logs for more details' % node.cvm_ip)

            if not cv.validate_xpress_cluster(cluster_config):
                msg = 'Cluster %s does not satisfy Xpress platform requirements. Check cluster log for details' % cluster_name
                logger.error(msg)
                raise StandardError(msg)
            if not cv.is_single_license_class_cluster(cluster_config):
                msg = 'Cluster %s intermixes software only and appliance nodes. Check cluster log for details' % cluster_name
                logger.error(msg)
                raise StandardError(msg)
            if factory_mode.factory_mode():
                logger.debug('Sleeping for 60s before cluster create')
                time.sleep(60)
            self._create_cluster()
            try:
                self.upload_hypervisor_iso()
            except:
                logger.exception('Error while uploading hypervisor binaries')

        return