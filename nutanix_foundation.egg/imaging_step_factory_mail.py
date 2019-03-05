# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/imaging_step_factory_mail.py
# Compiled at: 2019-02-15 12:42:10
import abc, logging, os, smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate
from foundation import factory_mode
from foundation import foundation_settings
from foundation import folder_central
from foundation import new_threading_model as ntm
from foundation.foundation_tools import get_current_foundation_version
from foundation.imaging_step import ImagingStepClusterAlwaysRunTask
DEFAULT_LOGGER = logging.getLogger(__name__)
IFCFG_CONF = '/etc/sysconfig/network-scripts/ifcfg-eth1'
SEND_MAIL_KEY = 'send_mail'
ONFAIL = 'onfail'
ALWAYS = 'always'

def get_vm_name(ifcfg_conf=IFCFG_CONF):
    factory_config = factory_mode.get_config()
    station_id_prefix = '%s-VM' % factory_config.get('factory_type', '?').upper()
    for line in open(ifcfg_conf):
        segs = line.split('=')
        if len(segs) != 2:
            continue
        else:
            k, v = segs
            if k == 'IPADDR':
                return station_id_prefix + v.strip()[-2:]
    else:
        return 'UNKNOWN'


class MailSender(object):

    @abc.abstractmethod
    def __init__(self, *args, **kwargs):
        """Init a sender object with `data`."""
        pass

    @abc.abstractmethod
    def send(self, from_, to, subject, text, attachments=None):
        """
        Send an email
        
        Args:
          attachments: [("att.txt", open("att.txt"))]
        """
        pass


class SMTPSender(MailSender):

    def __init__(self, server, username, password):
        smtp = smtplib.SMTP(server, 587)
        smtp.starttls()
        smtp.login(username, password)
        self.smtp = smtp

    def send(self, from_, to, subject, text, attachments=None):
        msg = MIMEMultipart()
        msg['From'] = from_
        if isinstance(to, basestring):
            msg['To'] = to
        else:
            msg['To'] = (',').join(to)
        msg['Date'] = formatdate(localtime=True)
        msg['Subject'] = subject
        msg.attach(MIMEText(text))
        for fn, fd in attachments or []:
            part = MIMEApplication(fd.read(), Name=os.path.basename(fn))
            part['Content-Disposition'] = 'attachment; filename="%s"' % os.path.basename(fn)
            msg.attach(part)

        self.smtp.sendmail(from_, to, msg.as_string())


class ImagingStepFactoryMail(ImagingStepClusterAlwaysRunTask):

    @classmethod
    def is_compatible(cls, config):
        config = factory_mode.get_config()
        settings = foundation_settings.get_settings()
        mode = config.get(SEND_MAIL_KEY, None)
        if mode in [ONFAIL, ALWAYS]:
            for key in ['mail_to', 'mail_from', 'mail_smtp', 'mail_password']:
                if not key in settings:
                    raise AssertionError('Missing key(%s) in settings' % key)

            return True
        return False
        return

    def get_progress_timing(self):
        return [
         ('Sending mail', 1)]

    def get_text(self, configs):
        text = 'Hi,\nImaging status is:\n\n'
        tasks = ntm.flat_tasks(self.config.graph)
        for config in configs:
            text += ('{} block {}, node {}:\n').format(config, getattr(config, 'block_id', '?').upper(), getattr(config, 'node_serial', '?').upper())
            if config._exceptions:
                for e in config._exceptions:
                    text += (' - FAIL: {}\n').format(e)

            else:
                node_tasks = filter(lambda task: task.config is config, tasks)
                if any(map(lambda task: task.get_state() in ('PENDING', 'NR'), node_tasks)):
                    text += ' - Incomplete\n'
                else:
                    text += ' - PASS\n'

        text += ('\n\n version: {}').format(get_current_foundation_version())
        return text

    def get_attachments(self):
        sess_id = self.config._session_id
        log_dir = folder_central.get_session_log_folder(sess_id)
        files = [
         (
          'persisted_config.json',
          open(folder_central.get_persisted_config_path()))]
        cluster_config = self.config
        nodes = cluster_config.cluster_members
        matching_list = [cluster_config.cluster_name] + [ node.cvm_ip for node in nodes ]
        in_list = lambda fn: any(map(lambda match: match in fn, matching_list))
        for root, _, fns in os.walk(log_dir):
            for fn in fns:
                if in_list(fn):
                    log_fn = os.path.join(root, fn)
                    files.append((os.path.basename(log_fn), open(log_fn)))

        return files

    def run(self):
        cluster_config = self.config
        nodes = cluster_config.cluster_members
        logger = self.logger
        factory_config = factory_mode.get_config()
        settings = foundation_settings.get_settings()
        mode = factory_config.get(SEND_MAIL_KEY)
        block_ids = set(map(lambda nc: nc.block_id, nodes))
        tasks = ntm.flat_tasks(cluster_config.graph)
        all_configs = [cluster_config] + nodes
        tasks = filter(lambda task: task.config in all_configs, tasks)
        if any(map(lambda task: task.get_state() in ('PENDING', 'NR'), tasks)):
            status = 'Incomplete'
        else:
            if any(map(lambda task: task.get_state() in ('FAILED', ), tasks)):
                status = 'Failed'
            else:
                status = 'Succeeded'
                if mode != ALWAYS:
                    logger.debug('No failed task, skip reporting')
                    return
        subject = ('[{}] Imaging {} on {} block(s): {}').format(get_vm_name(), status, len(block_ids), (',').join(block_ids))
        text = self.get_text(all_configs)
        attachments = self.get_attachments()
        fancy_mail_from = ('{} <{}>').format(get_vm_name(), settings['mail_from'])
        try:
            mailer = SMTPSender(settings['mail_smtp'], settings['mail_from'], settings['mail_password'])
            mailer.send(fancy_mail_from, settings['mail_to'], subject, text, attachments)
            logger.info('Email sent to %s', settings['mail_to'])
        except Exception as e:
            logger.exception('failed to send with %s: %s', SMTPSender, e)