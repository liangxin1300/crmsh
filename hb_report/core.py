import os
import sys
import argparse
import datetime
import atexit
import shutil
import time
import glob
import tarfile
import re
import json
from multiprocessing import Process

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from hb_report import const, utils, collect
from crmsh import utils as crmutils
from crmsh import corosync
from crmsh.config import report, path, core


def is_collector():
    '''
    collector is for collecting logs and data
    '''
    return len(sys.argv) > 2 and sys.argv[1] == "__slave"


def include_me(node_list):
    return utils.me() in node_list


def get_nodes(context):
    '''
    find nodes to collect
    '''
    # not set by using -n
    if not context.nodes:
        nodes = crmutils.list_cluster_nodes()
        if not nodes:
            utils.log_fatal("Could not figure out a list of nodes; is this a cluster node?")
        context.nodes = nodes
    if context.single and include_me(context.nodes):
        context.nodes = [utils.me()]

    utils.log_debug1("Nodes to collect: {}".format(context.nodes))


class Context(object):

    def __init__(self):
        self.__dict__['from_time'] = utils.parse_to_timestamp(report.from_time)
        self.__dict__['no_compress'] = not report.compress
        self.__dict__['speed_up'] = report.speed_up
        self.__dict__['extra_logs'] = report.collect_extra_logs.split()
        self.__dict__['rm_exist_dest'] = report.remove_exist_dest
        self.__dict__['single'] = report.single_node

        self.__dict__['to_time'] = utils.parse_to_timestamp(utils.now())
        self.__dict__['sensitive_regex'] = "passw.*"
        self.__dict__['regex'] = "CRIT: ERROR: error: warning: crit:"
        self.__dict__['ssh_askpw_nodes'] = []

    def __str__(self):
        return json.dumps(self.__dict__)

    def __setattr__(self, name, value):
        if name in ["from_time", "to_time"]:
            value = utils.parse_to_timestamp(value)
        elif isinstance(value, list) and utils.is_2dlist(value):
            value = utils.zip_nested(value)
        super().__setattr__(name, value)

    def __setitem__(self, key, value):
        self.__dict__[key] = value

    def dumps(self):
        return json.dumps(self.__dict__, indent=2)

    def create_tempfile(self):
        self.temp_file = utils.make_temp_file()
        utils.log_debug2("Create tempfile \"{}\"".format(self.temp_file))

    def add_tempfile(self, filename):
        with open(self.temp_file, 'a') as f:
            f.write(filename + '\n')
        utils.log_debug2("Add tempfile \"{}\" to \"{}\"".format(filename, self.temp_file))

    def drop_tempfile(self):
        with open(self.temp_file, 'r') as f:
            for line in f.read().split('\n'):
                if os.path.isdir(line):
                    shutil.rmtree(line)
                if os.path.isfile(line):
                    os.remove(line)
        os.remove(self.temp_file)
        utils.log_debug2("Remove tempfile \"{}\"".format(self.temp_file))


def print_extra_help():
    print('''
  . the multifile output is stored in a tarball {dest}.tar.bz2
  . the time specification is as in either Date::Parse or
    Date::Manip, whatever you have installed; Date::Parse is
    preferred
  . we try to figure where is the logfile; if we can't, please
    clue us in ('-l')
  . we collect only one logfile and /var/log/messages; if you
    have more than one logfile, then use '-E' option to supply
    as many as you want ('-M' empties the list)

  Examples

    report -f 2pm report_1
    report -f "2007/9/5 12:30" -t "2007/9/5 14:00" report_2
    report -f 1:00 -t 3:00 -l /var/log/cluster/ha-debug report_3
    report -f "09sep07 2:00" -u hbadmin report_4
    report -f 18:00 -p "usern.*" -p "admin.*" report_5
    report -f cts:133 ctstest_133

  . WARNING . WARNING . WARNING . WARNING . WARNING . WARNING .

    We won't sanitize the CIB and the peinputs files, because
    that would make them useless when trying to reproduce the
    PE behaviour. You may still choose to obliterate sensitive
    information if you use the -s and -p options, but in that
    case the support may be lacking as well. The logs and the
    crm_mon, ccm_tool, and crm_verify output are *not* sanitized.

    Additional system logs (/var/log/messages) are collected in
    order to have a more complete report. If you don't want that
    specify -M.

    IT IS YOUR RESPONSIBILITY TO PROTECT THE DATA FROM EXPOSURE!''')



def parse_argument(context):
    parser = argparse.ArgumentParser(description='{} - create report for HA cluster'.format(context.name),
                                     add_help=False)
    parser.add_argument('-h', '--help', dest='help', action='store_true',
                        help='show this help message and exit')
    parser.add_argument('-f', dest='from_time', metavar='time',
                        help='time to start from')
    parser.add_argument('-t', dest='to_time', metavar='time',
                        help='time to finish at (default: now)')
    parser.add_argument('-d', dest='no_compress', action='store_true',
                        help="don't compress, but leave result in a directory")
    parser.add_argument('-n', dest='nodes', metavar='node', action="append",
                        help='''node names for this cluster; this option is additive
                                (use -n a -n b)
                                if you run report on the loghost or use autojoin,
                                it is highly recommended to set this option''')
    parser.add_argument('-u', dest='ssh_user', metavar='user',
                        help='ssh user to access other nodes'),
    parser.add_argument('-X', dest='ssh_options', metavar='ssh-options', action='append', default=[],
                        help='extra ssh(1) options'),
    parser.add_argument('-l', dest='ha_log', metavar='file',
                        help='log file')
    parser.add_argument('-E', dest='extra_logs', metavar='file', action='append',
                        help='''extra logs to collect; this option is additive
                                (dflt: /var/log/messages)''')
    parser.add_argument('-s', dest='sanitize', action='store_true',
                        help='sanitize the PE and CIB files')
    parser.add_argument('-p', dest='sensitive_regex', metavar='patt', action='append',
                        help='''regular expression to match variables containing sensitive data;
                                this option is additive (dflt: "passw.*")''')
    parser.add_argument('-L', dest='regex', metavar='patt', action='append',
                        help='''regular expression to match in log files for analysis;
                                this option is additive (dflt: CRIT: ERROR:)''')
    parser.add_argument('-e', dest='editor', metavar='prog',
                        help='your favourite editor')
    parser.add_argument('-Q', dest='speed_up', action='store_true',
                        help="don't run resource intensive operations (speed up)")
    parser.add_argument('-M', dest='no_extra', action='store_true',
                        help="don't collect extra logs (/var/log/messages)")
    parser.add_argument('-D', dest='no_editor', action='store_true',
                        help="don't invoke editor to write description")
    parser.add_argument('-Z', dest='rm_exist_dest', action='store_true',
                        help='if destination directories exist, remove them instead of exiting')
    parser.add_argument('-S', dest='single', action='store_true',
                        help='''single node operation; don't try to start report
                                collectors on other nodes''')
    parser.add_argument('-v', dest='debug', action='count', default=0,
                        help='increase verbosity')
    parser.add_argument('-V', dest='version', action='store_true',
                        help='print version')
    parser.add_argument('dest', nargs='?',
                        help='report name (may include path where to store the report)')

    args = parser.parse_args()
    if args.help:
        parser.print_help()
        print_extra_help()
        sys.exit(0)

    for arg in vars(args):
        value = getattr(args, arg)
        if value or not hasattr(context, arg):
            setattr(context, arg, value)

    process_some_arguments(context)


def process_some_arguments(context):
    if context.to_time <= context.from_time:
        utils.log_fatal("Start time must be before finish time")

    if not context.dest:
        context.dest = '{}-{}'.format(context.name, utils.now("%a-%d-%b-%Y"))

    context.from_time_str = utils.dt_to_str(utils.ts_to_dt(context.from_time))
    context.to_time_str = utils.dt_to_str(utils.ts_to_dt(context.to_time))

    # log provided by the user?
    if context.ha_log and \
       not os.path.isfile(context.ha_log) and \
       not is_collector():
        utils.log_warning("\"{}\" not found; we will try to find log ourselves".format(context.ha_log))


def load_from_config(context):
    '''
    load context attributes from crmsh.config and corosync.conf
    '''
    context.ocf_root = getattr(path, 'ocf_root', None)
    if not context.ocf_root or not os.path.isdir(context.ocf_root):
        utils.log_fatal("Cannot find ocf root directory!")
    ocf_lib_file = "{}/lib/heartbeat/ocf-directories".format(context.ocf_root)
    if not os.path.exists(ocf_lib_file):
        utils.log_fatal("File {} not exist".format(ocf_lib_file))
    with open(ocf_lib_file) as f:
        data = f.read()
    for line in data.split('\n'):
        res = re.search(r'HA_VARLIB:=(.*)}', line)
        if res:
            context.ha_varlib = res.group(1)

    context.pe_dir = getattr(path, 'pe_state_dir', None)
    if not context.pe_dir or not os.path.isdir(context.pe_dir):
        utils.log_fatal("Cannot find PE files directory!")

    context.cib_dir = getattr(path, 'crm_config', None)
    if not context.cib_dir or not os.path.isdir(context.cib_dir):
        utils.log_fatal("Cannot find CIB files directory!")

    context.pcmk_lib = os.path.dirname(context.cib_dir)
    utils.log_debug2("Setting PCMK_LIB to %s" % context.pcmk_lib)
    context.cores_dirs = os.path.join(context.pcmk_lib, "cores")
    if os.path.isdir(const.COROSYNC_LIB):
        context.cores_dirs += " {}".format(const.COROSYNC_LIB)

    # from corosync.conf
    if not os.path.exists(corosync.conf()):
        return
    context.to_logfile = crmutils.get_boolean(corosync.get_value('logging.to_logfile'))
    context.logfile = corosync.get_value('logging.logfile')
    context.log_facility = corosync.get_value('logging.syslog_facility')
    if not context.log_facility:
        context.log_facility = "daemon"


def is_our_log(context, logf):
    '''
    check if the log contains a piece of our segment
    '''
    data = utils.data_from_all_types_file(logf)
    if not data:
        return 0 # don't include this log

    # reset this var to check every file's format
    if hasattr(context, 'stamp_type'):
        delattr(context, "stamp_type")
    first_time = utils.find_first_ts(utils.head(10, data))
    last_time = utils.find_first_ts(utils.tail(10, data))
    from_time = context.from_time
    to_time = context.to_time

    if (not first_time) or (not last_time):
        if os.stat(logf).st_size > 0:
            return 4 # irregular log, not empty
        return 0  # skip (empty log?)
    if from_time > last_time:
        # we shouldn't get here anyway if the logs are in order
        return 2  # we're past good logs; exit
    if from_time >= first_time:
        return 3  # this is the last good log
    if to_time >= first_time:
        return 1  # include this log
    else:
        return 0  # don't include this log


def arch_logs(context, logf):
    '''
    go through archived logs (timewise backwards) and see if there
    are lines belonging to us
    (we rely on untouched log files, i.e. that modify time
    hasn't been changed)
    '''
    ret = []
    # look for rotation files such as: ha-log-20090308 or
    # ha-log-20090308.gz (.bz2) or ha-log.0, etc
    files = [logf] + glob.glob(logf+"*[0-9z]")
    for f in sorted(files, key=os.path.getctime):
        res = is_our_log(context, f)
        if res == 0: # noop, continue
            continue
        elif res == 1: # include log and continue
            ret.append(f)
            utils.log_debug2("Found log %s" % f)
        elif res == 2: # don't go through older logs!
            break
        elif res == 3: # include log and continue
            ret.append(f)
            utils.log_debug2("Found log %s" % f)
            break
    return ret


def print_logseg(context, logf):
    data = utils.data_from_all_types_file(logf)
    if data is None:
        return
    
    from_time = context.from_time
    to_time = context.to_time

    if not from_time or from_time == 0:
        from_line = 1
    else:
        from_line = utils.findln_by_time(logf, from_time)
    if from_line is None:
        utils.log_warning("Couldn't find line for time {}; corrupt log file?".format(from_time))
        return

    if to_time != 0:
        to_line = findln_by_time(logf, to_time)
        if to_line is None:
            utils.log_warning("Couldn't find line for time {}; corrupt log file?".format(to_time))
            return

    utils.log_debug2("Including segment [{}-{}] from {}".format(from_line, to_line, logf))  
    return utils.filter_lines(logf, from_line, to_line)    


def find_log(context):
    #journalctl -u pacemaker -u corosync -u sbd
    if context.extra_logs:
        for f in context.extra_logs.split():
            if os.path.isfile(f) and f not in const.PCMK_LOG.split():
                return f

        f = os.path.join(context.work_dir, const.JOURNAL_F)
        if os.path.isfile(f):
            return f

        for f in const.PCMK_LOG.split():
            if os.path.isfile(f):
                return f
    else:
        utils.log_debug2("Will try with {}".format(context.logfile))
        return context.logfile


def dump_logset(context, logf, outf):
    '''
    find log/set of logs which are interesting for us
    '''
    logf_set = []
    logf_set = arch_logs(context, logf)
    if len(logf_set) == 0:
        return

    num_logs = len(logf_set)
    oldest = logf_set[-1]
    newest = logf_set[0]
    mid_logfiles = logf_set[1:-1]
    out_string = ""

    # the first logfile: from $from_time to $to_time (or end)
    # logfiles in the middle: all
    # the last logfile: from beginning to $to_time (or end)
    if num_logs == 1:
        out_string += print_logseg(newest, context)
    else:
        out_string += print_logseg(oldest, from_time, 0)
        for f in mid_logfiles:
            out_string += print_log(f)
            log_debug2("Including complete %s logfile" % f)
        out_string += print_logseg(newest, 0, to_time)

    crmutils.str2file(out_string, outf)


def valid_dest(context):
    dest_dir = utils.dirname(context.dest)
    if not os.path.isdir(dest_dir):
        utils.log_fatal('{} is invalid directory name'.format(dest_dir))
    context.dest_dir = dest_dir

    dest_file = os.path.basename(context.dest)
    if not crmutils.is_filename_sane(dest_file):
        utils.log_fatal('{} is invalid file name'.format(dest_file))

    if context.no_compress and os.path.isdir(context.dest):
        if context.rm_exist_dest:
            shutil.rmtree(context.dest)
        else:
            utils.log_fatal('Destination directory {} exists, please cleanup or use -Z option'.format(context.dest))

    context.dest = dest_file


def setup_workdir(context):
    '''
    setup work directory that we can put all logs into it
    '''
    valid_dest(context)
    tmpdir = utils.make_temp_dir()
    context.add_tempfile(tmpdir)
    if not is_collector():
        context.work_dir = os.path.join(tmpdir, os.path.basename(context.dest))
    else:
        context.work_dir = os.path.join(tmpdir,
                                        os.path.basename(context.dest),
                                        utils.me())
        context.dest_path = "{}/{}".format(context.dest, utils.me())
    utils._mkdir(context.work_dir)
    utils.log_debug2('Setup work directory in {}'.format(context.work_dir))


def collect_journal(context, cmd, outf):
    if not utils.which("journalctl"):
        utils.log_warning("Command journalctl not found")
        return

    utils.log_debug2("Running command: {}".format(' '.join(cmd.split())))
    rc, out, err = crmutils.get_stdout_stderr(cmd)
    if rc == 0 and out:
        utils.log_debug1("Dump {} into {}".format(os.path.basename(outf), context.dest_path))
        crmutils.str2file(out, outf)
    if rc != 0 and err:
        utils.log_error(err)


def collect_journal_ha(context):
    '''
    Using journalctl collect ha related log as ha-log.txt
    '''
    outf = os.path.join(context.work_dir, const.HALOG_F)
    cmd = 'journalctl -u pacemaker -u corosync -u sbd \
            --since "{}" --until "{}" \
            -o short-iso --no-pager | tail -n +2'.\
            format(context.from_time_str, context.to_time_str)
    collect_journal(context, cmd, outf)


def collect_journal_general(context):
    '''
    Using journalctl collect system log as journal.log
    '''
    outf = os.path.join(context.work_dir, const.JOURNAL_F)
    cmd = 'journalctl --since "{}" --until "{}" \
            -o short-iso --no-pager | tail -n +2'.\
            format(context.from_time_str, context.to_time_str)
    collect_journal(context, cmd, outf)


def collect_other_logs_and_info(context):
    process_list = []
    for cf in const.COLLECT_FUNCTIONS:
        p = Process(target=getattr(collect, cf), args=(context,))
        p.start()
        process_list.append(p)
    for p in process_list:
        p.join()

    #if not context.speed_up:
        #TODO
        #sanitize(context)

    for l in context.extra_logs:
        if not os.path.isfile(l):
            continue


def test_ssh_conn(addr):
    cmd = r"ssh %s -T -o Batchmode=yes %s true" % (const.SSH_OPTS, addr)
    rc, _, _= crmutils.get_stdout_stderr(cmd)
    return rc == 0


def find_ssh_user(context):
    ssh_user = "__undef"

    if not context.ssh_user:
        try_user_list = "__default " + const.TRY_SSH
    else:
        try_user_list = context.ssh_user

    for n in context.nodes:
        rc = 1
        if n == utils.me():
            continue
        for u in try_user_list.split():
            if u != '__default':
                ssh_s = '@'.join((u, n))
            else:
                ssh_s = n

            if test_ssh_conn(ssh_s):
                utils.log_debug2("SSH {} OK".format(ssh_s))
                ssh_user = u
                try_user_list = u
                rc = 0
                break
            else:
                utils.log_debug2("ssh {} failed".format(ssh_s))
        if rc == 1:
            context.ssh_askpw_nodes.append(n)

    if context.ssh_askpw_nodes:
        utils.log_warning("Passwordless ssh to node(s) {} does not work".format(context.ssh_askpw_nodes))
    if ssh_user == "__undef":
        return
    if ssh_user != "__default":
        context.ssh_user = ssh_user


def say_ssh_user(context):
    if context.ssh_user:
        return context.ssh_user
    else:
        return "your user"


def ssh_issue(context):
    if not context.single:
        find_ssh_user(context)

    ssh_opts = const.SSH_OPTS
    for opt in context.ssh_options:
        if opt not in const.SSH_OPTS:
            ssh_opts += " -o {}".format(opt)
    if context.ssh_user:
        ssh_opts += " -o User={}".format(context.ssh_user)
    context.ssh_options = ssh_opts

    context.sudo = ""
    if (not context.ssh_user and os.getuid() != 0) or \
        context.ssh_user and context.ssh_user != "root":
        utils.log_debug2("ssh user other than root, use sudo")
        context.sudo = "sudo -u root"

    context.local_sudo = ""
    if os.getuid() != 0:
        utils.log_debug2("Local user other than root, use sudo")
        context.local_sudo = "sudo -u root"


def collect_for_nodes(context):
    for node in context.nodes:
        if node in context.ssh_askpw_nodes:
            utils.log_info("Please provide password for {} at {}".format(say_ssh_user(context), node))
            utils.log_info("Note that collecting data will take a while.")
            start_slave_collector(node, context)
        else:
            p = Process(target=start_slave_collector, args=(node, context))
            p.start()
            p.join()


def start_slave_collector(node, context):
    cmd_slave = r"{} __slave '{}'".format(context.name, context)
    if node == utils.me():
        cmd = r'{} {}'.format(context.local_sudo, cmd_slave)
    else:
        cmd = r'ssh {} {} "{} {}"'.format(context.ssh_options, node, context.sudo, cmd_slave.replace('"', '\\"'))

    _, out = crmutils.get_stdout(cmd)
    out_data_list = out.split('\n')
    compress_data = ""
    for data in out_data_list:
        if data.startswith(const.COMPRESS_DATA_FLAG):
            compress_data = data.lstrip(const.COMPRESS_DATA_FLAG)
        else:
            print(data)

    cmd = r"(cd {} && tar xf -)".format(context.work_dir)
    crmutils.get_stdout_stderr(cmd, input_s=eval(compress_data))


def load_context(context):
    '''
    Load context attributes from master process
    '''
    if len(sys.argv) < 3:
        utils.log_fatal("For collector, the number of arguments must > 3")
    for key, value in json.loads(sys.argv[2]).items():
        context[key] = value


def sanitize(context):
    '''
    replace sensitive info with '****'
    '''
    conf = os.path.join(context.work_dir, os.path.basename(const.CONF))
    if os.path.isfile(conf):
        sanitize_one(context, conf)

    cib_f = os.path.join(context.work_dir, const.CIB_F)
    file_list = [cib_f] + glob.glob(os.path.join(context.work_dir, "pengine", "*"))
    for f in [item for item in file_list if os.path.isfile(item)]:
        if context.sanitize:
            sanitize_one(context, f)
        else:
            if utils.is_sensitive_file(f):
                utils.log_warning("Some PE or CIB files contain possibly sensitive data")
                utils.log_warning("You may not want to send this report to a public mailing list")


def sanitize_one(context, in_file):
    data = utils.get_data_from_tarfile(in_file)
    if not data:
        return

    ref = make_temp_file()
    context.add_tempfile(ref)
    touch_r(in_file, ref)

    with open_(in_file, 'w') as f:
        f.write(sub_string(data))

    touch_r(ref, in_file)


def pick_first(choice):
    for tmp in choice:
        if crmutils.is_program(tmp):
            return tmp
    return None


def pick_compress(context):
    compress_prog_ext_dict = {
        "bzip2": ".bz2",
        "gzip": ".gz",
        "xz":".xz"
    }
    context.compress_prog = pick_first(compress_prog_ext_dict.keys())
    if context.compress_prog:
        context.compress_ext = compress_prog_ext_dict[context.compress_prog]
    else:
        utils.log_warning("Could not find a compression program; the resulting tarball may be huge")
        context.compress_prog = "cat"


def consolidate(context, file_name):
    """
    Remove duplicates if files are same, make links instead
    """
    if file_name == const.CIB_F:
        return
    for n in context.nodes:
        orig_file = os.path.join(context.work_dir, n, file_name)
        if os.path.isfile(os.path.join(context.work_dir, file_name)):
            os.remove(orig_file)
        else:
            shutil.move(orig_file, context.work_dir)
        os.symlink("../{}".format(file_name), orig_file)


def cib_diff(cib1, cib2):
    """
    check if cib files have same content in the cluster
    """
    return_code = False
    out_string = ""

    if not utils.which("crm_diff"):
        utils.log_warning("crm_diff(8) not found, cannot diff CIBs")
        return return_code, out_string

    dir1 = os.path.dirname(cib1)
    dir2 = os.path.dirname(cib2)
    run1 = os.path.join(dir1, "RUNNING")
    run2 = os.path.join(dir2, "RUNNING")
    stop1 = os.path.join(dir1, "STOPPED")
    stop2 = os.path.join(dir2, "STOPPED")

    if os.path.isfile(run1) and os.path.isfile(run2) or \
            os.path.isfile(stop1) and os.path.isfile(stop2):
        rc, out, _ = crmutils.get_stdout_stderr("crm_diff -c -n {} -o {}".format(cib1, cib2))
        if out:
            out_string += "{}\n".format(out)
        return_code = not bool(rc)
    else:
        out_string += "Can't compare cibs from running and stopped systems\n"
    return return_code, out_string


def text_diff(file1, file2):
    out_string = ""
    rc, out, _ = crmutils.get_stdout_stderr("diff -bBu {} {}".format(file1, file2))
    return_code = not bool(rc)
    if out:
        out_string += "{}\n".format(out)
    return return_code, out_string


def diff_check(file1, file2):
    out_string = ""
    return_code = False
    for f in [file1, file2]:
        if not os.path.isfile(f):
            out_string += "{} does not exist\n".format(f)
            return return_code, out_string
    if os.path.basename(file1) == const.CIB_F:
        return cib_diff(file1, file2)
    else:
        return text_diff(file1, file2)


def analyze_one(context, file_name):
    rc_list = []
    out_string = ""
    file1 = os.path.join(context.work_dir, context.nodes[0], file_name)
    for n in context.nodes[1:]:
        rc, out = diff_check(file1, os.path.join(context.work_dir, n, file_name))
        rc_list.append(rc)
        out_string += out
    return all(rc_list), out_string


def analyze(context):
    out_string = ""
    flist = [const.MEMBERSHIP_F, const.CRM_MON_F, const.B_CONF, const.SYSINFO_F, const.CIB_F]
    for f in flist:
        out_string += "Diff {}...".format(f)
        glob_res = glob.glob("{}/*/{}".format(context.work_dir, f))
        if len(glob_res) == 1:
            out_string += "Only one {}, skip\n".format(glob_res[0])
            continue
        if not glob_res:
            out_string += "Not found {}/*/{}\n".format(context.work_dir, f)
            continue
    
        rc, out = analyze_one(context, f)
        if rc:
            out_string += "OK\n\n"
            consolidate(context, f)
        else:
            out_string += "\n{}\n\n".format(out)

    out_string += check_crmvfy(context)
    out_string += check_cores(context)
    out_string += check_logs(context)
    crmutils.str2file(out_string, os.path.join(context.work_dir, const.ANALYSIS_F))


def check_crmvfy(context):
    out_string = ""
    for n in context.nodes:
        crm_verify_f = os.path.join(context.work_dir, n, const.CRM_VERIFY_F)
        if os.path.isfile(crm_verify_f):
            out_string += "WARN: crm_verify reported warnings at {}:\n".format(n)
            with open(crm_verify_f) as f:
                out_string += f.read()
    return out_string


def check_cores(context):
    out_string = ""
    flist = glob.glob(os.path.join(context.work_dir, "*/cores/*"))
    if flist:
        out_string += "WARN: coredupmps found at:\n"
        for f in flist:
            out_string += "  {}\n".format(f)
    return out_string


def check_logs(context):
    def filter_log(log, patt):
        out = ""
        with open(log) as fd:
            data = fd.read()
        for line in data.split('\n'):
            if re.search(patt, line):
                out += '{}\n'.format(line)
        return out

    out_string = ""
    logfile_list = []
    flist = [os.path.basename(f) for f in context.extra_logs] + [const.HALOG_F]
    for f in flist:
        logfile_list += glob.glob(os.path.join(context.work_dir, '*/{}'.format(f)))
    if not logfile_list:
        return out_string
    out_string += "\nLog patterns:\n"
    log_patterns = context.regex.replace(' ', '|')
    for f in logfile_list:
        out_string += filter_log(f, log_patterns)
    return out_string


def process_results(context):
    analyze(context)

    if context.no_compress:
        shutil.move(context.work_dir, context.dest_dir)
    else:
        pick_compress(context)
        cmd_meta = {
            "w_dir": context.work_dir,
            "dest": context.dest,
            "d_dir": context.dest_dir,
            "comp_prog": context.compress_prog,
            "comp_ext": context.compress_ext
        }
        cmd = r"(cd {w_dir}/.. && tar cf - {dest})|{comp_prog} > {d_dir}/{dest}.tar{comp_ext}".format(**cmd_meta)
        utils.log_debug2("Running: {}".format(cmd))
        rc, _, err = crmutils.get_stdout_stderr(cmd)
        if err:
            utils.log_fatal(err)

    finalword(context)


def finalword(context):
    if context.no_compress:
        dest_path = "{}/{}".format(context.dest_dir, context.dest)
    else:
        dest_path = "{}/{}.tar{}".format(context.dest_dir, context.dest, context.compress_ext)
    utils.log_info("The report is saved in {}".format(dest_path))
    utils.log_info("Report timespan: {} - {}".format(context.from_time_str, context.to_time_str))
    utils.log_info("Thank you for taking time to create this report.")


def push_data(context):
    utils.log_debug2("Pushing data from {}".format(context.work_dir))
    cmd = r'cd {}/.. && tar -h -cf - {}'.format(context.work_dir, utils.me())
    rc, out, err = crmutils.get_stdout_stderr(cmd, raw=True)
    if rc == 0 and out:
        print("{}{}".format(const.COMPRESS_DATA_FLAG, out))
        utils.log_debug1("="*45)
    if rc != 0 and err:
        utils.log_fatal(err)


def dump_context(context):
    crmutils.str2file(context.dumps(), os.path.join(context.work_dir, const.CTX_F))


def run(context):
    '''
    Major work flow
    '''
    if is_collector():
        load_context(context)
    else:
        parse_argument(context)
        load_from_config(context)

    context.create_tempfile()
    atexit.register(context.drop_tempfile)
    setup_workdir(context)

    if is_collector():
        collect_journal_ha(context)
        collect_journal_general(context)
        collect_other_logs_and_info(context)
        dump_context(context)
        push_data(context)
    else:
        get_nodes(context)
        ssh_issue(context)
        collect_for_nodes(context)
        process_results(context)


ctx = Context()
