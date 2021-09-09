import os
import sys
import re
import json
import argparse
import shutil
import glob
from enum import Enum
from multiprocessing import Pool
from inspect import getmembers, isfunction

from crmsh import log, tmpfiles
from crmsh import utils as crmutils
from crmsh.config import report, path
from crmsh.report import const, utils, collect, sanitize


logger = log.setup_report_logger(__name__)


class LogfileType(Enum):
    """
    Class to define files under timespan
    """
    UNKNOWN = -1
    # in timespan, include
    GOOD = 0
    # irregular file not starts with regular timE
    IRREGULAR = 1
    # empty file
    EMPTY = 2
    # before the timespan
    BEFORE_TIME = 3
    # after the timespan
    AFTER_TIME = 4


def generate_collect_functions():
    """
    Generate function list from collect.py
    """
    return [func for func, _ in getmembers(collect, isfunction) if func.startswith("collect_")]


class Context(object):
    """
    Class to store and manage value in context
    """
    def __init__(self):
        """
        Init function
        """
        self.no_compress = None
        self.speed_up = None
        self.extra_logs = []
        self.rm_exist_dest = None
        self.single = None
        self.from_time = None
        self.to_time = None
        self.delta_time_str = None
        self.regex = "CRIT: ERROR: error: warning: crit:".split()
        self.ssh_askpw_nodes = []
        self.collect_functions = []
        self.sensitive_regex_list = []
        self.sanitize_rule_dict = {}
        self.sanitize_value_cib_list = []
        self.sanitize_key_cib_list = []
        self.sanitize_value_raw_list = []

    def __str__(self):
        return json.dumps(self.__dict__)

    def dumps(self):
        return json.dumps(self.__dict__, indent=2)

    def load_values(self):
        """
        Load values for Context instance
        """
        self.from_time = utils.parse_to_timestamp(report.from_time)
        self.to_time = utils.parse_to_timestamp(utils.now())
        self.no_compress = not report.compress
        self.speed_up = report.speed_up
        self.extra_logs = report.collect_extra_logs.split()
        self.rm_exist_dest = report.remove_exist_dest
        self.single = report.single_node
        self.get_dir_from_crm_config_path()
        self.get_ha_varlib()
        self.get_cores_dir()
        self.sensitive_regex_list += sanitize.load_sanitize_rule()

    def get_dir_from_crm_config_path(self):
        """
        Get some directories from crmsh.config.path
        """
        for item in ["ocf_root", "pe_state_dir", "crm_config"]:
            value = getattr(path, item, None)
            if not value or not os.path.isdir(value):
                raise utils.CRMReportError("Cannot find {} directory from crmsh.config.path".format(item))
            setattr(self, item, value)

    def get_ha_varlib(self):
        """
        Get HA_VARLIB value from ocf lib
        """
        ocf_lib_file = "{}/lib/heartbeat/ocf-directories".format(self.ocf_root)
        if not os.path.exists(ocf_lib_file):
            raise utils.CRMReportError("File {} not exist".format(ocf_lib_file))
        data = utils.read_from_file(ocf_lib_file)
        if not data:
            raise utils.CRMReportError("File {} is empty".format(ocf_lib_file))
        res = re.search(r'HA_VARLIB:=(.*)}', data)
        if res:
            self.ha_varlib = res.group(1)
        else:
            raise utils.CRMReportError("Cannot find HA_VARLIB in {}".format(ocf_lib_file))

    def get_cores_dir(self):
        """
        Get cores directories
        """
        self.pcmk_lib = os.path.dirname(self.crm_config)
        self.cores_dirs = [os.path.join(self.pcmk_lib, "cores")]
        if os.path.isdir(const.COROSYNC_LIB):
            self.cores_dirs.append(const.COROSYNC_LIB)

    def load_from_argv(self):
        """
        Load context attributes from master process
        """
        for key, value in json.loads(sys.argv[2]).items():
            setattr(self, key, value)


context = Context()


def is_collector():
    """
    Check if current process is collector
    """
    return len(sys.argv) > 1 and sys.argv[1] == const.COLLECTOR


def validate_dest():
    """
    Validate dest directory
    """
    if os.path.isdir(context.dest) and context.no_compress:
        if context.rm_exist_dest:
            shutil.rmtree(context.dest)
        else:
            raise utils.CRMReportError('Destination directory "{}" exists, please cleanup or use -Z option'.format(context.dest))

    dest_dir = os.path.dirname(context.dest)
    if not dest_dir:
        dest_dir = "."
    if not os.path.isdir(dest_dir):
        raise utils.CRMReportError("\"{}\" isn't a directory".format(dest_dir))
    context.dest_dir = dest_dir

    dest_file = os.path.basename(context.dest)
    if not crmutils.is_filename_sane(dest_file):
        raise utils.CRMReportError("\"{}\" is invalid file name".format(dest_file))

    context.dest = dest_file


def setup_workdir():
    """
    Setup work directory
    """
    validate_dest()
    tmpdir = tmpfiles.create_dir()
    if not is_collector():
        context.work_dir = os.path.join(tmpdir, context.dest)
    else:
        context.work_dir = os.path.join(tmpdir, context.dest, crmutils.this_node())
        context.dest_path = os.path.join(context.dest, crmutils.this_node())
    crmutils.mkdirp(context.work_dir)
    logger.debug("Setup work directory in \"%s\"", context.work_dir)


def check_exclusive_options(args):
    """
    Check if exclusive options used together
    """
    options = ""
    if args.from_time and args.before_time:
        options = "-f and -b"
    elif args.to_time and args.before_time:
        options = "-t and -b"
    elif args.nodes and args.single:
        options = "-n and -S"
    elif args.extra_logs and args.no_extra:
        options = "-E and -M"
    if options:
        raise utils.CRMReportError("{} options are exclusive".format(options))


def process_context_value():
    """
    Process some context values
    """
    if context.before_time:
        context.from_time = utils.parse_to_timestamp(context.before_time)
    if context.to_time <= context.from_time:
        raise utils.CRMReportError("Start time must be before finish time")
    if not context.dest:
        context.dest = '{}-{}'.format(context.name, utils.now(const.TIME_FORMAT_FOR_TAR))
    sanitize.parse_sanitize_rule(context.sensitive_regex_list)
    context.from_time_str = utils.ts_to_str(context.from_time)
    context.to_time_str = utils.ts_to_str(context.to_time)


def process_option_value(name, value):
    """
    Process option values before setting them to context, parse and validate
    """
    if name == "debug":
        report.verbosity = value
    if name == "before_time" and not re.match(const.DELTA_TIME_REG, value):
        raise utils.CRMReportError("Wrong format of -b option \"{}\" (valid examples: {})".format(value, const.DELTA_TIME_EXAMPLE))
    if name in ["from_time", "to_time"]:
        value = utils.parse_to_timestamp(value)
    if name == "ssh_options":
        value = crmutils.parse_append_action_argument(value)
        for item in value:
            if not re.search('\w+=\w+', item):
                raise utils.CRMReportError("Wrong format of -X option \"{}\" (valid format: \w+=\w+)".format(item))
    if name == "nodes":
        value = crmutils.parse_append_action_argument(value)
        # TODO need to verify it?
    if name in ["extra_logs", "regex", "sensitive_regex_list"]:
        value = crmutils.parse_append_action_argument(value) + getattr(context, name, [])
    if isinstance(value, list):
        value = utils.unique_list(value)
    return value


def parse_argument():
    """
    Use argparse to parse argument
    """
    parser = argparse.ArgumentParser(
            usage="{} [options] [dest]".format(context.name),
            epilog=const.EXTRA_HELP,
            add_help=False,
            formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-h", "--help", action="store_true", dest="help",
            help="Show this help message and exit")
    parser.add_argument('-f', dest='from_time', metavar='time',
            help='Time to start from (default: 12 hours before)')
    parser.add_argument('-t', dest='to_time', metavar='time',
            help='Time to finish at (default: now)')
    parser.add_argument('-b', dest='before_time', metavar='time',
            help='How long time in the past, before now (valid examples: {})'.format(const.DELTA_TIME_EXAMPLE))
    parser.add_argument('-d', dest='no_compress', action='store_true',
            help="Don't compress, but leave result in a directory")
    parser.add_argument('-n', dest='nodes', metavar='node', action="append", default=[],
            help='Node names for this cluster; this option is additive (use -n a -n b or -n "a b"); if you run report on the loghost or use autojoin, it is highly recommended to set this option''')
    parser.add_argument('-u', dest='ssh_user', metavar='user',
            help='SSH user to access other nodes'),
    parser.add_argument('-X', dest='ssh_options', metavar='ssh-options', action='append', default=[],
            help='Extra ssh(1) options (default: StrictHostKeyChecking=no EscapeChar=none ConnectTimeout=15); this option is additive (use -X opt1 -X opt2 or -X "opt1 opt2")'),
    parser.add_argument('-E', dest='extra_logs', metavar='file', action='append', default=[],
            help='Extra logs to collect (default: /var/log/messages, /var/log/ha-cluster-bootstrap.log); this option is additive (use -E file1 -E file2 or -E "file1 file2")')
    parser.add_argument('-s', dest='do_sanitize', action='store_true',
            help='Replace sensitive info in PE or CIB or pacemaker log files')
    parser.add_argument('-p', dest='sensitive_regex_list', metavar='patt', action='append', default=[],
            help='Regular expression to match variables containing sensitive data (default: passw.*); this option is additive (use -p patt1 -p patt2 or -p "patt1 patt2")')
    parser.add_argument('-L', dest='regex', metavar='patt', action='append', default=[],
            help='Regular expression to match in log files for analysis (default: CRIT:, ERROR:, error:, warning:, crit:); this option is additive (use -L patt1 -L patt2 or -L "patt1 patt2")')
    parser.add_argument('-Q', dest='speed_up', action='store_true',
            help="The quick mode, which skips producing dot files from PE inputs, verifying installed cluster stack rpms and sanitizing files for sensitive information")
    parser.add_argument('-M', dest='no_extra', action='store_true',
            help="Don't collect extra logs, opposite option of -E")
    parser.add_argument('-Z', dest='rm_exist_dest', action='store_true',
            help='If destination directories exist, remove them instead of exiting')
    parser.add_argument('-S', dest='single', action='store_true',
            help="Single node operation; don't try to start report collectors on other nodes")
    parser.add_argument('-v', dest='debug', action='count', default=0,
            help='Increase verbosity')
    parser.add_argument('dest', nargs='?',
            help='Report name (may include path where to store the report)')

    args = parser.parse_args()
    if args.help:
        parser.print_help()
        sys.exit(0)

    return args


def process_argument():
    """
    Parse, validate and process arguments, put the values into context
    """
    args = parse_argument()
    check_exclusive_options(args)
    crmutils.check_space_option_value(args)

    for arg in vars(args):
        value = getattr(args, arg)
        if value:
            value = process_option_value(arg, value)
            setattr(context, arg, value)
        elif not hasattr(context, arg):
            setattr(context, arg, value)

    process_context_value()
    logger.debug2("In context: %s", context)


def get_nodes():
    """
    Find nodes if context.nodes not set
    """
    if context.single:
        context.nodes = [crmutils.this_node()]
    elif not context.nodes:
        nodes = crmutils.list_cluster_nodes()
        if not nodes:
            raise utils.CRMReportError("Cannot figure out a list of nodes")
        context.nodes = nodes

    logger.debug("Nodes to collect: %s", context.nodes)


def is_our_log(logf):
    '''
    check if the log contains a piece of our segment

    return value
    0      good log;        include
    1      irregular log;   include
    2      empty log;       don't include
    3      before timespan; don't include
    4      after timespan;  don't include
    '''
    data = utils.read_from_file(logf)
    if not data:
        logger.debug2("Found empty file \"%s\"; exclude", logf)
        return LogfileType.EMPTY

    # reset this attr to check file's format
    if hasattr(context, 'stamp_type'):
        delattr(context, "stamp_type")
    first_time = utils.find_first_ts(utils.head(10, data))
    last_time = utils.find_first_ts(utils.tail(10, data), order=False)
    from_time = context.from_time
    to_time = context.to_time

    if (not first_time) or (not last_time):
        logger.debug2("Found irregular file \"%s\"; include", logf)
        return LogfileType.IRREGULAR
    if from_time > last_time:
        logger.debug2("Found before timespan file \"%s\"; exclude", logf)
        return LogfileType.BEFORE_TIME
    if from_time >= first_time or to_time >= first_time:
        logger.debug2("Found in timespan file \"%s\"; include", logf)
        return LogfileType.GOOD
    else:
        logger.debug2("Found after timespan file \"%s\"; exclude", logf)
        return LogfileType.AFTER_TIME


def arch_logs(logf):
    """
    go through archived logs (timewise backwards) and see if there
    are lines belonging to us
    (we rely on untouched log files, i.e. that modify time
    hasn't been changed)
    """
    ret_list = []
    _type = LogfileType.UNKNOWN
    # look for rotation files such as: ha-log-20090308 or
    # ha-log-20090308.gz (.bz2) or ha-log.0, etc
    files = [logf] + glob.glob(logf+"*[0-9z]")
    # like ls -t, newest first
    for f in sorted(files, key=os.path.getmtime, reverse=True):
        res = is_our_log(f)
        # empty or after timespan, continue
        if res in [LogfileType.EMPTY, LogfileType.AFTER_TIME]:
            continue
        # before timespan, no need go ahead
        if res == LogfileType.BEFORE_TIME:
            break
        # good/irregular file, append
        if res in [LogfileType.GOOD, LogfileType.IRREGULAR]:
            _type = res
            ret_list.append(f)
    if ret_list:
        logger.debug2("Found logs {}".format(ret_list))
    return _type, ret_list


def print_logseg(logf, from_time, to_time):
    """
    Dump log content in timespan
    """
    data = utils.read_from_file(logf)
    first_line = 1
    last_line = len(data.split('\n'))

    from_line = utils.findln_by_time(data, from_time) if from_time != 0 else first_line
    if not from_line:
        logger.warning("Couldn't find line in %s for time %s", logf, utils.ts_to_str(from_time))
        return ""

    to_line = utils.findln_by_time(data, to_time, left_value=True) if to_time != 0 else last_line
    if not to_line:
        logger.warning("Couldn't find line in %s for time %s", logf, utils.ts_to_str(to_time))
        return ""

    logger.debug2("Including segment [%s-%s] from %s", from_line, to_line, logf)
    return '\n'.join(data.split('\n')[from_line-1: to_line]) + '\n'


def dump_logset(logf):
    """
    find log/set of logs which are interesting for us
    """
    logf_type, logf_list = arch_logs(logf)
    if not logf_list:
        logger.debug2("No suitable log set found for log %s", logf)
        return

    out_string = ""
    # irregular file list
    if logf_type == LogfileType.IRREGULAR:
        for f in reversed(logf_list):
            out_string += print_logseg(f, 0, 0)
            logger.debug2("Including complete file \"%s\"", f)
    elif logf_type == LogfileType.GOOD:
        num_logs = len(logf_list)
        if num_logs == 1:
            out_string += print_logseg(logf_list[0], context.from_time, context.to_time)
            logger.debug2("Including incomplete file \"%s\", from %s to %s", logf_list[0], context.from_time_str, context.to_time_str)
        else:
            newest, *middles, oldest = logf_list
            out_string += print_logseg(oldest, context.from_time, 0)
            logger.debug2("Including incomplete file \"%s\", from %s to the last line", oldest, context.from_time_str)
            for f in middles:
                out_string += print_logseg(f, 0, 0)
                logger.debug2("Including complete file \"%s\"", f)
            out_string += print_logseg(newest, 0, context.to_time)
            logger.debug2("Including incomplete file \"%s\", from the first line to %s", newest, context.to_time_str)

    if out_string:
        basename_f = os.path.basename(logf)
        crmutils.str2file(out_string.strip('\n'), utils.work_path(basename_f))
        logger.debug("Dump logset \"%s\" into %s", logf_list, utils.dest_path(basename_f))


def find_ssh_user():
    ssh_user = "__undef"

    if not context.ssh_user:
        try_user_list = ["__default"] + const.TRY_SSH_USER.split()
    else:
        try_user_list = [context.ssh_user]

    for n in context.nodes:
        rc = 1
        if n == crmutils.this_node():
            continue
        for u in try_user_list:
            if u != '__default':
                ssh_s = '@'.join((u, n))
            else:
                ssh_s = n

            if not crmutils.check_ssh_passwd_need(ssh_s):
                logger.debug("ssh %s OK", ssh_s)
                ssh_user = u
                try_user_list = [u] # we support just one user
                rc = 0
                break
            else:
                logger.debug("ssh %s failed", ssh_s)
        if rc == 1:
            context.ssh_askpw_nodes.append(n)

    if context.ssh_askpw_nodes:
        logger.warning("Passwordless ssh to node(s) %s does not work", context.ssh_askpw_nodes)
    if ssh_user == "__undef":
        return
    if ssh_user != "__default":
        context.ssh_user = ssh_user


def ssh_issue():
    if not context.single:
        find_ssh_user()
    if context.ssh_options:
        ssh_opts = ' '.join(context.ssh_options)
    else:
        ssh_opts = const.SSH_OPTS_DEFAULT
    if context.ssh_user:
        ssh_opts += " User={}".format(context.ssh_user)
    context.ssh_options = ssh_opts.split()


def start_collector(node):
    """
    """
    cmd_slave = r"crm report {} '{}'".format(const.COLLECTOR, context)
    if node == crmutils.this_node():
        #TODO need sudo?
        cmd = cmd_slave
    else:
        cmd = r'ssh -o {} {} "{}"'.format(' -o '.join(context.ssh_options), node, cmd_slave.replace('"', '\\"'))
    logger.debug2("Running: %s", cmd)

    rc, out, err = crmutils.get_stdout_stderr(cmd)
    if rc == 255: # TODO ssh error?
        context.nodes.remove(node)
        return
    if err:
        print(err)
    compress_data = ""
    for data in out.split('\n'):
        if data.startswith(const.COMPRESS_DATA_FLAG):
            # report data from collector
            compress_data = data.lstrip(const.COMPRESS_DATA_FLAG)
        else:
            # log data from collector
            print(data)

    cmd = r"(cd {} && tar xf -)".format(context.work_dir)
    crmutils.get_stdout_stderr(cmd, input_s=eval(compress_data))


def collect_for_nodes():
    """
    Run collector on each node
    """
    for node in context.nodes:
        if node in context.ssh_askpw_nodes:
            context.nodes.remove(node)
    if context.nodes:
        pool = Pool(processes=len(context.nodes))
        for node in context.nodes:
            pool.apply_async(start_collector, args=(node,))
        pool.close()
        pool.join()

    for node in context.ssh_askpw_nodes:
        logger.info("Please provide password for %s at %s",
                context.ssh_user if context.ssh_user else "your user",
                node)
        logger.info("Note that collecting data will take a while.")
        start_collector(node)


def finalword():
    """
    Show final words at the end
    """
    if context.no_compress:
        dest_path = "{}/{}".format(context.dest_dir, context.dest)
    else:
        dest_path = "{}/{}.tar{}".format(context.dest_dir, context.dest, context.compress_ext)
    logger.info("The report is saved in %s", dest_path)
    logger.info("Report timespan: %s - %s", context.from_time_str, context.to_time_str)
    logger.info("Thank you for taking time to create this report.")


def pick_compress():
    """
    Choose compress prog and ext name
    """
    compress_prog_ext_dict = {
        "bzip2": ".bz2",
        "gzip": ".gz",
        "xz":".xz"
    }
    context.compress_prog = next(filter(lambda cmd: crmutils.is_program(cmd), compress_prog_ext_dict.keys()), "cat")
    context.compress_ext = "" if context.compress_prog == "cat" else compress_prog_ext_dict[context.compress_prog]


def touch_timespan_file():
    """
    Touch timespan file
    """
    timespan_str = "Report timespan: {} - {}{}".format(context.from_time_str, context.to_time_str, ", " + context.delta_time_str if context.delta_time_str else "")
    crmutils.str2file(timespan_str, utils.work_path(const.TIMESPAN_F))


def dump_context():
    """
    """
    crmutils.str2file(context.dumps(), utils.work_path(const.CTX_F))


def cib_diff(cib1, cib2):
    """
    Check if cib files have same content in the cluster
    """
    return_code = False
    out_string = ""

    if not utils.which("crm_diff"):
        out_string = "crm_diff(8) not found, cannot diff CIBs"
        logger.warning(out_string)
        return return_code, out_string

    node1 = os.path.dirname(cib1)
    node2= os.path.dirname(cib2)
    run1 = os.path.join(node1, const.RUNNING_FLAG)
    run2 = os.path.join(node2, const.RUNNING_FLAG)
    stop1 = os.path.join(node1, const.STOPPED_FLAG)
    stop2 = os.path.join(node2, const.STOPPED_FLAG)

    if os.path.isfile(run1) and os.path.isfile(run2) or \
            os.path.isfile(stop1) and os.path.isfile(stop2):
        rc, out, _ = crmutils.get_stdout_stderr("crm_diff -c -n {} -o {}".format(cib1, cib2))
        if out:
            out_string += "{}\n".format(out)
        return_code = not bool(rc)
    else:
        out_string += "Can't compare cibs from running and stopped systems ({} and {})\n".format(node1, node2)
    return return_code, out_string


def text_diff(file1, file2):
    """
    Show difference for two common files
    """
    out_string = ""
    rc, out, _ = crmutils.get_stdout_stderr("diff -bBu {} {}".format(file1, file2))
    return_code = not bool(rc)
    if out:
        out_string += "{}\n".format(out)
    return return_code, out_string


def diff_check(file1, file2):
    """
    Show difference for two files
    """
    out_string = ""
    return_code = False
    for f in [file1, file2]:
        if not os.path.exists(f):
            out_string += "{} does not exist\n".format(f)
            return return_code, out_string
    if os.path.basename(file1) == const.CIB_F:
        return cib_diff(file1, file2)
    else:
        return text_diff(file1, file2)


def consolidate_or_diff(file_name):
    """
    Consolidate the file if its contents are the same
    Else, show the diff part
    """
    rc_list = []
    out_string = ""
    file1 = os.path.join(context.work_dir, context.nodes[0], file_name)
    for n in context.nodes[1:]:
        rc, out = diff_check(file1, os.path.join(context.work_dir, n, file_name))
        rc_list.append(rc)
        out_string += out

    if all(rc_list):
        out_string += "OK\n\n"
        consolidate(file_name)
    else:
        out_string += "\n{}\n\n".format(out)
    return out_string


def consolidate(file_name):
    """
    Remove duplicates if files are same, make links instead
    """
    if file_name == const.CIB_F:
        return
    for n in context.nodes:
        orig_file = os.path.join(context.work_dir, n, file_name)
        if os.path.isfile(utils.work_path(file_name)):
            os.remove(orig_file)
        else:
            shutil.move(orig_file, context.work_dir)
        os.symlink("../{}".format(file_name), orig_file)


def check_crmvfy():
    """
    Check if there was output in crm_verify.txt
    """
    out_string = ""
    for n in context.nodes:
        crm_verify_f = os.path.join(context.work_dir, n, const.CRM_VERIFY_F)
        if os.path.isfile(crm_verify_f):
            out_string += "WARN: crm_verify reported warnings at {}, see {}\n".format(n, crm_verify_f)
    return out_string


def check_backtraces():
    """
    Check if there was coredumps
    """
    out_string = ""
    for n in context.nodes:
        bt_f = os.path.join(context.work_dir, n, const.BT_F)
        if os.path.isfile(bt_f) and not utils.is_file_empty(bt_f):
            out_string += "WARN: coredumps found at {}, see {}\n".format(n, bt_f)
    return out_string


def filter_log(log, patt):
    out_string = ""
    data = utils.read_from_file(log)
    if not data:
        return out_string
    for line in data.split('\n'):
        if re.search(patt, line):
            out_string += '{}\n'.format(line)
    return out_string


def check_logs():
    out_string = ""
    logfile_list = []
    flist = [os.path.basename(f) for f in context.extra_logs] + [const.HALOG_F]
    for f in flist:
        logfile_list += glob.glob("{}/*/{}".format(context.work_dir, f))
    if not logfile_list:
        return out_string
    out_string += "\nLog patterns:\n"
    log_patterns = '|'.join(context.regex)
    for f in logfile_list:
        out_string += filter_log(f, log_patterns)
    return out_string


def diff_files():
    """
    Try to diff files between nodes
    """
    out_string = ""
    for f in const.ANALYZE_LIST:
        out_string += "Diff {}...".format(f)
        glob_target = "{}/*/{}".format(context.work_dir, f)
        glob_res = glob.glob(glob_target)
        if len(glob_res) == 1:
            out_string += "Only one {}, skip\n".format(glob_res[0])
            continue
        if not glob_res:
            out_string += "Not found {}\n".format(glob_target)
            continue
        out_string += consolidate_or_diff(f)
    return out_string


def analyze():
    """
    Analyze report results
    """
    out_string = diff_files()
    out_string += check_crmvfy()
    out_string += check_backtraces()
    out_string += check_logs()
    crmutils.str2file(out_string, utils.work_path(const.ANALYSIS_F))


def process_results():
    """
    Process report results
    """
    analyze()
    dump_context()
    touch_timespan_file()

    if context.no_compress:
        shutil.move(context.work_dir, context.dest_dir)
    else:
        pick_compress()
        cmd_meta = {
            "w_dir": context.work_dir,
            "dest": context.dest,
            "d_dir": context.dest_dir,
            "comp_prog": context.compress_prog,
            "comp_ext": context.compress_ext
        }
        cmd = r"(cd {w_dir}/.. && tar cf - {dest})|{comp_prog} > {d_dir}/{dest}.tar{comp_ext}".format(**cmd_meta)
        logger.debug2("Running: %s", cmd)
        utils.get_stdout_or_raise_error(cmd)

    finalword()


def collect_logs_and_info():
    """
    Collect logs, configurations and information
    """
    dump_context()
    # HA log, which will be analyzed later, should be collected firstly
    collect.get_journal_ha()

    collect_func_list = generate_collect_functions()
    pool = Pool(processes=len(collect_func_list))
    # result here to store AsyncResult object returned from apply_async
    # Then calling get() method will catch exceptions like NameError, AttributeError, etc.
    # Otherwise parent process will not know these exceptions raised
    # Calling get() right after apply_async will be blocked until child process finished, so
    # need to append to a list firstly
    # TODO: please improve this if have more suitable solution
    result_list = []
    for cf in collect_func_list:
        result = pool.apply_async(getattr(collect, cf))
        result_list.append(result)
    pool.close()
    pool.join()

    for result in result_list:
        try:
            result.get()
        except utils.CRMReportError as err:
            logger.error(str(err))

    sanitize.sanitize()


def push_data():
    """
    Pushing data from collector
    """
    logger.debug("Finished collecting, pushing data from collector")
    cmd = r'cd {}/.. && tar -h -cf - {}'.format(context.work_dir, crmutils.this_node())
    rc, out, err = crmutils.get_stdout_stderr(cmd, raw=True)
    if rc == 0 and out:
        print("{}{}".format(const.COMPRESS_DATA_FLAG, out))
    else:
        raise utils.CRMReportError(err)


def run():
    """
    Major work flow
    """
    try:
        if is_collector():
            context.load_from_argv()
            report.verbosity = context.debug
        else:
            context.name = const.NAME
            context.load_values()
            process_argument()

        setup_workdir()

        if is_collector():
            collect_logs_and_info()
            push_data()
        else:
            get_nodes()
            ssh_issue()
            collect_for_nodes()
            process_results()
    except utils.CRMReportError as err:
        logger.error(str(err))
        sys.exit(1)
