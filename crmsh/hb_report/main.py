import os
import sys
import re
import json
import argparse
import shutil
import glob
from enum import Enum
from multiprocessing import Process

from crmsh import log, tmpfiles
from crmsh import utils as crmutils
from crmsh.config import report, path
from crmsh.hb_report import const, utils


logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)
logger_utils.set_debug2_level()


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


class Context(object):
    """
    Class to store and manage value in context
    """
    def __init__(self):
        """
        Init function
        """
        self.__dict__['from_time'] = utils.parse_to_timestamp(report.from_time)
        self.__dict__['no_compress'] = not report.compress
        self.__dict__['speed_up'] = report.speed_up
        self.__dict__['extra_logs'] = report.collect_extra_logs.split()
        self.__dict__['rm_exist_dest'] = report.remove_exist_dest
        self.__dict__['single'] = report.single_node

        self.__dict__['to_time'] = utils.parse_to_timestamp(utils.now())
        self.__dict__['sensitive_regex'] = ["passw.*"]
        self.__dict__['regex'] = "CRIT: ERROR: error: warning: crit:".split()
        self.__dict__['ssh_askpw_nodes'] = []
        self.__dict__['name'] = "hb_report"

    def __str__(self):
        return json.dumps(self.__dict__)


ctx = Context()


def is_collector():
    """
    Check if current process is collector
    """
    return len(sys.argv) > 2 and sys.argv[2] == const.COLLECTOR


def process_dest(context):
    """
    """
    if os.path.isdir(context.dest) and context.no_compress:
        if context.rm_exist_dest:
            shutil.rmtree(context.dest)
        else:
            crmutils.fatal('Destination directory "{}" exists, please cleanup or use -Z option'.format(context.dest))

    dest_dir = os.path.dirname(context.dest)
    if not dest_dir:
        dest_dir = "."
    if not os.path.isdir(dest_dir):
        crmutils.fatal("\"{}\" isn't a directory".format(dest_dir))
    context.dest_dir = dest_dir

    dest_file = os.path.basename(context.dest)
    if not crmutils.is_filename_sane(dest_file):
        crmutils.fatal("\"{}\" is invalid file name".format(dest_file))

    context.dest = dest_file


def setup_workdir(context):
    """
    """
    process_dest(context)
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
    elif args.speed_up and args.sanitize:
        options = "-s and -Q"
    if options:
        crmutils.fatal("{} options are exclusive".format(options))


def process_context_value(context):
    """
    """
    if context.before_time:
        context.from_time = context.before_time
    if context.to_time <= context.from_time:
        crmutils.fatal("Start time must be before finish time")
    if not context.dest:
        context.dest = '{}-{}'.format(context.name, utils.now(const.TIME_FORMAT_FOR_TAR))

    context.from_time_str = utils.ts_to_str(context.from_time)
    context.to_time_str = utils.ts_to_str(context.to_time)


def process_option_value(name, value):
    """
    Process option values before setting them to context, parse and validate
    """
    if name == "debug":
        report.verbosity = value
    if name == "before_time" and not re.match(const.DELTA_TIME_REG, value):
        crmutils.fatal("Wrong format of -b option \"{}\" (valid examples: {})".format(value, const.DELTA_TIME_EXAMPLE))
    if name in ["from_time", "to_time"]:
        value = utils.parse_to_timestamp(value)
    if name == "ssh_options":
        value = crmutils.parse_append_action_argument(value)
        for item in value:
            if not re.search('\w+=\w+', item):
                crmutils.fatal("Wrong format of -X option \"{}\" (valid format: \w+=\w+)".format(item))
    if name == "nodes":
        value = crmutils.parse_append_action_argument(value)
        # TODO need to verify it?
    if name in ["extra_logs", "regex", "sensitive_regex"]:
        value = crmutils.parse_append_action_argument(value) + self.__dict__[name]
        # TODO don't forget the password bug of hb_report
    if isinstance(value, list):
        value = utils.unique_list(value)
    return value


def parse_argument(context):
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
    parser.add_argument('-s', dest='sanitize', action='store_true',
            help='Replace sensitive info in PE or CIB or pacemaker log files')
    parser.add_argument('-p', dest='sensitive_regex', metavar='patt', action='append', default=[],
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
        raise crmutils.TerminateSubCommand

    return args


def process_argument(context):
    """
    """
    args = parse_argument(context)
    check_exclusive_options(args)
    crmutils.check_space_option_value(args)

    for arg in vars(args):
        value = getattr(args, arg)
        if value:
            value = process_option_value(arg, value)
            setattr(context, arg, value)
        elif not hasattr(context, arg):
            setattr(context, arg, value)

    process_context_value(context)
    logger.debug2("In context: %s", context)


def get_nodes(context):
    """
    Find nodes if context.nodes not set
    """
    if not context.nodes:
        nodes = crmutils.list_cluster_nodes()
        if not nodes:
            crmutils.fatal("Cannot figure out a list of nodes")
        context.nodes = nodes
    if context.single:
        context.nodes = [utils.this_node()]

    logger.debug("Nodes to collect: %s", context.nodes)


def is_our_log(context, logf):
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
    last_time = utils.find_first_ts(utils.tail(10, data))
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


def arch_logs(context, logf):
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
        res = is_our_log(context, f)
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

    to_line = utils.findln_by_time(data, to_time) if to_time != 0 else last_line
    if not to_line:
        logger.warning("Couldn't find line in %s for time %s", logf, utils.ts_to_str(to_time))
        return ""

    logger.debug2("Including segment [%s-%s] from %s", from_line, to_line, logf)
    return utils.filter_lines(data, from_line, to_line)


def dump_logset(context, logf):
    """
    find log/set of logs which are interesting for us
    """
    logf_type, logf_list = arch_logs(context, logf)
    if not logf_list:
        logger.debug2("No suitable log set found for log %s", logf)
        return

    out_string = ""
    # irregular file list
    if logf_type == LogfileType.IRREGULAR:
        for f in logf_list:
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
        outf = os.path.join(context.work_dir, os.path.basename(logf))
        crmutils.str2file(out_string.strip('\n'), outf)
        logger.debug("Dump logset \"%s\" into %s/%s", logf_list, context.dest_path, os.path.basename(logf))


def get_ha_varlib(context):
    """
    Get HA_VARLIB value from ocf lib
    """
    ocf_lib_file = "{}/lib/heartbeat/ocf-directories".format(context.ocf_root)
    if not os.path.exists(ocf_lib_file):
        crmutils.fatal("File {} not exist".format(ocf_lib_file))
    with open(ocf_lib_file) as f:
        data = f.read()
    for line in data.split('\n'):
        res = re.search(r'HA_VARLIB:=(.*)}', line)
        if res:
            context.ha_varlib = res.group(1)
        else:
            crmutils.fatal("Cannot find HA_VARLIB in {}".format(ocf_lib_file))


def get_dir_from_crm_config_path(context):
    """
    Get some directories from crmsh.config.path
    """
    for item in ["ocf_root", "pe_state_dir", "crm_config"]:
        value = getattr(path, item, None)
        if not value or not os.path.isdir(value):
            crmutils.fatal("Cannot find {} directory from crmsh.config.path".format(item))
        setattr(context, item, value)


def get_cores_dir(context):
    """
    Get cores directories
    """
    context.pcmk_lib = os.path.dirname(context.crm_config)
    context.cores_dirs = os.path.join(context.pcmk_lib, "cores")
    if os.path.isdir(const.COROSYNC_LIB):
        context.cores_dirs += " {}".format(const.COROSYNC_LIB)


def load_from_config(context):
    """
    load context attributes from crmsh.config
    """
    get_dir_from_crm_config_path(context)
    get_ha_varlib(context)
    get_cores_dir(context)


def run(*args):
    """
    Major work flow
    """
    if is_collector():
        logger.info("in collector")
    else:
        process_argument(ctx)
        load_from_config(ctx)

    setup_workdir(ctx)

    if is_collector():
        pass
    else:
        get_nodes(ctx)

    return True
