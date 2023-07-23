# Copyright (C) 2017 Xin Liang <XLiang@suse.com>
# See COPYING for license information.

import bz2
import lzma
import datetime
import glob
import gzip
import multiprocessing
import os
import random
import re
import shutil
import string
import subprocess
import sys
import atexit
import tempfile
import contextlib
from dateutil import tz
from threading import Timer
from inspect import getmembers, isfunction
from enum import Enum
from typing import Optional, List

import crmsh.config
from crmsh import utils as crmutils
from crmsh import corosync, log, userdir, tmpfiles
from crmsh.report import constants, collect, core


logger = log.setup_report_logger(__name__)


class LogType(Enum):
    GOOD = 0             # good log; include
    IRREGULAR = 1        # irregular log; include
    EMPTY = 2            # empty log; exclude
    BEFORE_TIMESPAN = 3  # log before timespan; exclude
    AFTER_TIMESPAN = 4   # log after timespan; exclude


class ReportGenericError(Exception):
    pass


class Tempfile(object):

    def __init__(self):
        self.file = create_tempfile()
        logger.debug("create tempfile \"%s\"", self.file)

    def add(self, filename):
        with open(self.file, 'a') as f:
            f.write(filename + '\n')
        logger.debug("add tempfile \"%s\" to \"%s\"", filename, self.file)

    def drop(self):
        with open(self.file, 'r') as f:
            for line in f.read().split('\n'):
                if os.path.isdir(line):
                    shutil.rmtree(line)
                if os.path.isfile(line):
                    os.remove(line)
        os.remove(self.file)
        logger.debug("remove tempfile \"%s\"", self.file)


def add_tempfiles(filename):
    t = Tempfile()
    t.add(filename)
    atexit.register(t.drop)


def arch_logs(context: core.Context, logf: str) -> List[str]:
    """
    Go through archived logs and return those in timespan
    """
    file_list = [logf] + glob.glob(logf+"*[0-9z]")
    # like ls -t, newest first
    return_list = [
        f
        for f in sorted(file_list, key=os.path.getmtime, reverse=True)
        if is_our_log(context, f) in [LogType.GOOD, LogType.IRREGULAR]
    ]
    if return_list:
        logger.debug2(f"Found logs {return_list} in {get_timespan_str(context)}")

    return return_list


def analyze():
    workdir = constants.WORKDIR
    out_string = ""
    tmp_string = ""
    flist = [constants.MEMBERSHIP_F, constants.CRM_MON_F,
             constants.B_CONF, constants.SYSINFO_F, constants.CIB_F]
    for f in flist:
        out_string += "Diff %s... " % f
        if not glob.glob("%s/*/%s" % (workdir, f)):
            out_string += "no %s/*/%s :/\n" % (workdir, f)
            continue
        code, tmp_string = analyze_one(workdir, f)
        if tmp_string:
            out_string += "\n" + tmp_string + "\n\n"
        else:
            out_string += "OK\n"
        if code == 0:
            if f != constants.CIB_F:
                consolidate(workdir, f)

    out_string += "\n"

    out_string += check_crmvfy(workdir)
    out_string += check_backtraces(workdir)
    out_string += check_permissions(workdir)
    out_string += check_logs(workdir)

    analyze_f = os.path.join(workdir, constants.ANALYSIS_F)
    crmutils.str2file(out_string, analyze_f)


def analyze_one(workdir, file_):
    out_string = ""
    tmp_string = ""
    tmp_rc = 0
    node0 = ""
    rc = 0
    for n in constants.NODES.split():
        if node0:
            tmp_rc, tmp_string = diff_check(os.path.join(workdir, node0, file_), os.path.join(workdir, n, file_))
            out_string += tmp_string
            rc += tmp_rc
        else:
            node0 = n
    return (rc, out_string)


def check_backtraces(workdir):
    out_string = ""
    pattern = "Core was generated|Program terminated"
    for n in constants.NODES.split():
        bt_f = os.path.join(workdir, n, constants.BT_F)
        if os.path.isfile(bt_f) and os.stat(bt_f).st_size != 0:
            out_string += "WARN: coredumps found at %s:\n" % n
            for line in grep(pattern, infile=bt_f):
                out_string += "    %s\n" % line
    return out_string


def check_crmvfy(workdir):
    """
    some basic analysis of the report
    """
    out_string = ""
    for n in constants.NODES.split():
        crm_verify_f = os.path.join(workdir, n, constants.CRM_VERIFY_F)
        if os.path.isfile(crm_verify_f) and os.stat(crm_verify_f).st_size != 0:
            out_string += "WARN: crm_verify reported warnings at %s:\n" % n
            out_string += open(crm_verify_f).read()
    return out_string


def check_if_log_is_empty():
    for f in find_files_all(constants.HALOG_F, constants.WORKDIR):
        if os.stat(f).st_size == 0:
            logger.warning("Report contains no logs; did you get the right timeframe?")


def check_logs(workdir):
    out_string = ""
    log_list = []
    for l in constants.EXTRA_LOGS.split():
        log_list += find_files_all(os.path.basename(l), workdir)
    if not log_list:
        return out_string

    out_string += "\nLog patterns:\n"
    log_patterns = constants.LOG_PATTERNS.replace(' ', '|')
    for n in constants.NODES.split():
        for f in log_list:
            out_string += '\n'.join(grep(log_patterns, infile=f))
    return out_string


def check_permissions(workdir):
    out_string = ""
    for n in constants.NODES.split():
        permissions_f = os.path.join(workdir, n, constants.PERMISSIONS_F)
        if os.path.isfile(permissions_f) and os.stat(permissions_f).st_size != 0:
            out_string += "Checking problems with permissions/ownership at %s:\n" % n
            out_string += open(permissions_f).read()
    return out_string


def cib_diff(file1, file2):
    """
    check if files have same content in the cluster
    """
    code = 0
    out_string = ""
    tmp_string = ""
    d1 = os.path.dirname(file1)
    d2 = os.path.dirname(file2)
    if (os.path.isfile(os.path.join(d1, "RUNNING")) and
        os.path.isfile(os.path.join(d2, "RUNNING"))) or \
        (os.path.isfile(os.path.join(d1, "STOPPED")) and
         os.path.isfile(os.path.join(d2, "STOPPED"))):
        if shutil.which("crm_diff"):
            code, tmp_string = get_command_info("crm_diff -c -n %s -o %s" % (file1, file2))
            out_string += tmp_string
        else:
            code = 1
            logger.warning("crm_diff(8) not found, cannot diff CIBs")
    else:
        code = 1
        out_string += "can't compare cibs from running and stopped systems\n"
    return code, out_string


def generate_collect_functions():
    """
    Generate function list from collect.py
    """
    return [func for func, _ in getmembers(collect, isfunction) if func.startswith("collect_")]


def compatibility_pcmk():
    get_crm_daemon_dir()
    if not constants.CRM_DAEMON_DIR:
        log_fatal("cannot find pacemaker daemon directory!")
    get_pe_state_dir()
    if not constants.PE_STATE_DIR:
        log_fatal("cannot find pe daemon directory!")
    get_cib_dir()
    if not constants.CIB_DIR:
        log_fatal("cannot find cib daemon directory!")

    constants.PCMK_LIB = os.path.dirname(constants.CIB_DIR)
    logger.debug("setting PCMK_LIB to %s", constants.PCMK_LIB)
    constants.CORES_DIRS = os.path.join(constants.PCMK_LIB, "cores")
    constants.CONF = "/etc/corosync/corosync.conf"
    if os.path.isfile(constants.CONF):
        constants.CORES_DIRS += " /var/lib/corosync"
    constants.B_CONF = os.path.basename(constants.CONF)


def consolidate(workdir, f):
    """
    remove duplicates if files are same, make links instead
    """
    for n in constants.NODES.split():
        if os.path.isfile(os.path.join(workdir, f)):
            os.remove(os.path.join(workdir, n, f))
        else:
            shutil.move(os.path.join(workdir, n, f), workdir)
        os.symlink("../%s" % f, os.path.join(workdir, n, f))


def create_tempfile(time=None):
    random_str = random_string(4)
    try:
        filename = tempfile.mkstemp(suffix=random_str, prefix="tmp.")[1]
    except:
        log_fatal("Can't create file %s" % filename)
    if time:
        os.utime(filename, (time, time))
    return filename


def date():
    return datetime.datetime.now().strftime("%a %b %-d %H:%M:%S CST %Y")


def diff_check(file1, file2):
    out_string = ""
    for f in [file1, file2]:
        if not os.path.isfile(f):
            out_string += "%s does not exist\n" % f
            return (1, out_string)
    if os.path.basename(file1) == constants.CIB_F:
        return cib_diff(file1, file2)
    else:
        return (0, txt_diff(file1, file2))


def get_distro_info() -> str:
    """
    Get distribution information
    """
    res = None
    if os.path.exists(constants.OSRELEASE):
        logger.debug2(f"Using {constants.OSRELEASE} to get distribution info")
        res = re.search("PRETTY_NAME=\"(.*)\"", read_from_file(constants.OSRELEASE))
    elif shutil.which("lsb_release"):
        logger.debug2("Using lsb_release to get distribution info")
        out = crmutils.get_stdout_or_raise_error("lsb_release -d")
        res = re.search("Description:\s+(.*)", out)
    return res.group(1) if res else "Unknown"


def dump_log(logf, from_line, to_line):
    if not from_line:
        return
    return filter_lines(logf, from_line, to_line)


def dump_logset(context: core.Context, logf: str) -> bool:
    """
    Dump the log set into the specified output file
    """
    logf_set = arch_logs(context, logf)
    if not logf_set:
        return False

    newest, oldest = logf_set[0], logf_set[-1]
    middle_set = logf_set[1:-1]
    out_string = ""

    if len(logf_set) == 1:
        out_string += print_logseg(newest, context.from_time, context.to_time)
    else:
        out_string += print_logseg(oldest, context.from_time, 0)
        for f in middle_set:
            out_string += print_logseg(f, 0, 0)
        out_string += print_logseg(newest, 0, context.to_time)

    if out_string:
        outf = os.path.join(context.work_dir, os.path.basename(logf))
        crmutils.str2file(out_string.strip('\n'), outf)
        logger.debug2(f"Dump {logf} into {outf}")

    return True


def events(destdir):
    events_f = os.path.join(destdir, "events.txt")
    out_string = ""
    pattern = '|'.join(constants.EVENT_PATTERNS.split()[1::2])
    halog_f = os.path.join(destdir, constants.HALOG_F)
    if os.path.isfile(halog_f):
        out_string = '\n'.join(grep(pattern, infile=halog_f))
        crmutils.str2file(out_string, events_f)
        for n in constants.NODES.split():
            if os.path.isdir(os.path.join(destdir, n)):
                events_node_f = os.path.join(destdir, n, "events.txt")
                out_string = '\n'.join(grep(" %s " % n, infile=events_f))
                crmutils.str2file(out_string, events_node_f)
    else:
        for n in constants.NODES.split():
            halog_f = os.path.join(destdir, n, constants.HALOG_F)
            if not os.path.isfile(halog_f):
                continue
            out_string = '\n'.join(grep(pattern, infile=halog_f))
            crmutils.str2file(out_string, os.path.join(destdir, n, "events.text"))


def find_decompressor(log_file):
    decompressor = "cat"
    if re.search("bz2$", log_file):
        decompressor = "bzip2 -dc"
    elif re.search("gz$", log_file):
        decompressor = "gzip -dc"
    elif re.search("xz$", log_file):
        decompressor = "xz -dc"
    return decompressor


def find_files_in_timespan(context: core.Context, target_dir_list: List[str]) -> List[str]:
    """
    Get a list of files in the target directories with creation time in the timespan
    """
    file_list = []

    for target_dir in target_dir_list:
        if not os.path.isdir(target_dir):
            raise ValueError(f"'{target_dir}' is not a valid directory")

        for root, dirs, files in os.walk(target_dir):
            for file in files:
                file_path = os.path.join(root, file)
                file_stat = os.stat(file_path)
                create_time = file_stat.st_ctime

                if context.from_time <= file_stat.st_ctime < context.to_time:
                    file_list.append(file_path)

    return file_list


def find_files_all(name, path):
    result = []
    for root, dirs, files in os.walk(path):
        if name in files:
            result.append(os.path.join(root, name))
    return result


def find_first_timestamp(data: List[str]) -> float:
    """
    Find the first timestamp in the given list of log line
    """
    for line in data:
        timestamp = get_timestamp(line)
        if timestamp:
            return timestamp
    return None


def filter_lines(data: str, from_line: int, to_line: int) -> str:
    """
    Filter lines from the given data based on the specified line range.
    """
    lines = data.split('\n')
    filtered_lines = [
        line + '\n' 
        for count, line in enumerate(lines, start=1) 
        if from_line <= count <= to_line
    ]
    return ''.join(filtered_lines)


def determin_log_format(data: str) -> str:
    """
    Determines the log format based on the given log line
    """
    for line in head(constants.CHECK_LOG_LINES, data):
        _list = line.split()
        # rfc5424 format:
        # 2003-10-11T22:14:15.003Z mymachine.example.com su
        if crmutils.parse_time(_list[0], quiet=True):
            return "rfc5424"
        # syslog format:
        # Feb 12 18:30:08 15sp1-1 kernel: e820: BIOS-provided physical RAM map:
        if len(_list) > 2 and crmutils.parse_time(' '.join(_list[0:3]), quiet=True):
            return "syslog"
        if len(_list) > 1 and crmutils.parse_time(_list[1], quiet=True):
            return "legacy"
    return None


def find_log():
    """
    first try syslog files, if none found then use the
    logfile/debugfile settings
    """
    if constants.EXTRA_LOGS:
        for l in constants.EXTRA_LOGS.split():
            if os.path.isfile(l):
                return l

        tmp_f = os.path.join(constants.WORKDIR, constants.JOURNAL_F)
        if os.path.isfile(tmp_f):
            return tmp_f

        for l in constants.PCMK_LOG.split():
            if os.path.isfile(l):
                return l

    if constants.HA_DEBUGFILE:
        logger.debug("will try with %s", constants.HA_DEBUGFILE)
    return constants.HA_DEBUGFILE


def findln_by_timestamp(data: str, given_timestamp: float) -> int:
    """
    Get line number of the specific time stamp
    """
    data_list = data.split('\n')
    first, last = 1, len(data_list)

    while first <= last:
        middle = (last + first) // 2
        middle_timestamp = get_timestamp(data_list[middle - 1])

        if not middle_timestamp:
            # Can't extract time in middle line; try the next one
            trycnt = 10
            while trycnt > 0 and middle < last:
                middle_timestamp = get_timestamp(data_list[middle])
                if middle_timestamp:
                    break
                middle += 1
                trycnt -= 1

        if not middle_timestamp:
            return None
        if middle_timestamp > given_timestamp:
            last = middle - 1
        elif middle_timestamp < given_timestamp:
            first = middle + 1
        else:
            return middle

    return None


def find_binary_for_core(corefile):
    """
    Given a core file, try to find the
    binary that generated it
    Returns a path or None
    """
    def findbin(fname):
        def isexec(filename):
            return os.path.isfile(filename) and os.access(filename, os.X_OK)
        bindirs = [constants.HA_BIN, constants.CRM_DAEMON_DIR]
        if shutil.which(fname):
            return fname
        else:
            for d in bindirs:
                if d is None:
                    continue
                testpath = os.path.join(d, fname)
                if isexec(testpath):
                    return testpath
        return None
    if shutil.which("cat"):
        random_binary = "cat"
    lines = [l for l in get_command_info_timeout(["gdb", random_binary, corefile]).splitlines() if "Core was generated by" in l]
    binname = None
    if len(lines) > 0:
        m = re.search(r"generated by .([^']+)", )
        if m:
            fname = m.group(1)
            binname = findbin(fname)
    if binname is not None:
        logger.debug("found the program at %s for core %s", testpath, corefile)
    else:
        logger.warning("Could not find the program path for core %s", corefile)
    return binname


def print_core_backtraces(flist):
    """
    Use gdb to get backtrace from core files.
    flist: names of core files to check
    """
    if not shutil.which("gdb"):
        logger.warning("Please install gdb to get backtraces")
        return
    for corefile in flist:
        absbinpath = find_binary_for_core(corefile)
        if absbinpath is None:
            continue
        get_debuginfo(absbinpath, corefile)
        bt_opts = os.environ.get("BT_OPTS", "thread apply all bt full")
        print("====================== start backtrace ======================")
        print(get_command_info_timeout(["ls", "-l", corefile]))
        print(get_command_info_timeout(["gdb", "-batch", "-n", "-quiet",
                                        "-ex", bt_opts, "-ex", "quit",
                                        absbinpath, corefile]))
        print("======================= end backtrace =======================")


def get_cib_dir():
    try:
        constants.CIB_DIR = crmsh.config.path.crm_config
    except:
        return
    if not os.path.isdir(constants.CIB_DIR):
        constants.CIB_DIR = None


def get_crm_daemon_dir():
    try:
        constants.CRM_DAEMON_DIR = crmsh.config.path.crm_daemon_dir
    except:
        return
    if not os.path.isdir(constants.CRM_DAEMON_DIR) or \
       not any(is_exec(os.path.join(constants.CRM_DAEMON_DIR, cmd)) for cmd in ["crmd", "pacemaker-controld"]):
        constants.CRM_DAEMON_DIR = None


def get_dirname(path):
    tmp = os.path.dirname(path)
    if not tmp:
        tmp = "."
    return tmp


def get_local_ip():
    local_ip = []
    ip_pattern = "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
    for line in grep(ip_pattern, incmd="corosync-cfgtool -s"):
        local_ip.append(line.split()[2])
    return local_ip


def get_nodes():
    """
    find nodes for this cluster
    """
    nodes = []
    # 1. set by user?
    if constants.USER_NODES:
        nodes = constants.USER_NODES.split()
    # 2. running crm
    elif crmutils.is_process("pacemaker-controld") or crmutils.is_process("crmd"):
        cmd = "crm node server"
        nodes = get_command_info(cmd)[1].strip().split('\n')
    # 3. if the cluster's stopped, try the CIB
    else:
        cmd = r"(CIB_file=%s/%s crm node server)" % (constants.CIB_DIR, constants.CIB_F)
        nodes = get_command_info(cmd)[1].strip().split('\n')

    return nodes


def get_peer_ip():
    local_ip = get_local_ip()
    peer_ip = []
    ip_pattern = "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
    for line in grep("runtime.*.srp.*.ip", incmd="corosync-cmapctl"):
        for ip in re.findall(ip_pattern, line):
            if ip not in local_ip:
                peer_ip.append(ip)
    return peer_ip


def get_pkg_mgr() -> str:
    """
    Get the package manager available in the system
    """
    pkg_mgr_candidates = {
        "rpm": "rpm",
        "dpkg": "deb",
        "pkg_info": "pkg_info",
        "pkginfo": "pkginfo"
    }
    for pkg_mgr, pkg_mgr_name in pkg_mgr_candidates.items():
        if shutil.which(pkg_mgr):
            return pkg_mgr_name

    logger.warning("Unknown package manager!")
    return ""


def get_timestamp(line: str) -> float:
    """
    Get timestamp for the given line
    """
    stamp_type = constants.STAMP_TYPE
    timestamp = None

    if stamp_type == "rfc5424":
        timestamp= crmutils.parse_to_timestamp(line.split()[0], quiet=True)
    elif stamp_type == "syslog":
        timestamp = crmutils.parse_to_timestamp(' '.join(line.split()[0:3]), quiet=True)
    elif stamp_type == "legacy":
        timestamp = crmutils.parse_to_timestamp(line.split()[1], quiet=True)

    return timestamp


def head(n, indata):
    return indata.split('\n')[:n]


def is_conf_set(option, subsys=None):
    subsys_start = 0
    if os.path.isfile(constants.CONF):
        data = read_from_file(constants.CONF)
        for line in data.split('\n'):
            if re.search("^\s*subsys\s*:\s*%s$" % subsys, line):
                subsys_start = 1
            if subsys_start == 1 and re.search("^\s*}", line):
                subsys_start = 0
            if re.match("^\s*%s\s*:\s*(on|yes)$" % option, line):
                if not subsys or subsys_start == 1:
                    return True
    return False


def is_exec(filename):
    return os.path.isfile(filename) and os.access(filename, os.X_OK)


def is_our_log(context: core.Context, logf: str) -> int:
    """
    Check if the log contains a piece of our segment
    """
    data = read_from_file(logf)
    if not data:
        return LogType.EMPTY
    stamp_type = determin_log_format(data)
    if not stamp_type:
        return LogType.IRREGULAR
    constants.STAMP_TYPE = stamp_type

    first_time = find_first_timestamp(head(10, data))
    last_time = find_first_timestamp(tail(10, data))
    from_time = context.from_time
    to_time = context.to_time

    if (not first_time) or (not last_time):
        return LogType.IRREGULAR
    if from_time > last_time:
        return LogType.BEFORE_TIMESPAN
    if from_time >= first_time or to_time >= first_time:
        return LogType.GOOD
    return LogType.AFTER_TIMESPAN


def log_size(logf, outf):
    l_size = os.stat(logf).st_size + 1
    out_string = "%s %d" % (logf, l_size)
    crmutils.str2file(out_string, outf)


def make_temp_dir():
    dir_path = r"/tmp/.crm_report.workdir.%s" % random_string(6)
    tmpfiles._mkdir(dir_path)
    return dir_path


def mktemplate(argv):
    """
    description template, editing, and other notes
    """
    workdir = constants.WORKDIR
    out_string = constants.EMAIL_TMPLATE.format("%s" % date(), ' '.join(argv[1:]))
    sysinfo_f = os.path.join(workdir, constants.SYSINFO_F)
    if os.path.isfile(sysinfo_f):
        out_string += "Common saystem info found:\n"
        with open(sysinfo_f, 'r') as f:
            out_string += f.read()
    else:
        for n in constants.NODES.split():
            sysinfo_node_f = os.path.join(workdir, n, constants.SYSINFO_F)
            if os.path.isfile(sysinfo_node_f):
                out_string += "System info %s:\n" % n
                out_string += sed_inplace(sysinfo_node_f, r'^', '    ')
                out_string += "\n"
    crmutils.str2file(out_string, os.path.join(workdir, constants.DESCRIPTION_F))


def print_log(logf):
    """
    print part of the log
    """
    cat = find_decompressor(logf)
    cmd = "%s %s" % (cat, logf)
    out = crmutils.get_stdout(cmd)
    return out


def print_logseg(log_file: str, from_time: float, to_time: float) -> str:
    """
    Print the log segment specified by the given timestamps
    """
    data = read_from_file(log_file)

    if from_time == 0:
        from_line = 1
    else:
        from_line = findln_by_timestamp(data, from_time)
        if from_line is None:
            return ""

    if to_time == 0:
        to_line = len(data.split('\n'))
    else:
        to_line = findln_by_timestamp(data, to_time)
        if to_line is None:
            return ""

    logger.debug("Including segment [%d-%d] from %s", from_line, to_line, log_file)
    return filter_lines(data, from_line, to_line)


def random_string(num):
    tmp = []
    if crmutils.is_int(num) and num > 0:
        s = string.ascii_letters + string.digits
        tmp = random.sample(s, num)
    return ''.join(tmp)


def sanitize():
    """
    replace sensitive info with '****'
    """
    logger.debug("Check or replace sensitive info from cib, pe and log files")

    get_sensitive_key_value_list()

    work_dir = constants.WORKDIR
    file_list = []
    for (dirpath, dirnames, filenames) in os.walk(work_dir):
        for _file in filenames:
            file_list.append(os.path.join(dirpath, _file))

    for f in [item for item in file_list if os.path.isfile(item)]:
        rc = sanitize_one(f)
        if rc == 1:
            logger.warning("Some PE/CIB/log files contain possibly sensitive data")
            logger.warning("Using \"-s\" option can replace sensitive data")
            break


def sanitize_one(in_file):
    """
    Open the file, replace sensitive string and write back
    """
    data = read_from_file(in_file)
    if not data:
        return
    if not include_sensitive_data(data):
        return
    if not constants.DO_SANITIZE:
        return 1
    logger.debug("Replace sensitive info for %s", in_file)
    write_to_file(in_file, sub_sensitive_string(data))


def parse_sanitize_rule(rule_string):
    for rule in rule_string.split():
        if ':' in rule:
            key, value = rule.split(':')
            if value != "raw":
                log_fatal("For sanitize_pattern {}, option should be \"raw\"".format(key))
            constants.SANITIZE_RULE_DICT[key] = value
        else:
            constants.SANITIZE_RULE_DICT[rule] = None


def sed_inplace(filename, pattern, repl):
    out_string = ""

    pattern_compiled = re.compile(pattern)
    with open(filename, 'r') as fd:
        for line in fd:
            out_string += pattern_compiled.sub(repl, line)

    return out_string


def str_to_bool(v):
    return v.lower() in ["true"]


def tail(n, indata):
    return indata.split('\n')[-n:]


def touch_r(src, dst):
    """
    like shell command "touch -r src dst"
    """
    if not os.path.exists(src):
        logger.warning("In touch_r function, %s not exists", src)
        return
    stat_info = os.stat(src)
    os.utime(dst, (stat_info.st_atime, stat_info.st_mtime))


def txt_diff(file1, file2):
    return get_command_info("diff -bBu %s %s" % (file1, file2))[1]


class Package:
    """
    A class to retrieve package versions and verify packages
    on various distros
    """
    def __init__(self, packages: str) -> None:
        self.pkg_type = get_pkg_mgr()
        self.packages = packages
        self.installed = ""

    def pkg_ver_deb(self):
        #TODO move impl here!!!!
        pass

    def pkg_ver_pkg_info(self):
        pass

    def pkg_ver_pkginfo(self):
        pass

    def pkg_ver_rpm(self) -> str:
        _, out, err = crmutils.get_stdout_stderr(f"rpm -q {self.packages}")
        return '\n'.join([line for line in out.splitlines() if "not installed" not in line])

    def version(self) -> str:
        if not self.pkg_type:
            return ""
        self.installed = getattr(self, f"pkg_ver_{self.pkg_type}")()
        return self.installed

    def verify_deb(self):
        #TODO move impl here!!!!
        pass

    def verify_pkg_info(self):
        pass

    def verify_pkginfo(self):
        pass

    def verify_rpm(self) -> str:
        res = ""
        for pack in self.installed.split():
            cmd = f"rpm --verify {pack}|grep -v 'not installed'"
            code, out = crmutils.get_stdout(cmd)
            if code != 0 and out:
                res = f"For package {pack}:\n"
                res += out + "\n"
        return res

    def verify(self) -> str:
        if not self.pkg_type:
            return ""
        if not self.installed:
            self.version()
        return getattr(self, f"verify_{self.pkg_type}")()


def get_open_method(infile):
    """
    Get the appropriate file open method based on the file extension
    """
    file_type_open_dict = {
        "gz": gzip.open,
        "bz2": bz2.open,
        "xz": lzma.open
    }
    file_ext = infile.split('.')[-1]
    return file_type_open_dict.get(file_ext, open)


def read_from_file(infile):
    """
    Read content from a file
    """
    _open = get_open_method(infile)
    try:
        with _open(infile, 'rt', encoding='utf-8', errors='replace') as f:
            data = f.read()
    except Exception as err:
        logger.error("When reading file \"%s\": %s", infile, str(err))
        return None

    return crmutils.to_ascii(data)


def write_to_file(tofile, data):
    _open = get_open_method(tofile)
    with _open(tofile, 'w') as f:
        if _open == open:
            f.write(data)
        else:
            f.write(data.encode('utf-8'))


def get_sensitive_key_value_list():
    """
    For each defined sanitize rule, get the sensitive value or key list
    """
    for key, value in constants.SANITIZE_RULE_DICT.items():
        try:
            if value == "raw":
                constants.SANITIZE_VALUE_RAW += extract_sensitive_value_list(key)
            else:
                constants.SANITIZE_VALUE_CIB += extract_sensitive_value_list(key)
                constants.SANITIZE_KEY_CIB.append(key.strip('.*?')+'.*?')
        except (FileNotFoundError, EOFError) as e:
            logger.warning(e)


def extract_sensitive_value_list(rule):
    """
    Extract sensitive value from cib.xml
    """
    cib_file = os.path.join(constants.WORKDIR, constants.WE, constants.CIB_F)
    if not os.path.exists(cib_file):
        raise FileNotFoundError("File {} was not collected".format(constants.CIB_F))

    with open(cib_file) as fd:
        data = fd.read()
    if not data:
        raise EOFError("File {} is empty".format(cib_file))

    value_list = re.findall(r'name="({})" value="(.*?)"'.format(rule.strip('?')+'?'), data)
    return [value[1] for value in value_list]


def include_sensitive_data(data):
    """
    Check whether contain sensitive data
    """
    if constants.SANITIZE_VALUE_RAW or constants.SANITIZE_VALUE_CIB:
        return True
    return False


def sub_sensitive_string(data):
    """
    Do the replace job

    For the raw sanitize_pattern option, replace exactly the value
    For the key:value nvpair sanitize_pattern, replace the value in which line contain the key
    """
    result = data
    if constants.SANITIZE_VALUE_RAW:
        result = re.sub(r'\b({})\b'.format('|'.join(constants.SANITIZE_VALUE_RAW)), "******", data)
    if constants.SANITIZE_VALUE_CIB:
        result = re.sub('({})({})'.format('|'.join(constants.SANITIZE_KEY_CIB), '|'.join(constants.SANITIZE_VALUE_CIB)), '\\1******', result)
    return result


def parse_to_timestamp(time: str) -> Optional[float]:
    """
    Parses the input time string and converts it to a timestamp.
    """
    time_format_mapping = {
            'Y': 'days', # datetime.timedelta don't support years
            'm': 'days', # datetime.timedelta don't support months
            'd': 'days',
            'H': 'hours',
            'M': 'minutes'
            }
    # Both '-12H' and '12h' mean 12 hours before
    res = re.match("^-?([1-9][0-9]*)([YmdHM])$", time)
    if res:
        number_str, flag = res.groups()
        if flag == "Y":
            number = 365 * int(number_str)
        elif flag == "m":
            number = 30 * int(number_str)
        else:
            number = int(number_str)
        time_unit = time_format_mapping[flag]
        timedelta = datetime.timedelta(**{time_unit: number})
        time = (datetime.datetime.now() - timedelta).strftime(constants.TIME_FORMAT)
    res = crmutils.parse_to_timestamp(time, quiet=True)
    if res:
        return res
    else:
        logger.error(f"Invalid time string '{time}'")
        logger.error('Try these format like: 2pm; 1:00; "2019/9/5 12:30"; "09-Sep-07 2:00"')
        return None


def ts_to_str(timestamp: float) -> str:
    return dt_to_str(ts_to_dt(timestamp))


def ts_to_dt(timestamp: float) -> datetime.datetime:
    dt = crmutils.timestamp_to_datetime(timestamp)
    dt += tz.tzlocal().utcoffset(dt)
    return dt


def dt_to_str(dt: datetime.datetime, form: str = constants.TIME_FORMAT) -> str:
    return dt.strftime(form)


def now(form: str = constants.TIME_FORMAT) -> str:
    return dt_to_str(datetime.datetime.now(), form=form)


def dirname(path: str) -> str:
    _dir = os.path.dirname(path)
    return _dir or "."


def get_cmd_output(cmd: str, timeout: int = None) -> str:
    """
    Get the output of a command
    """
    out_str = ""
    _, out, err = crmutils.get_stdout_stderr(cmd, timeout=timeout)
    if out:
        out_str += f"{out}\n"
    if err:
        out_str += f"{err}\n"
    return out_str


def get_timespan_str(context: core.Context) -> str:
    from_time_str = ts_to_str(context.from_time)
    to_time_str = ts_to_str(context.to_time)
    return f"{from_time_str} - {to_time_str}"
# vim:ts=4:sw=4:et:
