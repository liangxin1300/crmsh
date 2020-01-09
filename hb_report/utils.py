import socket
import sys
import re
import datetime
import string
import random
import os
import tempfile
import contextlib
import tarfile
import subprocess
import threading
from dateutil import tz

import crmsh.config
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from hb_report import const, core
from crmsh import msg as crmmsg
from crmsh import utils as crmutils


@contextlib.contextmanager
def stdchannel_redirected(stdchannel, dest_filename):
    """
    A context manager to temporarily redirect stdout or stderr
    e.g.:
    with stdchannel_redirected(sys.stderr, os.devnull):
        if compiler.has_function('clock_gettime', libraries=['rt']):
            libraries.append('rt')
    """

    try:
        oldstdchannel = os.dup(stdchannel.fileno())
        dest_file = open(dest_filename, 'w')
        os.dup2(dest_file.fileno(), stdchannel.fileno())
        yield

    finally:
        if oldstdchannel is not None:
            os.dup2(oldstdchannel, stdchannel.fileno())
        if dest_file is not None:
            dest_file.close()


def parse_time(timeline):
    with stdchannel_redirected(sys.stderr, os.devnull):
        try:
            res = crmutils.parse_time(timeline)
        except:
            return None
        return res


def log_info(msg):
    crmmsg.common_info("{}#{}: {}".format(me(), get_role(), msg))


def log_warning(msg):
    crmmsg.common_warn("{}#{}: {}".format(me(), get_role(), msg))


def log_error(msg):
    crmmsg.common_err("{}#{}: {}".format(me(), get_role(), msg))


def log_fatal(msg):
    crmmsg.common_err("{}#{}: {}".format(me(), get_role(), msg))
    sys.exit(1)


def get_role():
    if core.is_collector():
        return "Collector"
    else:
        return "Master"


def log_debug1(msg):
    if core.ctx.debug >= 1:
        crmsh.config.core.debug = "yes"
        crmmsg.common_debug("{}#{}: {}".format(me(), get_role(), msg))


def log_debug2(msg):
    if core.ctx.debug > 1:
        crmsh.config.core.debug = "yes"
        crmmsg.common_debug("{}#{}: {}".format(me(), get_role(), msg))


def get_stamp_legacy(line):
    return parse_time(line.split()[1])


def get_stamp_rfc5424(line):
    return parse_time(line.split()[0])


def get_stamp_syslog(line):
    return parse_time(' '.join(line.split()[0:3]))


def find_stamp_type(line):
    _type = None
    if get_stamp_syslog(line):
        _type = "syslog"
    elif get_stamp_rfc5424(line):
        _type = "rfc5424"
    elif get_stamp_legacy(line):
        _type = "legacy"
    log_msg = "the log file is in the {} format".format(_type)
    if _type == "legacy":
        log_msg += "(please consider switching to syslog format)"
    log_debug2(log_msg)
    return _type


def get_ts(line):
    ts = None
    if not hasattr(core.ctx, "stamp_type"):
        core.ctx.stamp_type = find_stamp_type(line)
    _type = core.ctx.stamp_type
    if _type == "rfc5424":
        ts = crmutils.parse_to_timestamp(line.split()[0])
    if _type == "syslog":
        ts = crmutils.parse_to_timestamp(' '.join(line.split()[0:3]))
    if _type == "legacy":
        ts = crmutils.parse_to_timestamp(line.split()[1])
    return ts


def line_time(logf, line_num):
    ts = None
    with open(logf, 'r', encoding='utf-8', errors='replace') as fd:
        line_res = head(line_num, fd.read())
        if line_res:
            ts = get_ts(line_res[-1])
    return ts


def findln_by_time(logf, tm):
    tmid = None
    first = 1
    last = sum(1 for l in open(logf, 'r', encoding='utf-8', errors='replace'))

    while first <= last:
        mid = (last+first)//2
        trycnt = 10
        while trycnt > 0:
            res = line_time(logf, mid)
            if res:
                tmid = int(res)
                break
            log_debug2("Cannot extract time: %s:%d; will try the next one" % (logf, mid))
            trycnt -= 1
            # shift the whole first-last segment
            prevmid = mid
            while prevmid == mid:
                first -= 1
                if first < 1:
                    first = 1
                last -= 1
                if last < first:
                    last = first
                prevmid = mid
                mid = (last+first)//2
                if first == last:
                    break
        if not tmid:
            log_warning("Giving up on log...")
            return None
        if int(tmid) > tm:
            last = mid - 1
        elif int(tmid) < tm:
            first = mid + 1
        else:
            break
    return mid


def find_first_ts(data):
    ts = None
    for line in data:
        ts = get_ts(line)
        if ts:
            break
    return ts


def head(n, indata):
    return indata.split('\n')[:n]


def tail(n, indata):
    return indata.split('\n')[-n:]


def is_2dlist(aList):
    return all([isinstance(sublist, list) for sublist in aList])


def parse_to_timestamp(time):
    if re.search("^-[1-9][0-9]*[YmdHM]$", time):
        number = int(re.findall("[1-9][0-9]*", time)[0])
        if re.search("^-[1-9][0-9]*Y$", time):
            timedelta = datetime.timedelta(days = number * 365)
        if re.search("^-[1-9][0-9]*m$", time):
            timedelta = datetime.timedelta(days = number * 30)
        if re.search("^-[1-9][0-9]*d$", time):
            timedelta = datetime.timedelta(days = number)
        if re.search("^-[1-9][0-9]*H$", time):
            timedelta = datetime.timedelta(hours = number)
        if re.search("^-[1-9][0-9]*M$", time):
            timedelta = datetime.timedelta(minutes = number)
        time = (datetime.datetime.now() - timedelta).strftime("%Y-%m-%d %H:%M")

    res = crmutils.parse_to_timestamp(time)
    if res:
        return res
    else:
        log_fatal('''Try these format like: 2pm; 1:00; "2019/9/5 12:30"; "09-Sep-07 2:00"'''.format(time))


def me():
    return socket.gethostname()


def zip_nested(nested):
    return [x for sublist in nested for x in sublist]


class Package(object):
    def __init__(self, pkgs):
        self.for_rpm = True
        if get_pkg_mgr() != "rpm":
            self.for_rpm = False
            log_warning("The package manager is %s, not support for now" % p)
        else:
            self.pkgs = installed_pkgs(pkgs)

    def version(self):
        if not self.for_rpm:
            return ""
        return pkg_ver_rpm(self.pkgs)

    def verify(self):
        if not self.for_rpm:
            return ""
        return verify_rpm(self.pkgs)


def get_pkg_mgr():
    for p in ["rpm", "dpkg", "pkg_info", "pkginfo"]:
        if which(p):
            return p
    else:
        log_warning("Unknown package manager!")
        return None


def installed_pkgs(packages):
    res = []
    for pkg in packages.split():
        rc, _ = crmutils.get_stdout("rpm -q %s" % pkg)
        if rc != 0:
            continue
        res.append(pkg)
    return res


def pkg_ver_rpm(packages):
    res = "Name | Version-Release | Distribution | Arch\n-----\n"
    cmd = "rpm -q --qf '%{name} | %{version}-%{release} | %{distribution} | %{arch}'"

    for pkg in packages:
        rc, out = crmutils.get_stdout("{} {}".format(cmd, pkg))
        if rc == 0 and out:
            res += out + '\n'
    return res


def verify_rpm(packages):
    res = ""
    for pkg in packages:
        rc, _, err = crmutils.get_stdout_stderr("rpm --verify {}".format(pkg))
        if rc != 0 and err:
            log_warning(err)
            res += "Verify {} error: {}\n".format(pkg, err)
    else:
        res = "All packages verify successfully\n"
        log_debug2(res)
    return res


def which(prog):
    return crmutils.get_stdout_stderr("which {}".format(prog))[0] == 0


def random_string(num):
    if not isinstance(num, int):
        raise TypeError('expected int')
    if num <= 0:
        raise ValueError('expected positive int')
    s = string.ascii_letters + string.digits
    return ''.join(random.sample(s, num))


def _mkdir(directory):
    if not os.path.isdir(directory):
        try:
            os.makedirs(directory)
        except OSError as err:
            log_fatal("Failed to create directory: %s" % (err))


def make_temp_dir():
    dir_path = '/tmp/{}.{}'.format(const.WORKDIR_PREFIX, random_string(6))
    _mkdir(dir_path)
    return dir_path


def make_temp_file(time=None):
    random_str = random_string(4)
    try:
        filename = tempfile.mkstemp(suffix=random_str, prefix="tmp.")[1]
    except:
        log_fatal("Can't create file {}".format(filename))
    if time:
        os.utime(filename, (time, time))
    return filename


def dirname(path):
    tmp = os.path.dirname(path)
    return tmp if tmp else "."


def ts_to_dt(timestamp):
    """
    timestamp convert to datetime; consider local timezone
    """
    dt = crmutils.timestamp_to_datetime(timestamp)
    dt += tz.tzlocal().utcoffset(dt)
    return dt


def now(form="%Y-%m-%d %H:%M"):
    return dt_to_str(datetime.datetime.now(), form=form)


def dt_to_str(dt, form="%Y-%m-%d %H:%M"):
    if not isinstance(dt, datetime.datetime):
        raise TypeError("expected <class 'datetime.datetime'>")
    return dt.strftime(form)


def get_stdout_stderr_timeout(cmd, input_s=None, shell=True, timeout=5):
    '''
    Run a cmd, return (rc, stdout, stderr)
    '''
    proc = subprocess.Popen(cmd,
                            shell=shell,
                            stdin=input_s and subprocess.PIPE or None,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    try:
        stdout_data, stderr_data = proc.communicate(input_s, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        log_error("Timeout running \"{}\"".format(cmd))
        return (-1, None, None)
    return (proc.returncode,
            crmutils.to_ascii(stdout_data).strip(),
            crmutils.to_ascii(stderr_data).strip())


def get_data_from_tarfile(logf):
    with tarfile.open(logf, 'r') as tar:
        for member in tar.getmembers():
            f = tar.extractfile(member)
            if f:
                return crmutils.to_ascii(f.read())
            else:
                return None


def data_from_all_types_file(in_file):
    if tarfile.is_tarfile(in_file):
        return get_data_from_tarfile(in_file)
    with open(in_file, 'r', encoding='utf-8', errors="replace") as fd:
        return fd.read()


def is_sensitive_string(in_string, pattern):
    pattern_string = re.sub(" ", "|", pattern)
    for line in crmutils.to_ascii(in_string).split('\n'):
        if re.search('name="{}"'.format(pattern_string[1:]), line):
            return True
    return False


def is_sensitive_file(in_file):
    data = data_from_all_types_file(in_file)
    if not data:
        return False
    if is_sensitive_string(data):
        return True
    else:
        return False


def filter_lines(logf, from_line, to_line):
    out_string = ""
    count = 1
    with open(logf, 'r', encoding='utf-8', errors='replace') as f:
        for line in f.readlines():
            if count >= from_line and count <= to_line:
                out_string += line
            if count > to_line:
                break
            count += 1
    return out_string

'''
def rpm_version(pkg):
    cmd = "rpm -qi {}|awk -F':' '/Version/{print $2}'".format(pkg)
    rc, out = utils.crmutils.get_stdout(cmd)
    if rc == 0:
        return out.lstrip()
    else:
        return None
'''


def touch_file(filename):
    open(filename, 'w').close()


def find_files(context, find_dirs):
    res = []
    from_time = context.from_time
    to_time = context.to_time

    from_stamp = make_temp_file(from_time)
    context.add_tempfile(from_stamp)
    findexp = "-newer %s" % from_stamp
    if to_time > 0:
        to_stamp = make_temp_file(to_time)
        context.add_tempfile(to_stamp)
        findexp += " ! -newer %s" % to_stamp

    cmd = r"find %s -type f %s" % (find_dirs, findexp)
    rc, out, _ = crmutils.get_stdout_stderr(cmd)
    if rc == 0 and out:
        res = out.split('\n')
    return res


def touch_r(src, dst):
    '''
    like shell command "touch -r src dst"
    '''
    if not os.path.exists(src):
        log_warning("In touch_r function, %s not exists" % src)
        return
    stat_info = os.stat(src)
    os.utime(dst, (stat_info.st_atime, stat_info.st_mtime))
