import os
import re
import datetime
import subprocess
import gzip
import bz2
import lzma
from dateutil import tz

from crmsh import log
from crmsh.report import const, core
from crmsh import utils as crmutils


logger = log.setup_report_logger(__name__)


class CRMReportError(Exception):
    """
    Define an exception to terminate crm report process
    """


def ts_to_dt(timestamp):
    """
    Convert from UNIX timestamp to datetime
    Consider local timezone
    """
    dt = crmutils.timestamp_to_datetime(timestamp)
    dt += tz.tzlocal().utcoffset(dt)
    return dt


def now(form=const.TIME_FORMAT):
    """
    Get current time string
    """
    return dt_to_str(datetime.datetime.now(), form=form)


def dt_to_str(dt, form=const.TIME_FORMAT):
    """
    Convert datetime to string
    """
    return dt.strftime(form)


def ts_to_str(ts, form=const.TIME_FORMAT):
    """
    Convert from UNIX timestamp to string
    """
    return dt_to_str(ts_to_dt(ts), form=form)


def timedelta_inst(number, flag):
    """
    Return timedelta instance
    number: number of time
    flag: time type, valid in range: YmdHM
    """
    time_range = list(const.TIME_TYPE)
    if flag not in time_range:
        raise CRMReportError("Wrong time type \"{}\", should be in {}".format(flag, time_range))

    if flag == 'Y':
        core.context.delta_time_str = "{} Year{}".format(number, "s" if number > 1 else "")
        return datetime.timedelta(days = number * 365)
    if flag == 'm':
        core.context.delta_time_str = "{} Month{}".format(number, "s" if number > 1 else "")
        return datetime.timedelta(days = number * 30)
    if flag == 'd':
        core.context.delta_time_str = "{} Day{}".format(number, "s" if number > 1 else "")
        return datetime.timedelta(days = number)
    if flag == 'H':
        core.context.delta_time_str = "{} Hour{}".format(number, "s" if number > 1 else "")
        return datetime.timedelta(hours = number)
    if flag == 'M':
        core.context.delta_time_str = "{} Minute{}".format(number, "s" if number > 1 else "")
        return datetime.timedelta(minutes = number)


def parse_to_timestamp(time_str):
    """
    Return UNIX timestamp in seconds
    """
    res = re.match(const.DELTA_TIME_REG, time_str)
    if res:
        number_str, flag = res.groups()
        delta_inst = timedelta_inst(int(number_str), flag)
        time_str = (datetime.datetime.now() - delta_inst).strftime(const.TIME_FORMAT)
    else:
        core.context.delta_time_str = None

    res = crmutils.parse_to_timestamp(time_str)
    if res:
        return res
    raise CRMReportError('Wrong time format: \"{}\". Try these format like: 2pm; 1:00; "2019/9/5 12:30"; "09-Sep-07 2:00"'.format(time_str))


def unique_list(sequence):
    """
    Got the list with unique items
    """
    seen = set()
    return [x for x in sequence if not (x in seen or seen.add(x))]


def get_rpm_info(packages):
    """
    Given rpm pakage names, return rpm info
    """
    output = "Name | Version-Release | Distribution | Arch\n-----\n"
    cmd = "rpm -q --qf '%{name} | %{version}-%{release} | %{distribution} | %{arch}\n'"

    _, out, _ = crmutils.get_stdout_stderr("{} {}".format(cmd, packages))
    for line in out.split('\n'):
        if re.search('not installed', line):
            continue
        output += line + '\n'
    return output


def verify_rpm(packages):
    """
    Verify rpm packages
    """
    output = ""
    _, out, err = crmutils.get_stdout_stderr("rpm --verify {}".format(packages))
    if err:
        logger.error(err)
        return output
    if out:
        for line in out.split('\n'):
            if re.search('not installed', line):
                continue
            output += line + '\n'
    if not output:
        output = "All packages verify successfully\n"
    return output


def distro_info():
    """
    Get distro information
    """
    res = None
    if os.path.exists(const.OSRELEASE):
        logger.debug("Using {} to get distribution info".format(const.OSRELEASE))
        res = re.search("PRETTY_NAME=\"(.*)\"", read_from_file(const.OSRELEASE))
    elif which("lsb_release"):
        logger.debug("Using lsb_release to get distribution info")
        out = get_stdout_or_raise_error("lsb_release -d")
        res = re.search("Description:\s+(.*)", out)
    return res.group(1) if res else "Unknown"


def which(prog):
    rc, _, _ = crmutils.get_stdout_stderr("which {}".format(prog))
    return rc == 0


def get_stdout_stderr_timeout(cmd, input_s=None, shell=True, timeout=5):
    '''
    Run a cmd with timeout, return (rc, stdout, stderr)
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
        logger.error("Timeout running \"%s\"", cmd)
        return (-1, None, None)
    return (proc.returncode, crmutils.to_ascii(stdout_data), crmutils.to_ascii(stderr_data))


def find_files(find_dir):
    """
    Find file list in the given timespan
    """
    file_list = []
    for root, _, files in os.walk(find_dir):
        for name in files:
            filename = os.path.join(root, name)
            mtime = os.stat(filename).st_mtime
            if mtime >= core.context.from_time and mtime <= core.context.to_time:
                file_list.append(filename)
    return file_list


def touch_file(filename):
    open(filename, 'w').close()


def get_open_method(infile):
    """
    Choose open method for different files, default is open
    """
    file_type_open_dict = {
            "gz": gzip.open,
            "bz2": bz2.open,
            "xz": lzma.open
            }
    try:
        _open = file_type_open_dict[infile.split('.')[-1]]
    except KeyError:
        _open = open
    return _open


def read_from_file(infile):
    """
    Read data from various kinds of file
    """
    data = None
    _open = get_open_method(infile)
    with _open(infile, 'rt', encoding='utf-8', errors='replace') as f:
        data = f.read()
    return crmutils.to_ascii(data.strip('\n'))


def write_to_file(tofile, data):
    """
    Write data to various kinds of file
    """
    _open = get_open_method(tofile)
    with _open(tofile, 'w') as f:
        if _open == open:
            f.write(data)
        else:
            f.write(data.encode('utf-8'))


def is_rfc5424(line):
    return crmutils.parse_to_timestamp(line.split()[0], quiet=True)


def is_syslog(line):
    return crmutils.parse_to_timestamp(' '.join(line.split()[0:3]), quiet=True)


def find_stamp_type(line):
    """
    Find time stamp type of line
    """
    if is_syslog(line):
        return const.STAMP_TYPE_SYSLOG
    elif is_rfc5424(line):
        return const.STAMP_TYPE_RFC5424
    return None


def get_ts(line):
    """
    Get timestamp of line
    """
    ts = None
    if not hasattr(core.context, "stamp_type") or not core.context.stamp_type:
        core.context.stamp_type = find_stamp_type(line)
    # rfc5424 format is like
    # 2003-10-11T22:14:15.003Z mymachine.example.com su
    if core.context.stamp_type == const.STAMP_TYPE_RFC5424:
        ts = crmutils.parse_to_timestamp(line.split()[0], quiet=True)
    # syslog format is like
    # Feb 12 18:30:08 15sp1-1 kernel: e820: BIOS-provided physical RAM map:
    if core.context.stamp_type == const.STAMP_TYPE_SYSLOG:
        ts = crmutils.parse_to_timestamp(' '.join(line.split()[0:3]), quiet=True)
    return ts


def line_time(data_list, line_num):
    """
    Get time stamp of the specific line
    """
    return get_ts(data_list[line_num-1])


def findln_by_time(data, ts, left_value=False):
    """
    Get line number of the specific time stamp
    When the line's time stamp closing to the target time stamp,
    When left_value is True, means return the last middle line in the left side, for to_time
    else, return the last middle line in the right side, for from_time
    """
    data_list = data.split('\n')

    first= 1
    last= len(data_list)
    time_middle = None
    right_middle = None
    left_middle = None

    while first <= last:
        middle = (last + first) // 2
        trycnt = 10
        while trycnt > 0:
            res = line_time(data_list, middle)
            if res:
                time_middle = res
                break
            trycnt -= 1
            # shift the whole first-last segment
            prevmid = middle
            while prevmid == middle:
                first -= 1
                if first < 1:
                    first = 1
                last -= 1
                if last < first:
                    last = first
                prevmid = middle
                middle = (last + first) // 2
                if first == last:
                    break
        if not time_middle:
            return None
        if time_middle > ts:
            last = middle - 1
            right_middle = middle
        elif time_middle < ts:
            first = middle + 1
            left_middle = middle
        else:
            return middle
    return left_middle if left_value else right_middle


def head(n, lines):
    """
    Return first n lines
    """
    return lines.split('\n')[:n]


def tail(n, lines):
    """
    Return last n lines
    """
    return lines.split('\n')[-n:]


def find_first_ts(lines, order=True):
    """
    Find first line with timestampt
    Return timestamp or None
    """
    ts = None
    lines = lines if order else reversed(lines)
    for line in lines:
        if not line:
            continue
        ts = get_ts(line)
        if ts:
            break
    return ts


def is_file_empty(_file):
    """
    Check if file is empty
    """
    return os.stat(_file).st_size == 0


def work_path(_file):
    """
    Shortcut of file path during process
    """
    return os.path.join(core.context.work_dir, _file)


def dest_path(_file):
    """
    Shortcut of file path in report results
    """
    return os.path.join(core.context.dest_path, _file)


def full_path(binary):
    """
    Get full path for a binary
    """
    return get_stdout_or_raise_error("which {}".format(binary))


def get_stdout_or_raise_error(cmd):
    """
    Wrap crmsh.utils.get_stdout_or_raise_error,
    raise CRMReportError when error
    """
    return crmutils.get_stdout_or_raise_error(cmd, exception=CRMReportError)
