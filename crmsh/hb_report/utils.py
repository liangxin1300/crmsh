import os
import re
import datetime
import subprocess
import gzip
import bz2
import lzma
from dateutil import tz

from crmsh import log
from crmsh.hb_report import const, main
from crmsh import utils as crmutils


logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)
logger_utils.set_debug2_level()


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
        crmutils.fatal("Wrong time type \"{}\", should be in {}".format(flag, time_range))

    if flag == 'Y':
        return datetime.timedelta(days = number * 365)
    if flag == 'm':
        return datetime.timedelta(days = number * 30)
    if flag == 'd':
        return datetime.timedelta(days = number)
    if flag == 'H':
        return datetime.timedelta(hours = number)
    if flag == 'M':
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

    res = crmutils.parse_to_timestamp(time_str)
    if res:
        return res
    crmutils.fatal('Wrong time format: \"{}\". Try these format like: 2pm; 1:00; "2019/9/5 12:30"; "09-Sep-07 2:00"'.format(time_str))


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

    _, out, err = crmutils.get_stdout_stderr("{} {}".format(cmd, packages))
    if err:
        logger.error(err)
    if out:
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
    if out:
        for line in out.split('\n'):
            if re.search('not installed', line):
                continue
            output += line + '\n'
    elif not output:
        output = "All packages verify successfully"
        logger.debug(output)
    return output


def distro_info():
    """
    Get distro information
    """
    if os.path.exists(const.OSRELEASE):
        logger.debug("Using {} to get distribution info".format(const.OSRELEASE))
        with open(const.OSRELEASE) as f:
            data = f.read()
        res = re.search("PRETTY_NAME=\"(.*)\"", data)
        if res:
            return res.group(1)
    elif which("lsb_release"):
        logger.debug("Using lsb_release to get distribution info")
        _, out, err = crmutils.get_stdout_stderr("lsb_release -d")
        if err:
            logger.error(err)
        if out:
            res = re.search("Description:\s+(.*)", out)
            if res:
                return res.group(1)
    return "Unknown"


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
        logger.error("Timeout running \"{}\"".format(cmd))
        return (-1, None, None)
    return (proc.returncode, crmutils.to_ascii(stdout_data), crmutils.to_ascii(stderr_data))


def find_files(context, find_dir):
    """
    """
    file_list = []
    for root, _, files in os.walk(path):
        for name in files:
            filename = os.path.join(root, name)
            mtime = os.stat(filename).st_mtime
            if mtime >= context.from_time and mtime < context.to_time:
                file_list.append(filename)
    return find_files


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
    return crmutils.to_ascii(data)


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
        return "syslog"
    elif is_rfc5424(line):
        return "rfc5424"
    return None


def get_ts(line):
    """
    Get timestamp of line
    """
    ts = None
    if not hasattr(main.ctx, "stamp_type") or not main.ctx.stamp_type:
        main.ctx.stamp_type = find_stamp_type(line)
    _type = main.ctx.stamp_type
    # rfc5424 format is like
    # 2003-10-11T22:14:15.003Z mymachine.example.com su
    if _type == "rfc5424":
        ts = crmutils.parse_to_timestamp(line.split()[0], quiet=True)
    # syslog format is like
    # Feb 12 18:30:08 15sp1-1 kernel: e820: BIOS-provided physical RAM map:
    if _type == "syslog":
        ts = crmutils.parse_to_timestamp(' '.join(line.split()[0:3]), quiet=True)
    return ts


def line_time(data_list, line_num):
    """
    Get time stamp of the specific line
    """
    return get_ts(data_list[line_num-1])


def findln_by_time(data, ts):
    """
    Get line number of the specific time stamp
    """
    data_list = data.split('\n')

    first= 1
    last= len(data_list)
    time_middle = None

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
        elif time_middle < ts:
            first = middle + 1
        else:
            break
    return middle


def filter_lines(data, from_line, to_line):
    """
    Filter lines by line range
    """
    out_string = ""
    count = 1
    for line in data.split('\n'):
        if count >= from_line and count <= to_line:
            out_string += line + '\n'
        if count > to_line:
            break
        count += 1
    return out_string


def head(n, indata):
    return indata.split('\n')[:n]


def tail(n, indata):
    return reversed(indata.split('\n')[-n:])


def find_first_ts(lines):
    ts = None
    for line in lines:
        if not line:
            continue
        ts = get_ts(line)
        if ts:
            break
    return ts
