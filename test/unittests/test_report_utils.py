import gzip
import pytest
import datetime
import subprocess
from unittest import mock

from crmsh.report import utils, core, const


@mock.patch('crmsh.report.utils.get_ts')
def test_line_time(mock_get_ts):
    mock_get_ts.return_value = "123"
    res = utils.line_time(["line1", "line2"], 2)
    assert res == "123"
    mock_get_ts.assert_called_once_with("line2")


@mock.patch('crmsh.report.utils.crmutils.parse_to_timestamp')
def test_get_ts_rfc(mock_parse):
    core.context.stamp_type = const.STAMP_TYPE_RFC5424
    mock_parse.return_value = "123"
    res = utils.get_ts("2003-10-11T22:14:15.003Z mymachine.example.com su")
    assert res == "123"
    mock_parse.assert_called_once_with("2003-10-11T22:14:15.003Z", quiet=True)


@mock.patch('crmsh.report.utils.find_stamp_type')
@mock.patch('crmsh.report.utils.crmutils.parse_to_timestamp')
def test_get_ts_syslog(mock_parse, mock_find_type):
    core.context.stamp_type = None
    mock_find_type.return_value = const.STAMP_TYPE_SYSLOG
    mock_parse.return_value = "123"
    res = utils.get_ts("Feb 12 18:30:08 15sp1-1 kernel: e820: BIOS-provided physical RAM map")
    assert res == "123"
    mock_parse.assert_called_once_with("Feb 12 18:30:08", quiet=True)


@mock.patch('crmsh.report.utils.crmutils.parse_to_timestamp')
def test_is_rfc5424(mock_parse):
    mock_parse.return_value = "123"
    line = "2003-10-11T22:14:15.003Z mymachine.example.com su"
    res = utils.is_rfc5424(line)
    assert res == "123"
    mock_parse.assert_called_once_with("2003-10-11T22:14:15.003Z", quiet=True)


@mock.patch('crmsh.report.utils.crmutils.parse_to_timestamp')
def test_is_syslog(mock_parse):
    mock_parse.return_value = "123"
    line = "Feb 12 18:30:08 15sp1-1 kernel: e820: BIOS-provided physical RAM map"
    res = utils.is_syslog(line)
    assert res == "123"
    mock_parse.assert_called_once_with("Feb 12 18:30:08", quiet=True)


@mock.patch('crmsh.report.utils.is_rfc5424')
@mock.patch('crmsh.report.utils.is_syslog')
def test_find_stamp_type_none(mock_syslog, mock_rfc):
    mock_syslog.return_value = False
    mock_rfc.return_value = False
    res = utils.find_stamp_type("line")
    assert res is None


@mock.patch('crmsh.report.utils.is_syslog')
def test_find_stamp_type_syslog(mock_syslog):
    mock_syslog.return_value = True
    res = utils.find_stamp_type("line")
    assert res == const.STAMP_TYPE_SYSLOG


@mock.patch('crmsh.report.utils.is_syslog')
@mock.patch('crmsh.report.utils.is_rfc5424')
def test_find_stamp_type_rfc(mock_rfc, mock_syslog):
    mock_syslog.return_value = False
    mock_rfc.return_value = True
    res = utils.find_stamp_type("line")
    assert res == const.STAMP_TYPE_RFC5424


@mock.patch('gzip.open')
@mock.patch('crmsh.report.utils.crmutils.to_ascii')
@mock.patch('crmsh.report.utils.get_open_method')
def test_read_from_file(mock_get_method, mock_to_ascii, mock_gopen):
    mock_get_method.return_value = mock_gopen
    mock_gopen.return_value = mock.mock_open(read_data="data1").return_value
    mock_to_ascii.return_value = "data1"
    res = utils.read_from_file("file.gz")
    assert res == mock_to_ascii.return_value
    mock_get_method.assert_called_once_with("file.gz")
    mock_gopen.assert_called_once_with("file.gz", "rt", encoding='utf-8', errors='replace')


def test_get_open_method_open():
    res = utils.get_open_method("file1")
    assert res == open


def test_get_open_method_gz():
    res = utils.get_open_method("file.gz")
    assert res == gzip.open


@mock.patch('builtins.open', create=True)
def test_touch_file(mock_open_file):
    mock_open_file_inst = mock.Mock()
    mock_open_file.return_value = mock_open_file_inst
    utils.touch_file("file1")
    mock_open_file.assert_called_once_with("file1", "w")
    mock_open_file_inst.close.assert_called_once_with()


@mock.patch("builtins.open", new_callable=mock.mock_open)
@mock.patch('crmsh.report.utils.get_open_method')
def test_write_to_file_open(mock_get_method, mock_open):
    mock_get_method.return_value = mock_open

    utils.write_to_file("tofile", "data")

    mock_get_method.assert_called_once_with("tofile")
    mock_open.assert_called_once_with("tofile", 'w')
    mock_open().write.assert_called_once_with("data")


@mock.patch("bz2.open", new_callable=mock.mock_open)
@mock.patch('crmsh.report.utils.get_open_method')
def test_write_to_file_bz2(mock_get_method, mock_bz2_open):
    mock_get_method.return_value = mock_bz2_open

    utils.write_to_file("tofile.bz2", "data")

    mock_get_method.assert_called_once_with("tofile.bz2")
    mock_bz2_open.assert_called_once_with("tofile.bz2", 'w')
    mock_bz2_open().write.assert_called_once_with("data".encode('utf-8'))


@mock.patch('os.stat')
@mock.patch('os.path.join')
@mock.patch('os.walk')
def test_find_files(mock_walk, mock_join, mock_stat):
    core.context.from_time = 1
    core.context.to_time = 10
    mock_walk.return_value = [("root", None, ["file1", "file2"])]
    mock_join.side_effect = ["root/file1", "root/file2"]
    mock_state_inst1 = mock.Mock(st_mtime=2)
    mock_state_inst2 = mock.Mock(st_mtime=10)
    mock_stat.side_effect = [mock_state_inst1, mock_state_inst2]

    res = utils.find_files("dir1")
    assert res == ["root/file1", "root/file2"]

    mock_walk.assert_called_once_with("dir1")
    mock_join.assert_has_calls([
        mock.call("root", "file1"),
        mock.call("root", "file2")
        ])


@mock.patch('crmsh.report.utils.crmutils.get_stdout_stderr')
def test_which(mock_run):
    mock_run.return_value = (0, None, None)
    assert utils.which("cmd") == True
    mock_run.assert_called_once_with("which cmd")


@mock.patch('crmsh.report.utils.which')
@mock.patch('os.path.exists')
def test_distro_info_unknown(mock_exists, mock_which):
    mock_exists.return_value = False
    mock_which.return_value = False
    res = utils.distro_info()
    assert res == "Unknown"
    mock_exists.assert_called_once_with(const.OSRELEASE)
    mock_which.assert_called_once_with("lsb_release")


@mock.patch('crmsh.report.utils.read_from_file')
@mock.patch('logging.Logger.debug')
@mock.patch('os.path.exists')
def test_distro_info_osrelease(mock_exists, mock_debug, mock_read):
    mock_exists.return_value = True
    mock_read.return_value = """
NAME="SLES"
VERSION="15-SP2"
VERSION_ID="15.2"
PRETTY_NAME="SUSE Linux Enterprise Server 15 SP2"
    """
    res = utils.distro_info()
    assert res == "SUSE Linux Enterprise Server 15 SP2"
    mock_exists.assert_called_once_with(const.OSRELEASE)
    mock_read.assert_called_once_with(const.OSRELEASE)


@mock.patch('crmsh.report.utils.get_stdout_or_raise_error')
@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.utils.which')
@mock.patch('os.path.exists')
def test_distro_info_lsb(mock_exists, mock_which, mock_debug, mock_run):
    mock_exists.return_value = False
    mock_which.return_value = True
    mock_run.return_value = "Description:   Fedora release 30 (Thirty)"
    res = utils.distro_info()
    assert res == "Fedora release 30 (Thirty)"
    mock_exists.assert_called_once_with(const.OSRELEASE)
    mock_which.assert_called_once_with("lsb_release")
    mock_run.assert_called_once_with("lsb_release -d")


@mock.patch('logging.Logger.error')
@mock.patch('crmsh.report.utils.crmutils.get_stdout_stderr')
def test_verify_rpm_error(mock_run, mock_error):
    mock_run.return_value = (0, None, "error")
    res = utils.verify_rpm("rpm1")
    assert res == ""
    mock_run.assert_called_once_with("rpm --verify rpm1")
    mock_error.assert_called_once_with("error")


@mock.patch('crmsh.report.utils.crmutils.get_stdout_stderr')
def test_verify_rpm_success(mock_run):
    mock_run.return_value = (0, None, None)
    res = utils.verify_rpm("rpm1")
    assert res == "All packages verify successfully\n"
    mock_run.assert_called_once_with("rpm --verify rpm1")


@mock.patch('crmsh.report.utils.crmutils.get_stdout_stderr')
def test_verify_rpm(mock_run):
    mock_run.return_value = (0, "data1\ndata2\nnot installed", None)
    res = utils.verify_rpm("rpm1")
    assert res == "data1\ndata2\n"
    mock_run.assert_called_once_with("rpm --verify rpm1")


def test_unique_list():
    res = utils.unique_list([1,1,2,2,3,3])
    assert res == [1,2,3]


@mock.patch('crmsh.report.utils.crmutils.get_stdout_stderr')
def test_get_rpm_info(mock_run):
    output = """line1
not installed line2"""
    mock_run.return_value = (0, output, None)
    res = utils.get_rpm_info("rpm1")
    assert res == "Name | Version-Release | Distribution | Arch\n-----\nline1\n"
    mock_run.assert_called_once_with("rpm -q --qf '%{name} | %{version}-%{release} | %{distribution} | %{arch}\n' rpm1")


@mock.patch('crmsh.report.utils.tz.tzlocal')
@mock.patch('crmsh.report.utils.crmutils.timestamp_to_datetime')
def test_ts_to_dt(mock_to_datetime, mock_tz):
    mock_to_datetime.return_value = "dt"
    mock_tz_inst = mock.Mock()
    mock_tz.return_value = mock_tz_inst
    mock_tz_inst.utcoffset.return_value = "dt"

    res = utils.ts_to_dt("1234")
    assert res == "dtdt"

    mock_to_datetime.assert_called_once_with("1234")
    mock_tz.assert_called_once_with()
    mock_tz_inst.utcoffset.assert_called_once_with("dt")


@mock.patch('crmsh.report.utils.dt_to_str')
@mock.patch('datetime.datetime')
def test_now(mock_datetime, mock_dt_to_str):
    date_instance = mock.Mock(year=2000)
    mock_datetime.now.return_value = date_instance
    mock_dt_to_str.return_value = "data"
    res = utils.now()
    assert res == mock_dt_to_str.return_value
    mock_dt_to_str.assert_called_once_with(mock_datetime.now.return_value, form=const.TIME_FORMAT)


def test_dt_to_str():
    dt = datetime.datetime(2020, 2, 19, 21, 44, 7, 977355)
    res = utils.dt_to_str(dt)
    assert res == "2020-02-19 21:44:07"


@mock.patch('crmsh.report.utils.dt_to_str')
@mock.patch('crmsh.report.utils.ts_to_dt')
def test_ts_to_str(mock_ts_to_dt, mock_dt_to_str):
    mock_ts_to_dt.return_value = "dt"
    mock_dt_to_str.return_value = "str"
    res = utils.ts_to_str("1234")
    assert res == mock_dt_to_str.return_value
    mock_ts_to_dt.assert_called_once_with("1234")
    mock_dt_to_str.assert_called_once_with(mock_ts_to_dt.return_value, form=const.TIME_FORMAT)


def test_timedelta_inst_exception():
    with pytest.raises(utils.CRMReportError) as err:
        utils.timedelta_inst(1, "x")
    assert str(err.value) == "Wrong time type \"x\", should be in ['Y', 'm', 'd', 'H', 'M']"


@mock.patch('datetime.timedelta')
def test_timedelta_inst_year(mock_timedelta):
    mock_timedelta_inst = mock.Mock()
    mock_timedelta.return_value = mock_timedelta_inst
    utils.timedelta_inst(2, "Y")
    assert core.context.delta_time_str == "2 Years"
    mock_timedelta.assert_called_once_with(days=2*365)


@mock.patch('datetime.timedelta')
def test_timedelta_inst_month(mock_timedelta):
    mock_timedelta_inst = mock.Mock()
    mock_timedelta.return_value = mock_timedelta_inst
    utils.timedelta_inst(2, "m")
    assert core.context.delta_time_str == "2 Months"
    mock_timedelta.assert_called_once_with(days=2*30)


@mock.patch('datetime.timedelta')
def test_timedelta_inst_day(mock_timedelta):
    mock_timedelta_inst = mock.Mock()
    mock_timedelta.return_value = mock_timedelta_inst
    utils.timedelta_inst(2, "d")
    assert core.context.delta_time_str == "2 Days"
    mock_timedelta.assert_called_once_with(days=2)


@mock.patch('datetime.timedelta')
def test_timedelta_inst_hour(mock_timedelta):
    mock_timedelta_inst = mock.Mock()
    mock_timedelta.return_value = mock_timedelta_inst
    utils.timedelta_inst(2, "H")
    assert core.context.delta_time_str == "2 Hours"
    mock_timedelta.assert_called_once_with(hours=2)


@mock.patch('datetime.timedelta')
def test_timedelta_inst_minute(mock_timedelta):
    mock_timedelta_inst = mock.Mock()
    mock_timedelta.return_value = mock_timedelta_inst
    utils.timedelta_inst(2, "M")
    assert core.context.delta_time_str == "2 Minutes"
    mock_timedelta.assert_called_once_with(minutes=2)


@mock.patch('crmsh.report.utils.crmutils.parse_to_timestamp')
def test_parse_to_timestamp_exception(mock_parse):
    mock_parse.return_value = None
    with pytest.raises(utils.CRMReportError) as err:
        utils.parse_to_timestamp("xxxxxx")
    assert str(err.value) == 'Wrong time format: "xxxxxx". Try these format like: 2pm; 1:00; "2019/9/5 12:30"; "09-Sep-07 2:00"'


@mock.patch('crmsh.report.utils.crmutils.parse_to_timestamp')
@mock.patch('datetime.datetime')
@mock.patch('crmsh.report.utils.timedelta_inst')
def test_parse_to_timestamp(mock_delta_inst, mock_datetime, mock_parse):
    date_instance = datetime.datetime(2020, 2, 19, 21, 44, 7, 977355)
    delta_instance = datetime.datetime(2020, 2, 18, 21, 44, 7, 977355)
    mock_datetime.now.return_value = date_instance
    mock_delta_inst.return_value = delta_instance
    mock_parse.return_value = "123"
    assert utils.parse_to_timestamp("1d") == "123"


@mock.patch('crmsh.report.utils.line_time')
def test_findln_by_time_irregular(mock_line_time):
    data = """line1
line2
line3
line4
line5"""
    mock_line_time.side_effect = [None for _ in range(10)]

    res = utils.findln_by_time(data, 100)
    assert res is None

    mock_line_time.assert_has_calls([
        mock.call(data.split('\n'), 3),
        mock.call(data.split('\n'), 2),
        ] + [mock.call(data.split('\n'), 1) for _ in range(8)])


@mock.patch('crmsh.report.utils.line_time')
def test_findln_by_time_right(mock_line_time):
    data = """1001 line1
1003 line2
1005 line3
1007 line4
1009 line5"""
    mock_line_time.side_effect = [1005, 1001, 1003]

    res = utils.findln_by_time(data, 1004)
    assert res == 3

    mock_line_time.assert_has_calls([
        mock.call(data.split('\n'), 3),
        mock.call(data.split('\n'), 1),
        mock.call(data.split('\n'), 2)
        ])


@mock.patch('crmsh.report.utils.line_time')
def test_findln_by_time_left(mock_line_time):
    data = """1001 line1
1003 line2
1005 line3
1007 line4
1009 line5"""
    mock_line_time.side_effect = [1005, 1007]

    res = utils.findln_by_time(data, 1006, left_value=True)
    assert res == 3

    mock_line_time.assert_has_calls([
        mock.call(data.split('\n'), 3),
        mock.call(data.split('\n'), 4)
        ])


@mock.patch('crmsh.report.utils.line_time')
def test_findln_by_time_exact(mock_line_time):
    data = """1001 line1
1003 line2
1005 line3
1007 line4
1009 line5"""
    mock_line_time.side_effect = [1005, 1007, 1009]

    res = utils.findln_by_time(data, 1009)
    assert res == 5

    mock_line_time.assert_has_calls([
        mock.call(data.split('\n'), 3),
        mock.call(data.split('\n'), 4),
        mock.call(data.split('\n'), 5)
        ])


def test_head():
    lines = """line1
line2
line3
line4
line5"""
    res = utils.head(2, lines)
    assert res == ["line1", "line2"]


def test_tail():
    lines = """line1
line2
line3
line4
line5"""
    res = utils.tail(2, lines)
    assert res == ["line4", "line5"]


@mock.patch('crmsh.report.utils.get_ts')
def test_find_first_ts(mock_get_ts):
    mock_get_ts.return_value = 12345
    lines = ["", "line1"]
    res = utils.find_first_ts(lines)
    assert res == 12345
    mock_get_ts.assert_called_once_with("line1")


@mock.patch('os.stat')
def test_is_file_empty(mock_stat):
    mock_stat.return_value = mock.Mock(st_size=0)
    res = utils.is_file_empty("file1")
    assert res is True
    mock_stat.assert_called_once_with("file1")


@mock.patch('os.path.join')
def test_work_path(mock_join):
    core.context.work_dir = "work_dir"
    mock_join.return_value = "work_dir/file1"
    res = utils.work_path("file1")
    assert res == "work_dir/file1"
    mock_join.assert_called_once_with("work_dir", "file1")


@mock.patch('os.path.join')
def test_dest_path(mock_join):
    core.context.dest_path = "dest_path"
    mock_join.return_value = "dest_path/file1"
    res = utils.dest_path("file1")
    assert res == "dest_path/file1"
    mock_join.assert_called_once_with("dest_path", "file1")


@mock.patch('crmsh.report.utils.get_stdout_or_raise_error')
def test_full_path(mock_run):
    mock_run.return_value = "/usr/sbin/corosync"
    res = utils.full_path("corosync")
    assert res == "/usr/sbin/corosync"
    mock_run.assert_called_once_with("which corosync")


@mock.patch('crmsh.report.utils.crmutils.get_stdout_or_raise_error')
def test_get_stdout_or_raise_error(mock_run):
    mock_run.return_value = "data"
    res = utils.get_stdout_or_raise_error("cmd")
    assert res == "data"
    mock_run.assert_called_once_with("cmd", exception=utils.CRMReportError)


@mock.patch('crmsh.report.utils.crmutils.to_ascii')
@mock.patch('subprocess.Popen')
def test_get_stdout_stderr_timeout(mock_popen, mock_to_ascii):
    mock_popen_inst = mock.Mock(returncode=0)
    mock_popen.return_value = mock_popen_inst
    mock_popen_inst.communicate = mock.Mock()
    mock_popen_inst.communicate.return_value = ("data", None)
    mock_to_ascii.side_effect = ["data", None]
    res = utils.get_stdout_stderr_timeout("cmd")
    assert res == (0, "data", None)
    mock_popen.assert_called_once_with('cmd', shell=True, stdin=None, stdout=-1, stderr=-1)


@mock.patch('logging.Logger.error')
def test_get_stdout_stderr_timeout_expired(mock_error):
    res = utils.get_stdout_stderr_timeout("sleep 2", timeout=1)
    assert res == (-1, None, None)
    mock_error.assert_called_once_with('Timeout running "%s"', "sleep 2")
