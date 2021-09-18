import os
import pytest
import sys
import unittest
from unittest import mock
from inspect import isfunction

from crmsh import utils as crmutils
from crmsh.config import report, path
from crmsh.report import collect, core, const, utils


class TestContext(unittest.TestCase):
    """
    Unitary tests for crmsh.report.core.Context
    """

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    def setUp(self):
        """
        Test setUp.
        """
        self.context_inst = core.Context()

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch('json.dumps')
    def test_str(self, mock_dumps):
        mock_dumps.return_value = "context str"
        assert str(core.context) == mock_dumps.return_value
        mock_dumps.assert_called_once_with(core.context.__dict__)

    @mock.patch('json.dumps')
    def test_dumps(self, mock_dumps):
        mock_dumps.return_value = "context str"
        assert core.context.dumps() == mock_dumps.return_value
        mock_dumps.assert_called_once_with(core.context.__dict__, indent=2)

    @mock.patch('crmsh.report.core.sanitize.load_sanitize_rule')
    @mock.patch('crmsh.report.core.Context.get_cores_dir')
    @mock.patch('crmsh.report.core.Context.get_ha_varlib')
    @mock.patch('crmsh.report.core.Context.get_dir_from_crm_config_path')
    @mock.patch('crmsh.report.utils.now')
    @mock.patch('crmsh.report.utils.parse_to_timestamp')
    def test_load_values(self, mock_parse, mock_now, mock_getdir, mock_get_havarlib, mock_get_coredir, mock_load_sanitize):
        mock_parse.side_effect = [123, 456]
        mock_now.return_value = "now date"
        self.context_inst.load_values()

    @mock.patch('os.path.isdir')
    def test_get_dir_from_crm_config_path_exception(self, mock_isdir):
        mock_isdir.return_value = False
        with pytest.raises(utils.CRMReportError) as err:
            self.context_inst.get_dir_from_crm_config_path()
        assert str(err.value) == "Cannot find ocf_root directory from crmsh.config.path"
        mock_isdir.assert_called_once_with(path.ocf_root)

    @mock.patch('os.path.isdir')
    def test_get_dir_from_crm_config_path(self, mock_isdir):
        mock_isdir.side_effect = [True, True, True]
        self.context_inst.get_dir_from_crm_config_path()
        assert self.context_inst.ocf_root == path.ocf_root
        assert self.context_inst.pe_state_dir == path.pe_state_dir
        assert self.context_inst.crm_config == path.crm_config

    @mock.patch('os.path.exists')
    def test_get_ha_varlib_exists_exception(self, mock_exists):
        self.context_inst.ocf_root = "/usr/lib/ocf"
        mock_exists.return_value = False
        with pytest.raises(utils.CRMReportError) as err:
            self.context_inst.get_ha_varlib()
        assert str(err.value) == "File /usr/lib/ocf/lib/heartbeat/ocf-directories not exist"

    @mock.patch('crmsh.report.utils.read_from_file')
    @mock.patch('os.path.exists')
    def test_get_ha_varlib_empty_exception(self, mock_exists, mock_read):
        self.context_inst.ocf_root = "/usr/lib/ocf"
        mock_exists.return_value = True
        mock_read.return_value = None
        with pytest.raises(utils.CRMReportError) as err:
            self.context_inst.get_ha_varlib()
        assert str(err.value) == "File /usr/lib/ocf/lib/heartbeat/ocf-directories is empty"

    @mock.patch('crmsh.report.utils.read_from_file')
    @mock.patch('os.path.exists')
    def test_get_ha_varlib_exception(self, mock_exists, mock_read):
        self.context_inst.ocf_root = "/usr/lib/ocf"
        mock_exists.return_value = True
        mock_read.return_value = "test"
        with pytest.raises(utils.CRMReportError) as err:
            self.context_inst.get_ha_varlib()
        assert str(err.value) == "Cannot find HA_VARLIB in /usr/lib/ocf/lib/heartbeat/ocf-directories"

    @mock.patch('crmsh.report.utils.read_from_file')
    @mock.patch('os.path.exists')
    def test_get_ha_varlib(self, mock_exists, mock_read):
        self.context_inst.ocf_root = "/usr/lib/ocf"
        mock_exists.return_value = True
        mock_read.return_value = ": ${HA_VARLIB:=/var/lib/heartbeat}"
        self.context_inst.get_ha_varlib()
        assert self.context_inst.ha_varlib == "/var/lib/heartbeat"

    @mock.patch('os.path.isdir')
    @mock.patch('os.path.join')
    @mock.patch('os.path.dirname')
    def test_get_cores_dir(self, mock_dirname, mock_join, mock_isdir):
        self.context_inst.crm_config = "/var/lib/pacemaker/cib"
        mock_dirname.return_value = "/var/lib/pacemaker"
        mock_join.return_value = "/var/lib/pacemaker/cores"
        mock_isdir.return_value = True
        self.context_inst.get_cores_dir()
        assert self.context_inst.cores_dirs == [mock_join.return_value, const.COROSYNC_LIB]

    def test_load_from_argv(self):
        sys.argv = ['/usr/sbin/crm', '__collector', '{"test_name": "test", "age": "19"}']
        self.context_inst.load_from_argv()
        assert self.context_inst.test_name == "test"


@mock.patch('crmsh.report.core.getmembers')
def test_generate_collect_functions(mock_getmembers):
    mock_getmembers.return_value = [("test1", None), ("collect_func1", None), ("collect_func2", None)]
    res = core.generate_collect_functions()
    assert res == ["collect_func1", "collect_func2"]
    mock_getmembers.assert_called_once_with(collect, isfunction)


def test_is_collector():
    sys.argv = ["test1", const.COLLECTOR]
    res = core.is_collector()
    assert res is True


@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.core.crmutils.mkdirp')
@mock.patch('crmsh.report.core.crmutils.this_node')
@mock.patch('os.path.join')
@mock.patch('crmsh.report.core.is_collector')
@mock.patch('crmsh.report.core.tmpfiles.create_dir')
@mock.patch('crmsh.report.core.validate_dest')
def test_setup_workdir(mock_validate_dest, mock_create_dir, mock_is_collector, mock_join, mock_this_node, mock_mkdir, mock_debug):
    mock_create_dir.return_value = "/tmp/tmp123"
    mock_is_collector.return_value = True
    mock_this_node.side_effect = ["node1", "node1"]
    mock_join.side_effect = ["work_path/dir", "dest_path/dir"]
    core.context.dest = "dest_dir"

    core.setup_workdir()

    mock_validate_dest.assert_called_once_with()
    mock_create_dir.assert_called_once_with()
    mock_is_collector.assert_called_once_with()
    mock_this_node.assert_has_calls([mock.call(), mock.call()])
    mock_join.assert_has_calls([
        mock.call(mock_create_dir.return_value, core.context.dest, "node1"),
        mock.call(core.context.dest, "node1")
        ])
    mock_mkdir.assert_called_once_with("work_path/dir")
    mock_debug.assert_called_once_with('Setup work directory in "%s"', "work_path/dir")


@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.core.crmutils.mkdirp')
@mock.patch('os.path.join')
@mock.patch('crmsh.report.core.is_collector')
@mock.patch('crmsh.report.core.tmpfiles.create_dir')
@mock.patch('crmsh.report.core.validate_dest')
def test_setup_workdir_collector(mock_validate_dest, mock_create_dir, mock_is_collector, mock_join, mock_mkdir, mock_debug):
    mock_create_dir.return_value = "/tmp/tmp123"
    mock_is_collector.return_value = False
    mock_join.return_value = "work_path/dir"
    core.context.dest = "dest_dir"

    core.setup_workdir()

    mock_validate_dest.assert_called_once_with()
    mock_create_dir.assert_called_once_with()
    mock_is_collector.assert_called_once_with()
    mock_join.assert_called_once_with(mock_create_dir.return_value, core.context.dest)
    mock_mkdir.assert_called_once_with("work_path/dir")
    mock_debug.assert_called_once_with('Setup work directory in "%s"', "work_path/dir")


def test_process_context_value_exception():
    core.context.before_time = None
    core.context.to_time = 1
    core.context.from_time = 2
    with pytest.raises(utils.CRMReportError) as err:
        core.process_context_value()
    assert str(err.value) == "Start time must be before finish time"


@mock.patch('crmsh.report.sanitize.parse_sanitize_rule')
@mock.patch('crmsh.report.utils.ts_to_str')
@mock.patch('crmsh.report.utils.now')
@mock.patch('crmsh.report.utils.parse_to_timestamp')
def test_process_context_value(mock_parse, mock_now, mock_to_str, mock_sanitize):
    core.context.before_time = "12d"
    core.context.to_time = 456
    core.context.dest = None
    core.context.name = "crm_report"
    core.context.sensitive_regex_list = ["passw.*"]
    mock_parse.return_value = 123
    mock_now.return_value = "Mon-20-Sep-2021"
    mock_to_str.side_effect = ["2021-09-21 21:58", "2021-09-21 21:58"]

    core.process_context_value()
    assert core.context.dest == "crm_report-Mon-20-Sep-2021"
    assert core.context.from_time_str == "2021-09-21 21:58"
    assert core.context.to_time_str == "2021-09-21 21:58"

    mock_parse.assert_called_once_with(core.context.before_time)
    mock_now.assert_called_once_with(const.TIME_FORMAT_FOR_TAR)
    mock_to_str.assert_has_calls([
        mock.call(mock_parse.return_value),
        mock.call(core.context.to_time)
        ])


@mock.patch('argparse.RawDescriptionHelpFormatter')
@mock.patch('argparse.ArgumentParser')
def test_parse_argument_help(mock_parser, mock_formatter):
    mock_parser_inst = mock.Mock()
    mock_parser.return_value = mock_parser_inst
    mock_args_inst = mock.Mock(help=True)
    mock_parser_inst.parse_args.return_value = mock_args_inst
    with pytest.raises(SystemExit):
        core.parse_argument()
    mock_parser_inst.print_help.assert_called_once_with()


@mock.patch('argparse.RawDescriptionHelpFormatter')
@mock.patch('argparse.ArgumentParser')
def test_parse_argument(mock_parser, mock_formatter):
    mock_parser_inst = mock.Mock()
    mock_parser.return_value = mock_parser_inst
    mock_args_inst = mock.Mock(help=False)
    mock_parser_inst.parse_args.return_value = mock_args_inst
    res = core.parse_argument()
    assert res == mock_args_inst
    mock_parser_inst.parse_args.assert_called_once_with()


@mock.patch('logging.Logger._log')
@mock.patch('crmsh.report.utils.read_from_file')
def test_is_our_log_empty(mock_read, mock_log):
    mock_read.return_value = None
    res = core.is_our_log("file1")
    assert res == core.LogfileType.EMPTY
    mock_read.assert_called_once_with("file1")


@mock.patch('crmsh.report.utils.tail')
@mock.patch('crmsh.report.utils.head')
@mock.patch('crmsh.report.utils.find_first_ts')
@mock.patch('logging.Logger._log')
@mock.patch('crmsh.report.utils.read_from_file')
def test_is_our_log_irregular(mock_read, mock_log, mock_find_ts, mock_head, mock_tail):
    mock_read.return_value = "data"
    mock_head.return_value = "line1"
    mock_tail.return_value = "line100"
    mock_find_ts.side_effect = [None, None]
    core.context.from_time = 123
    core.context.to_time = 456

    res = core.is_our_log("file1")
    assert res == core.LogfileType.IRREGULAR

    mock_read.assert_called_once_with("file1")
    mock_head.assert_called_once_with(10, "data")
    mock_tail.assert_called_once_with(10, "data")
    mock_find_ts.assert_has_calls([
        mock.call(mock_head.return_value),
        mock.call(mock_tail.return_value, order=False)
        ])


@mock.patch('crmsh.report.utils.tail')
@mock.patch('crmsh.report.utils.head')
@mock.patch('crmsh.report.utils.find_first_ts')
@mock.patch('logging.Logger._log')
@mock.patch('crmsh.report.utils.read_from_file')
def test_is_our_log_before(mock_read, mock_log, mock_find_ts, mock_head, mock_tail):
    mock_read.return_value = "data"
    mock_head.return_value = "line1"
    mock_tail.return_value = "line100"
    mock_find_ts.side_effect = [12, 45]
    core.context.from_time = 123
    core.context.to_time = 456

    res = core.is_our_log("file1")
    assert res == core.LogfileType.BEFORE_TIME

    mock_read.assert_called_once_with("file1")
    mock_head.assert_called_once_with(10, "data")
    mock_tail.assert_called_once_with(10, "data")
    mock_find_ts.assert_has_calls([
        mock.call(mock_head.return_value),
        mock.call(mock_tail.return_value, order=False)
        ])


@mock.patch('crmsh.report.utils.tail')
@mock.patch('crmsh.report.utils.head')
@mock.patch('crmsh.report.utils.find_first_ts')
@mock.patch('logging.Logger._log')
@mock.patch('crmsh.report.utils.read_from_file')
def test_is_our_log_good(mock_read, mock_log, mock_find_ts, mock_head, mock_tail):
    mock_read.return_value = "data"
    mock_head.return_value = "line1"
    mock_tail.return_value = "line100"
    mock_find_ts.side_effect = [12, 124]
    core.context.from_time = 123
    core.context.to_time = 456

    res = core.is_our_log("file1")
    assert res == core.LogfileType.GOOD

    mock_read.assert_called_once_with("file1")
    mock_head.assert_called_once_with(10, "data")
    mock_tail.assert_called_once_with(10, "data")
    mock_find_ts.assert_has_calls([
        mock.call(mock_head.return_value),
        mock.call(mock_tail.return_value, order=False)
        ])


@mock.patch('crmsh.report.utils.tail')
@mock.patch('crmsh.report.utils.head')
@mock.patch('crmsh.report.utils.find_first_ts')
@mock.patch('logging.Logger._log')
@mock.patch('crmsh.report.utils.read_from_file')
def test_is_our_log_after(mock_read, mock_log, mock_find_ts, mock_head, mock_tail):
    core.context.stamp_type = "rfcxxx"
    mock_read.return_value = "data"
    mock_head.return_value = "line1"
    mock_tail.return_value = "line100"
    mock_find_ts.side_effect = [1000, 1001]
    core.context.from_time = 123
    core.context.to_time = 456

    res = core.is_our_log("file1")
    assert res == core.LogfileType.AFTER_TIME

    mock_read.assert_called_once_with("file1")
    mock_head.assert_called_once_with(10, "data")
    mock_tail.assert_called_once_with(10, "data")
    mock_find_ts.assert_has_calls([
        mock.call(mock_head.return_value),
        mock.call(mock_tail.return_value, order=False)
        ])


@mock.patch('logging.Logger._log')
@mock.patch('crmsh.report.core.is_our_log')
@mock.patch('builtins.sorted')
@mock.patch('glob.glob')
def test_arch_logs(mock_glob, mock_sorted, mock_is_our_log, mock_log):
    mock_glob.return_value = ["file1.xz", "file2.xz"]
    mock_sorted.return_value = ["file", "file1.xz", "file2.xz"]
    mock_is_our_log.side_effect = [core.LogfileType.EMPTY, core.LogfileType.GOOD, core.LogfileType.BEFORE_TIME]
    _type, ret_list = core.arch_logs("file")
    assert (_type, ret_list) == (core.LogfileType.GOOD, ["file1.xz"])
    mock_glob.assert_called_once_with("file*[0-9z]")
    mock_sorted.assert_called_once_with(mock_sorted.return_value, key=os.path.getmtime, reverse=True)
    mock_is_our_log.assert_has_calls([
        mock.call("file"),
        mock.call("file1.xz"),
        mock.call("file2.xz")
        ])


@mock.patch('crmsh.report.core.push_data')
@mock.patch('crmsh.report.core.collect_logs_and_info')
@mock.patch('crmsh.report.core.setup_workdir')
@mock.patch('crmsh.report.core.is_collector')
def test_run_collector(mock_collector, mock_setup, mock_collect, mock_push):
    mock_collector.side_effect = [True, True]
    core.context.load_from_argv = mock.Mock()
    core.context.debug = True
    core.run()
    mock_collector.assert_has_calls([mock.call(), mock.call()])


@mock.patch('crmsh.report.core.crmutils.get_stdout_stderr')
@mock.patch('crmsh.report.core.crmutils.this_node')
@mock.patch('logging.Logger.debug')
def test_push_data_exception(mock_debug, mock_this_node, mock_run):
    mock_this_node.return_value = "node1"
    mock_run.return_value = (1, None, "error data")
    with pytest.raises(utils.CRMReportError) as err:
        core.push_data()
    assert str(err.value) == "error data"


@mock.patch('crmsh.report.core.crmutils.get_stdout_stderr')
@mock.patch('crmsh.report.core.crmutils.this_node')
@mock.patch('logging.Logger.debug')
def test_push_data(mock_debug, mock_this_node, mock_run):
    mock_this_node.return_value = "node1"
    mock_run.return_value = (0, "data", None)
    core.push_data()
    mock_run.assert_called_once_with('cd work_path/dir/.. && tar -h -cf - node1', raw=True)


@mock.patch('crmsh.report.core.process_results')
@mock.patch('crmsh.report.core.collect_for_nodes')
@mock.patch('crmsh.report.core.ssh_issue')
@mock.patch('crmsh.report.core.get_nodes')
@mock.patch('crmsh.report.core.setup_workdir')
@mock.patch('crmsh.report.core.process_argument')
@mock.patch('crmsh.report.core.is_collector')
def test_run(mock_collector, mock_process_arg, mock_setup, mock_get_nodes, mock_ssh, mock_collect, mock_process):
    mock_collector.side_effect = [False, False]
    core.context.load_values = mock.Mock()
    core.run()
    mock_collector.assert_has_calls([mock.call(), mock.call()])


@mock.patch('sys.exit')
@mock.patch('logging.Logger.error')
@mock.patch('crmsh.report.core.is_collector')
def test_run_exception(mock_collector, mock_error, mock_exit):
    mock_collector.side_effect = utils.CRMReportError("error data")
    mock_exit.side_effect = SystemExit
    with pytest.raises(SystemExit):
        core.run()
    mock_error.assert_called_once_with("error data")


@mock.patch('crmsh.report.sanitize.sanitize')
@mock.patch('logging.Logger.error')
@mock.patch('crmsh.report.core.Pool')
@mock.patch('crmsh.report.core.generate_collect_functions')
@mock.patch('crmsh.report.collect.get_journal_ha')
@mock.patch('crmsh.report.core.dump_context')
def test_collect_logs_and_info(mock_context, mock_ha_log, mock_generate, mock_pool, mock_error, mock_sanitize):
    mock_generate.return_value = ["collect_sys_info", "collect_sys_stats"]
    mock_pool_inst = mock.Mock()
    mock_pool.return_value = mock_pool_inst
    mock_result_inst1 = mock.Mock()
    mock_result_inst2 = mock.Mock()
    mock_pool_inst.apply_async.side_effect = [mock_result_inst1, mock_result_inst2]
    mock_result_inst2.get.side_effect = utils.CRMReportError("error data")

    core.collect_logs_and_info()

    mock_context.assert_called_once_with()
    mock_ha_log.assert_called_once_with()
    mock_generate.assert_called_once_with()
    mock_pool.assert_called_once_with(processes=2)
    mock_pool_inst.apply_async.assert_has_calls([
        mock.call(collect.collect_sys_info),
        mock.call(collect.collect_sys_stats)
        ])
    mock_pool_inst.close.assert_called_once_with()
    mock_pool_inst.join.assert_called_once_with()
    mock_result_inst1.get.assert_called_once_with()
    mock_result_inst2.get.assert_called_once_with()
    mock_error.assert_called_once_with("error data")
    mock_sanitize.assert_called_once_with()


@mock.patch('crmsh.report.core.finalword')
@mock.patch('shutil.move')
@mock.patch('crmsh.report.core.touch_timespan_file')
@mock.patch('crmsh.report.core.dump_context')
def test_process_results_no_compress(mock_context, mock_timespan, mock_move, mock_finalword):
    core.context.no_compress = True
    core.context.work_dir = "work_dir"
    core.context.dest_dir = "dest_dir"
    core.process_results()
    mock_move.assert_called_once_with(core.context.work_dir, core.context.dest_dir)


@mock.patch('crmsh.report.core.finalword')
@mock.patch('crmsh.report.utils.get_stdout_or_raise_error')
@mock.patch('logging.Logger._log')
@mock.patch('crmsh.report.core.pick_compress')
@mock.patch('crmsh.report.core.touch_timespan_file')
@mock.patch('crmsh.report.core.dump_context')
def test_process_results(mock_context, mock_timespan, mock_pick, mock_debug2, mock_run, mock_finalword):
    core.context.no_compress = False
    core.context.work_dir = "work_dir"
    core.context.dest_dir = "dest_dir"
    core.context.dest = "dest"
    core.context.compress_prog = "tar"
    core.context.compress_ext = ".bz2"
    core.process_results()
    mock_run.assert_called_once_with('(cd work_dir/.. && tar cf - dest)|tar > dest_dir/dest.tar.bz2')


@mock.patch('crmsh.report.core.crmutils.str2file')
@mock.patch('crmsh.report.utils.work_path')
def test_dump_context(mock_work_path, mock_str2file):
    mock_work_path.return_value = "work_path/{}".format(const.CTX_F)
    core.context.dumps = mock.Mock()
    core.context.dumps.return_value = "data"
    core.dump_context()
    mock_str2file.assert_called_once_with("data", mock_work_path.return_value)


@mock.patch('crmsh.report.core.crmutils.str2file')
@mock.patch('crmsh.report.utils.work_path')
def test_touch_timespan_file(mock_work_path, mock_str2file):
    mock_work_path.return_value = "work_path/{}".format(const.TIMESPAN_F)
    core.context.from_time_str = "123"
    core.context.to_time_str = "456"
    core.context.delta_time_str = "1day"
    core.touch_timespan_file()
    mock_str2file.assert_called_once_with("Report timespan: {} - {}, {}".format(core.context.from_time_str, core.context.to_time_str, core.context.delta_time_str), mock_work_path.return_value)


@mock.patch('crmsh.report.core.crmutils.is_program')
def test_pick_compress(mock_program):
    mock_program.return_value = True
    core.pick_compress()
    assert core.context.compress_prog == "bzip2"
    assert core.context.compress_ext == ".bz2"


@mock.patch('logging.Logger.info')
def test_finalword_no_compress(mock_info):
    core.context.no_compress = True
    core.context.dest_dir = "dest_dir"
    core.context.dest = "dest"
    dest_path = "{}/{}".format(core.context.dest_dir, core.context.dest)
    core.context.from_time_str = 123
    core.context.to_time_str = 456
    core.finalword()
    mock_info.assert_has_calls([
        mock.call("The report is saved in %s", dest_path),
        mock.call("Report timespan: %s - %s", core.context.from_time_str, core.context.to_time_str),
        mock.call("Thank you for taking time to create this report.")
        ])


@mock.patch('logging.Logger.info')
def test_finalword(mock_info):
    core.context.no_compress = False
    core.context.dest_dir = "dest_dir"
    core.context.dest = "dest"
    core.context.compress_ext = ".bz2"
    dest_path = "{}/{}.tar{}".format(core.context.dest_dir, core.context.dest, core.context.compress_ext)
    core.context.from_time_str = 123
    core.context.to_time_str = 456
    core.finalword()
    mock_info.assert_has_calls([
        mock.call("The report is saved in %s", dest_path),
        mock.call("Report timespan: %s - %s", core.context.from_time_str, core.context.to_time_str),
        mock.call("Thank you for taking time to create this report.")
        ])


def test_check_exclusive_options_fb():
    args = mock.Mock(from_time=True, before_time=True)
    with pytest.raises(utils.CRMReportError) as err:
        core.check_exclusive_options(args)
    assert str(err.value) == "-f and -b options are exclusive"


def test_check_exclusive_options_tb():
    args = mock.Mock(to_time=True, before_time=True, from_time=False)
    with pytest.raises(utils.CRMReportError) as err:
        core.check_exclusive_options(args)
    assert str(err.value) == "-t and -b options are exclusive"


def test_check_exclusive_options_ns():
    args = mock.Mock(nodes=True, single=True, before_time=False)
    with pytest.raises(utils.CRMReportError) as err:
        core.check_exclusive_options(args)
    assert str(err.value) == "-n and -S options are exclusive"


def test_check_exclusive_options_em():
    args = mock.Mock(extra_logs=True, no_extra=True, before_time=False, nodes=False)
    with pytest.raises(utils.CRMReportError) as err:
        core.check_exclusive_options(args)
    assert str(err.value) == "-E and -M options are exclusive"


def test_process_option_value_debug():
    res = core.process_option_value("debug", True)
    assert res == True
    assert crmutils.is_boolean_true(report.verbosity) == True


def test_process_option_value_time_expection():
    with pytest.raises(utils.CRMReportError) as err:
        core.process_option_value("before_time", "1234")
    assert str(err.value) == 'Wrong format of -b option "1234" (valid examples: 30M; 12H; 10d; 2m; 1Y)'


@mock.patch('crmsh.report.utils.parse_to_timestamp')
def test_process_option_value_from_time(mock_parse):
    mock_parse.return_value = 12345
    res = core.process_option_value("from_time", "123")
    assert res == mock_parse.return_value
    mock_parse.assert_called_once_with("123")


@mock.patch('crmsh.report.core.crmutils.parse_append_action_argument')
def test_process_option_value_ssh_exception(mock_parse_append):
    mock_parse_append.return_value = ["zhao", "qian"]
    with pytest.raises(utils.CRMReportError) as err:
        core.process_option_value("ssh_options", ["zhao", "qian"])
    assert str(err.value) == 'Wrong format of -X option "zhao" (valid format: \w+=\w+)'
    mock_parse_append.assert_called_once_with(["zhao", "qian"])


@mock.patch('crmsh.report.utils.unique_list')
@mock.patch('crmsh.report.core.crmutils.parse_append_action_argument')
def test_process_option_value_nodes(mock_parse_append, mock_unique):
    mock_parse_append.return_value = ["node1", "node2", "node2"]
    mock_unique.return_value = ["node1", "node2"]
    res = core.process_option_value("nodes", ["node1", "node2", "node2"])
    assert res == mock_unique.return_value
    mock_unique.assert_called_once_with(mock_parse_append.return_value)


@mock.patch('crmsh.report.core.crmutils.parse_append_action_argument')
def test_process_option_value_sensitive(mock_parse_append):
    mock_parse_append.return_value = ["patt1"]
    core.context.sensitive_regex_list = ["patt2", "patt3"]
    res = core.process_option_value("sensitive_regex_list", ["patt1"])
    assert res == ["patt1", "patt2", "patt3"]


@mock.patch('crmsh.report.core.crmutils.list_cluster_nodes')
def test_get_nodes_exception(mock_list_nodes):
    core.context.single = False
    core.context.nodes = []
    mock_list_nodes.return_value = None
    with pytest.raises(utils.CRMReportError) as err:
        core.get_nodes()
    assert str(err.value) == "Cannot figure out a list of nodes"


@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.core.crmutils.list_cluster_nodes')
def test_get_nodes(mock_list_nodes, mock_debug):
    core.context.single = False
    core.context.nodes = []
    mock_list_nodes.return_value = ["node1", "node2"]
    core.get_nodes()
    assert core.context.nodes == mock_list_nodes.return_value
    mock_list_nodes.assert_called_once_with()
    mock_debug.assert_called_once_with("Nodes to collect: %s", core.context.nodes)


@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.core.crmutils.this_node')
def test_get_nodes_single(mock_this_node, mock_debug):
    core.context.single = True
    mock_this_node.return_value = "node1"
    core.get_nodes()
    mock_debug.assert_called_once_with("Nodes to collect: %s", core.context.nodes)


@mock.patch('crmsh.report.utils.ts_to_str')
@mock.patch('logging.Logger.warning')
@mock.patch('crmsh.report.utils.findln_by_time')
@mock.patch('crmsh.report.utils.read_from_file')
def test_print_logseg_no_from_line(mock_read, mock_findln, mock_warning, mock_ts_to_str):
    mock_read.return_value = "line1\nline2\nline3\nline4\nline5"
    mock_findln.return_value = None
    mock_ts_to_str.return_value = "time str 123"
    res = core.print_logseg("log1", "123", "456")
    assert res == ""
    mock_read.assert_called_once_with("log1")
    mock_findln.assert_called_once_with(mock_read.return_value, "123")
    mock_warning.assert_called_once_with("Couldn't find line in %s for time %s", "log1", mock_ts_to_str.return_value)


@mock.patch('crmsh.report.utils.ts_to_str')
@mock.patch('logging.Logger.warning')
@mock.patch('crmsh.report.utils.findln_by_time')
@mock.patch('crmsh.report.utils.read_from_file')
def test_print_logseg_no_to_line(mock_read, mock_findln, mock_warning, mock_ts_to_str):
    mock_read.return_value = "line1\nline2\nline3\nline4\nline5"
    mock_findln.side_effect = [1, None]
    mock_ts_to_str.return_value = "time str 456"
    res = core.print_logseg("log1", "123", "456")
    assert res == ""
    mock_read.assert_called_once_with("log1")
    mock_findln.assert_has_calls([
        mock.call(mock_read.return_value, "123"),
        mock.call(mock_read.return_value, "456", left_value=True)
        ])
    mock_warning.assert_called_once_with("Couldn't find line in %s for time %s", "log1", mock_ts_to_str.return_value)


@mock.patch('logging.Logger._log')
@mock.patch('crmsh.report.utils.findln_by_time')
@mock.patch('crmsh.report.utils.read_from_file')
def test_print_logseg(mock_read, mock_findln, mock_debug2):
    mock_read.return_value = "line1\nline2\nline3\nline4\nline5"
    mock_findln.side_effect = [1, 4]
    res = core.print_logseg("log1", "123", "456")
    assert res == "line1\nline2\nline3\nline4\n"
    mock_read.assert_called_once_with("log1")
    mock_findln.assert_has_calls([
        mock.call(mock_read.return_value, "123"),
        mock.call(mock_read.return_value, "456", left_value=True)
        ])


@mock.patch('logging.Logger._log')
@mock.patch('crmsh.report.core.arch_logs')
def test_dump_logset_return(mock_arch_logs, mock_log):
    mock_arch_logs.return_value = (None, [])
    core.dump_logset("file1")
    mock_arch_logs.assert_called_once_with("file1")
    mock_log.assert_called_once_with(15, 'No suitable log set found for log %s', ('file1',))


@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('crmsh.report.core.crmutils.str2file')
@mock.patch('crmsh.report.utils.work_path')
@mock.patch('os.path.basename')
@mock.patch('logging.Logger._log')
@mock.patch('crmsh.report.core.print_logseg')
@mock.patch('crmsh.report.core.arch_logs')
def test_dump_logset_irregular(mock_arch_logs, mock_print, mock_log, mock_basename, mock_work_path, mock_str2file, mock_dest_path, mock_debug):
    mock_arch_logs.return_value = (core.LogfileType.IRREGULAR, ["file1"])
    mock_print.return_value = "data"
    mock_basename.return_value = "file1"
    mock_work_path.return_value = "work_path/file1"
    mock_dest_path.return_value = "dest_path/file1"

    core.dump_logset("file1")

    mock_arch_logs.assert_called_once_with("file1")
    mock_print.assert_called_once_with("file1", 0, 0)
    mock_log.assert_called_once_with(15, 'Including complete file "%s"', ('file1',))
    mock_str2file.assert_called_once_with("data", mock_work_path.return_value)
    mock_debug.assert_called_once_with('Dump logset "%s" into %s', ["file1"], mock_dest_path.return_value)


@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('crmsh.report.core.crmutils.str2file')
@mock.patch('crmsh.report.utils.work_path')
@mock.patch('os.path.basename')
@mock.patch('logging.Logger._log')
@mock.patch('crmsh.report.core.print_logseg')
@mock.patch('crmsh.report.core.arch_logs')
def test_dump_logset_good_onefile(mock_arch_logs, mock_print, mock_log, mock_basename, mock_work_path, mock_str2file, mock_dest_path, mock_debug):
    mock_arch_logs.return_value = (core.LogfileType.GOOD, ["file1"])
    mock_print.return_value = "data"
    mock_basename.return_value = "file1"
    mock_work_path.return_value = "work_path/file1"
    mock_dest_path.return_value = "dest_path/file1"
    core.context.from_time = "123"
    core.context.from_time_str = "str 123"
    core.context.to_time = "456"
    core.context.to_time_str = "str 456"

    core.dump_logset("file1")

    mock_arch_logs.assert_called_once_with("file1")
    mock_print.assert_called_once_with("file1", core.context.from_time, core.context.to_time)
    mock_log.assert_called_once_with(15, 'Including incomplete file "%s", from %s to %s', ('file1', core.context.from_time_str, core.context.to_time_str,))
    mock_str2file.assert_called_once_with("data", mock_work_path.return_value)
    mock_debug.assert_called_once_with('Dump logset "%s" into %s', ["file1"], mock_dest_path.return_value)


@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('crmsh.report.core.crmutils.str2file')
@mock.patch('crmsh.report.utils.work_path')
@mock.patch('os.path.basename')
@mock.patch('logging.Logger._log')
@mock.patch('crmsh.report.core.print_logseg')
@mock.patch('crmsh.report.core.arch_logs')
def test_dump_logset_good_multifiles(mock_arch_logs, mock_print, mock_log, mock_basename, mock_work_path, mock_str2file, mock_dest_path, mock_debug):
    mock_arch_logs.return_value = (core.LogfileType.GOOD, ["file1", "file2", "file3"])
    mock_print.side_effect = ["data1\n", "data2\n", "data3\n"]
    mock_basename.return_value = "file1"
    mock_work_path.return_value = "work_path/file1"
    mock_dest_path.return_value = "dest_path/file1"
    core.context.from_time = "123"
    core.context.from_time_str = "str 123"
    core.context.to_time = "456"
    core.context.to_time_str = "str 456"

    core.dump_logset("file1")

    mock_arch_logs.assert_called_once_with("file1")
    mock_print.assert_has_calls([
        mock.call("file3", core.context.from_time, 0),
        mock.call("file2", 0, 0),
        mock.call("file1", 0, core.context.to_time)
        ])
    mock_log.assert_has_calls([
        mock.call(15, 'Including incomplete file "%s", from %s to the last line', ("file3", core.context.from_time_str,)),
        mock.call(15, 'Including complete file "%s"', ("file2",)),
        mock.call(15, 'Including incomplete file "%s", from the first line to %s', ("file1", core.context.to_time_str,))
        ])
    mock_str2file.assert_called_once_with("data1\ndata2\ndata3", mock_work_path.return_value)
    mock_debug.assert_called_once_with('Dump logset "%s" into %s', ["file1", "file2", "file3"], mock_dest_path.return_value)


@mock.patch('os.path.isdir')
def test_validate_dest_exist_dir_exception(mock_isdir):
    core.context.dest = "report"
    core.context.no_compress = True
    mock_isdir.return_value = True
    core.context.rm_exist_dest = False
    with pytest.raises(utils.CRMReportError) as err:
        core.validate_dest()
    assert str(err.value) == 'Destination directory "report" exists, please cleanup or use -Z option'


@mock.patch('os.path.dirname')
@mock.patch('os.path.isdir')
def test_validate_dest_not_dir_exception(mock_isdir, mock_dirname):
    core.context.dest = "dir/report"
    mock_isdir.side_effect = [False, False]
    mock_dirname.return_value = "dir"
    with pytest.raises(utils.CRMReportError) as err:
        core.validate_dest()
    assert str(err.value) == "\"dir\" isn't a directory"


@mock.patch('crmsh.report.core.crmutils.is_filename_sane')
@mock.patch('os.path.basename')
@mock.patch('os.path.dirname')
@mock.patch('os.path.isdir')
def test_validate_dest_invalid_name_exception(mock_isdir, mock_dirname, mock_basename, mock_sane_name):
    core.context.dest = "dir/report"
    mock_isdir.side_effect = [False, True]
    mock_basename.return_value = "report"
    mock_dirname.return_value = "dir"
    mock_sane_name.return_value = False
    with pytest.raises(utils.CRMReportError) as err:
        core.validate_dest()
    assert str(err.value) == "\"report\" is invalid file name"


@mock.patch('crmsh.report.core.crmutils.is_filename_sane')
@mock.patch('os.path.basename')
@mock.patch('os.path.dirname')
@mock.patch('shutil.rmtree')
@mock.patch('os.path.isdir')
def test_validate_dest(mock_isdir, mock_rmtree, mock_dirname, mock_basename, mock_sane_name):
    core.context.dest = "dir/report"
    core.context.no_compress = True
    core.context.rm_exist_dest = True
    mock_isdir.side_effect = [True, True]
    mock_basename.return_value = "report"
    mock_dirname.return_value = ""
    mock_sane_name.return_value = True
    core.validate_dest()
    assert core.context.dest == "report"
    assert core.context.dest_dir == "."
    mock_rmtree.assert_called_once_with("dir/report")


@mock.patch('crmsh.report.core.start_collector')
@mock.patch('logging.Logger.info')
@mock.patch('crmsh.report.core.Pool')
def test_collect_for_nodes(mock_pool, mock_info, mock_collector):
    core.context.nodes = ["node1", "node2", "node3"]
    core.context.ssh_askpw_nodes = ["node3"]
    core.context.ssh_user = None
    mock_pool_inst = mock.Mock()
    mock_pool.return_value = mock_pool_inst
    core.collect_for_nodes()
    mock_pool.assert_called_once_with(processes=2)
    mock_pool_inst.apply_async.assert_has_calls([
        mock.call(core.start_collector, args=("node1",)),
        mock.call(core.start_collector, args=("node2",))
        ])
    mock_collector.assert_called_once_with("node3")


@mock.patch('logging.Logger._log')
@mock.patch('crmsh.report.core.process_context_value')
@mock.patch('crmsh.report.core.process_option_value')
@mock.patch('crmsh.report.core.crmutils.check_space_option_value')
@mock.patch('crmsh.report.core.check_exclusive_options')
@mock.patch('crmsh.report.core.parse_argument')
def test_process_argument(mock_parse, mock_check_exclue, mock_check_space, mock_process_option, mock_process_context, mock_debug):
    class Ctx:
        def __init__(self, from_time, to_time, need_help):
            self.from_time = from_time
            self.to_time = to_time
            self.need_help = need_help
    mock_parse_inst = Ctx(from_time=123, to_time=456, need_help=None)
    mock_parse.return_value = mock_parse_inst
    mock_process_option.side_effect = [123, 456]
    core.process_argument()
    mock_check_exclue.assert_called_once_with(mock_parse_inst)
    mock_check_space.assert_called_once_with(mock_parse_inst)
    mock_process_option.assert_has_calls([
        mock.call('from_time', 123),
        mock.call('to_time', 456)
        ])
