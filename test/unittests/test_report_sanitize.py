import pytest
from unittest import mock

from crmsh import config
from crmsh.report import core, sanitize, utils, const


def test_load_sanitize_rule_empty():
    config.report.sanitize_rule = ''
    assert sanitize.load_sanitize_rule() == []


def test_load_sanitize_rule():
    config.report.sanitize_rule = "passw.*  | ip.*:raw | TEL | TEL"
    assert sorted(sanitize.load_sanitize_rule()) == sorted(["TEL", "ip.*:raw", "passw.*"])


def test_parse_sanitize_rule_exception():
    rule_list = ["ip.*:test"]
    with pytest.raises(utils.CRMReportError) as err:
        sanitize.parse_sanitize_rule(rule_list)
    assert str(err.value) == 'For sanitize_pattern ip.*, option should be "raw"'


@mock.patch('logging.Logger._log')
def test_parse_sanitize_rule(mock_debug):
    rule_list = ["TEL", "ip.*:raw", "passw.*"]
    sanitize.parse_sanitize_rule(rule_list)
    assert core.context.sanitize_rule_dict == {'TEL': None, 'ip.*': 'raw', 'passw.*': None}


@mock.patch('logging.Logger._log')
def test_parse_sanitize_none(mock_debug):
    core.context.sanitize_rule_dict = {}
    sanitize.parse_sanitize_rule(None)
    assert core.context.sanitize_rule_dict == {'passw.*': None}


@mock.patch('logging.Logger.warning')
@mock.patch('os.path.exists')
@mock.patch('crmsh.report.utils.work_path')
def test_extract_sensitive_value_list_no_file(mock_work_path, mock_exists, mock_warning):
    mock_work_path.return_value = "work_path/{}".format(const.CIB_F)
    mock_exists.return_value = False
    assert sanitize.extract_sensitive_value_list("rule") == []
    mock_warning.assert_called_once_with("File %s was not collected", const.CIB_F)


@mock.patch('logging.Logger.warning')
@mock.patch('crmsh.report.utils.read_from_file')
@mock.patch('os.path.exists')
@mock.patch('crmsh.report.utils.work_path')
def test_extract_sensitive_value_list_empty(mock_work_path, mock_exists, mock_read, mock_warning):
    mock_work_path.return_value = "work_path/{}".format(const.CIB_F)
    mock_exists.return_value = True
    mock_read.return_value = ""
    assert sanitize.extract_sensitive_value_list("rule") == []
    mock_warning.assert_called_once_with("File %s is empty", mock_work_path.return_value)


@mock.patch('crmsh.report.utils.read_from_file')
@mock.patch('os.path.exists')
@mock.patch('crmsh.report.utils.work_path')
def test_extract_sensitive_value_list(mock_work_path, mock_exists, mock_read):
    mock_work_path.return_value = "work_path/{}".format(const.CIB_F)
    mock_exists.return_value = True
    mock_read.return_value = '<nvpair id="nodes-1084783297-utilization-password" name="password" value="qwertyui"/>'
    res = sanitize.extract_sensitive_value_list("passw.*")
    assert res == ["qwertyui"]


@mock.patch('crmsh.report.sanitize.extract_sensitive_value_list')
def test_get_sensitive_key_value_list(mock_extract):
    core.context.sanitize_rule_dict = {
            'TEL': None,
            'ip': 'raw'
            }
    core.context.sanitize_value_raw_list = []
    core.context.sanitize_value_cib_list = []
    mock_extract.side_effect = [['123456789'], ['10.10.10.123']]
    sanitize.get_sensitive_key_value_list()
    assert core.context.sanitize_value_raw_list == ['10.10.10.123']
    assert core.context.sanitize_value_cib_list == ['123456789']
    assert core.context.sanitize_key_cib_list == ['TEL.*?']


def test_include_sensitive_data_true():
    core.context.sanitize_value_raw_list = [1,2,3]
    assert sanitize.include_sensitive_data() == True


def test_include_sensitive_data_false():
    core.context.sanitize_value_raw_list = []
    core.context.sanitize_value_cib_list = []
    assert sanitize.include_sensitive_data() == False


def test_sub_sensitive_string():
    data = """<nvpair name="ip" value="10.10.10.124" id="ip2-instance_attributes-ip"/>
<nvpair id="nodes-1084783297-utilization-password" name="password" value="qwertyui"/>"""
    expected_data = """<nvpair name="ip" value="******" id="ip2-instance_attributes-ip"/>
<nvpair id="nodes-1084783297-utilization-password" name="password" value="******"/>"""
    core.context.sanitize_value_raw_list = ["10.10.10.124"]
    core.context.sanitize_value_cib_list = ["qwertyui"]
    core.context.sanitize_key_cib_list = ["passw.*"]
    res = sanitize.sub_sensitive_string(data)
    assert res == expected_data


@mock.patch('logging.Logger.warning')
@mock.patch('crmsh.report.sanitize.include_sensitive_data')
@mock.patch('crmsh.report.sanitize.get_sensitive_key_value_list')
@mock.patch('logging.Logger.debug')
def test_sanitize_return(mock_debug, mock_get_list, mock_include, mock_warning):
    mock_include.return_value = True
    core.context.do_sanitize = False
    sanitize.sanitize()
    mock_debug.assert_called_once_with("Check or replace sensitive info from CIB, PE and log files")
    mock_warning.assert_has_calls([
        mock.call("Some PE/CIB/log files contain possibly sensitive data"),
        mock.call('Using "-s" option can replace sensitive data')
        ])


@mock.patch('crmsh.report.utils.write_to_file')
@mock.patch('crmsh.report.sanitize.sub_sensitive_string')
@mock.patch('crmsh.report.utils.read_from_file')
@mock.patch('os.path.isfile')
@mock.patch('os.path.join')
@mock.patch('os.walk')
@mock.patch('crmsh.report.sanitize.include_sensitive_data')
@mock.patch('crmsh.report.sanitize.get_sensitive_key_value_list')
@mock.patch('logging.Logger.debug')
def test_sanitize(mock_debug, mock_get_list, mock_include, mock_walk, mock_join, mock_isfile, mock_read, mock_sub, mock_write):
    mock_include.return_value = False
    core.context.work_dir = "work_dir"
    mock_walk.return_value = [("dir", None, ["file1", "file2"])]
    mock_join.side_effect = ["dir/file1", "dir/file2"]
    mock_isfile.side_effect = [True, True]
    mock_read.side_effect = ["", "data"]
    mock_sub.return_value = "sub_data"
    sanitize.sanitize()
    mock_debug.assert_called_once_with("Check or replace sensitive info from CIB, PE and log files")
    mock_get_list.assert_called_once_with()
    mock_include.assert_called_once_with()
    mock_walk.assert_called_once_with(core.context.work_dir)
    mock_join.assert_has_calls([
        mock.call("dir", "file1"),
        mock.call("dir", "file2")
        ])
    mock_write.assert_called_once_with("dir/file2", "sub_data")
