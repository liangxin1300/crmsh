from unittest import mock

from crmsh.report import collect, core, const, utils


@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.collect.find_pe_files')
def test_collect_pe_inputs_not_found(mock_find_pe, mock_debug):
    mock_find_pe.return_value = []
    collect.collect_pe_inputs()
    mock_find_pe.assert_called_once_with()
    mock_debug.assert_called_once_with("Nothing found for PE files in the giving time")


@mock.patch('crmsh.report.collect.convert_pe_dot_files')
@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('os.symlink')
@mock.patch('os.path.join')
@mock.patch('crmsh.report.collect.crmutils.mkdirp')
@mock.patch('crmsh.report.utils.work_path')
@mock.patch('os.path.basename')
@mock.patch('crmsh.report.collect.find_pe_files')
def test_collect_pe_inputs(mock_find_pe, mock_basename, mock_work_path, mock_mkdir, mock_join, mock_symlink, mock_dest_path, mock_debug, mock_convert):
    mock_find_pe.return_value = ["/var/lib/pacemaker/pengine/pe-input-1.bz2",
            "/var/lib/pacemaker/pengine/pe-input-2.bz2"]
    core.context.pe_state_dir = "/var/lib/pacemaker/pengine"
    mock_basename.side_effect = ["pengine", "pe-input-1.bz2", "pe-input-2.bz2"]
    mock_work_path.return_value = "work_path/pengine"
    mock_join.side_effect = ["work_path/pengine/pe-input-1.bz2",
            "work_path/pengine/pe-input-2.bz2"]
    mock_dest_path.return_value = "dest_path/pengine"

    collect.collect_pe_inputs()

    mock_find_pe.assert_called_once_with()
    mock_basename.assert_has_calls([
        mock.call(core.context.pe_state_dir),
        mock.call("/var/lib/pacemaker/pengine/pe-input-1.bz2"),
        mock.call("/var/lib/pacemaker/pengine/pe-input-2.bz2")
        ])
    mock_symlink.assert_has_calls([
        mock.call("/var/lib/pacemaker/pengine/pe-input-1.bz2", "work_path/pengine/pe-input-1.bz2"),
        mock.call("/var/lib/pacemaker/pengine/pe-input-2.bz2", "work_path/pengine/pe-input-2.bz2")
        ])
    mock_debug.assert_called_once_with("Dump %d pengine input files into %s", 2, mock_dest_path.return_value)


@mock.patch('logging.Logger.debug')
def test_convert_pe_dot_files_skip(mock_debug):
    core.context.speed_up = True
    collect.convert_pe_dot_files([], "dir")
    mock_debug.assert_called_once_with("Skip converting PE inputs to dot files")


@mock.patch('logging.Logger.debug')
def test_convert_pe_dot_files_max(mock_debug):
    core.context.speed_up = False
    const.MAX_PE_FILES = 2
    collect.convert_pe_dot_files(["file1", "file2", "file3"], "dir")
    mock_debug.assert_called_once_with("Too many PE inputs to create dot files")


@mock.patch('crmsh.report.collect.pe_to_dot')
@mock.patch('os.path.basename')
@mock.patch('os.path.join')
def test_convert_pe_dot_files(mock_join, mock_basename, mock_to_dot):
    core.context.speed_up = False
    mock_basename.return_value = "file1"
    mock_join.return_value = "dir/file1"
    collect.convert_pe_dot_files(["file1"], "dir")
    mock_basename.assert_called_once_with("file1")
    mock_join.assert_called_once_with("dir", mock_basename.return_value)
    mock_to_dot.assert_called_once_with(mock_join.return_value)


@mock.patch('logging.Logger.error')
@mock.patch('crmsh.report.collect.crmutils.get_stdout_stderr')
def test_pe_to_dot(mock_run, mock_error):
    mock_run.return_value = (1, None, "error")
    collect.pe_to_dot("work_path/pengine/pe-input-2.bz")
    cmd = "%s -D %s -x %s" % (const.PTEST, "work_path/pengine/pe-input-2.dot", "work_path/pengine/pe-input-2.bz")
    mock_run.assert_called_once_with(cmd)


@mock.patch('logging.Logger.error')
@mock.patch('crmsh.report.collect.crmutils.get_stdout_stderr')
@mock.patch('os.path.exists')
@mock.patch('crmsh.report.utils.which')
def test_get_ocfs2_related_output(mock_which, mock_exits, mock_run, mock_error):
    const.OCFS2_CMD_LIST = ["cmd1", "cat file1"]
    mock_which.side_effect = [True, True]
    mock_exits.return_value = False
    mock_run.return_value = (0, "data", "error")
    res = collect.get_ocfs2_related_output()
    assert res == "\n\n#=====[ Command ] ==========================#\n# cmd1\ndata"
    mock_which.assert_has_calls([
        mock.call("cmd1"),
        mock.call("cat")
        ])
    mock_exits.assert_called_once_with("file1")
    mock_run.assert_called_once_with("cmd1")
    mock_error.assert_called_once_with("error")


@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('crmsh.report.collect.crmutils.str2file')
@mock.patch('crmsh.report.utils.work_path')
@mock.patch('crmsh.report.collect.crmutils.get_stdout_stderr')
def test_collect_ocfs2_info_error(mock_run, mock_work_path, mock_str2file, mock_dest_path, mock_debug):
    mock_run.return_value = (1, None, "error")
    mock_work_path.return_value = "work_path/{}".format(const.OCFS2_F)
    mock_dest_path.return_value = "dest_path/{}".format(const.OCFS2_F)
    collect.collect_ocfs2_info()
    mock_run.assert_called_once_with("mounted.ocfs2 -d")
    mock_str2file.assert_called_once_with("Failed to run \"mounted.ocfs2 -d\": error", mock_work_path.return_value)
    mock_debug.assert_called_once_with("Dump OCFS2 info into %s", mock_dest_path.return_value)


@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('crmsh.report.collect.crmutils.str2file')
@mock.patch('crmsh.report.utils.work_path')
@mock.patch('crmsh.report.collect.crmutils.get_stdout_stderr')
def test_collect_ocfs2_info_not_found(mock_run, mock_work_path, mock_str2file, mock_dest_path, mock_debug):
    mock_run.return_value = (0, "data", None)
    mock_work_path.return_value = "work_path/{}".format(const.OCFS2_F)
    mock_dest_path.return_value = "dest_path/{}".format(const.OCFS2_F)
    collect.collect_ocfs2_info()
    mock_run.assert_called_once_with("mounted.ocfs2 -d")
    mock_str2file.assert_called_once_with("No ocfs2 partitions found", mock_work_path.return_value)
    mock_debug.assert_called_once_with("Dump OCFS2 info into %s", mock_dest_path.return_value)


@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('crmsh.report.collect.crmutils.str2file')
@mock.patch('crmsh.report.utils.work_path')
@mock.patch('crmsh.report.collect.get_ocfs2_related_output')
@mock.patch('crmsh.report.collect.lsof_ocfs2_device')
@mock.patch('crmsh.report.collect.dump_D_process')
@mock.patch('crmsh.report.collect.crmutils.get_stdout_stderr')
def test_collect_ocfs2_info(mock_run, mock_dump_D, mock_lsof, mock_related_output, mock_work_path, mock_str2file, mock_dest_path, mock_debug):
    mock_run.return_value = (0, "data1\ndata2", None)
    mock_work_path.return_value = "work_path/{}".format(const.OCFS2_F)
    mock_dest_path.return_value = "dest_path/{}".format(const.OCFS2_F)
    mock_dump_D.return_value = "dump data\n"
    mock_lsof.return_value = "lsof data\n"
    mock_related_output.return_value = "other data"

    collect.collect_ocfs2_info()

    mock_run.assert_called_once_with("mounted.ocfs2 -d")
    mock_str2file.assert_called_once_with("dump data\nlsof data\nother data", mock_work_path.return_value)
    mock_debug.assert_called_once_with("Dump OCFS2 info into %s", mock_dest_path.return_value)


@mock.patch('crmsh.report.collect.crmutils.get_stdout_stderr')
def test_dump_D_process_zero(mock_run):
    mock_run.return_value = (0, None, None)
    res = collect.dump_D_process()
    assert res == "Dump D-state process stack: 0\n"
    mock_run.assert_called_once_with("ps aux|awk '$8 ~ /^D/{print $2}'")


@mock.patch('crmsh.report.collect.crmutils.get_stdout_stderr')
def test_dump_D_process(mock_run):
    mock_run.side_effect = [(0, "31842", None), (0, "crm", None), (0, "stack data", None)]
    res = collect.dump_D_process()
    assert res == "Dump D-state process stack: 1\npid: 31842     comm: crm\nstack data\n\n"
    mock_run.assert_has_calls([
        mock.call("ps aux|awk '$8 ~ /^D/{print $2}'"),
        mock.call("cat /proc/31842/comm"),
        mock.call("cat /proc/31842/stack")
        ])


@mock.patch('crmsh.report.collect.crmutils.get_stdout_stderr')
@mock.patch('crmsh.report.utils.get_stdout_or_raise_error')
def test_lsof_ocfs2_device(mock_run_or_raise, mock_run):
    mock_run_or_raise.return_value = "\n/dev/sda3 on /srv/clusterfs type ocfs2 (rw"
    mock_run.return_value = (0, "data", None)
    res = collect.lsof_ocfs2_device()
    assert res == "\n\n#=====[ Command ] ==========================#\n# lsof /dev/sda3\ndata"
    mock_run_or_raise.assert_called_once_with("mount")
    mock_run.assert_called_once_with("lsof /dev/sda3")


@mock.patch('os.path.isfile')
def test_dump_corosync_log_return(mock_isfile):
    mock_isfile.return_value = False
    collect.dump_corosync_log()
    mock_isfile.assert_called_once_with(const.COROSYNC_CONF)


@mock.patch('crmsh.report.core.dump_logset')
@mock.patch('crmsh.corosync.get_value')
@mock.patch('os.path.isfile')
def test_dump_corosync_log(mock_isfile, mock_get_value, mock_dump):
    mock_isfile.side_effect = [True, True]
    mock_get_value.return_value = "corosync.log"
    collect.dump_corosync_log()
    mock_isfile.assert_has_calls([
        mock.call(const.COROSYNC_CONF),
        mock.call(mock_get_value.return_value)
        ])
    mock_dump.assert_called_once_with(mock_get_value.return_value)


@mock.patch('logging.Logger.debug')
def test_collect_extra_logs_return(mock_debug):
    core.context.no_extra = True
    collect.collect_extra_logs()
    mock_debug.assert_called_once_with("Skip collecting extra logs")


@mock.patch('crmsh.report.core.dump_logset')
@mock.patch('logging.Logger.warning')
@mock.patch('os.path.isfile')
def test_collect_extra_logs(mock_isfile, mock_warning, mock_dump):
    core.context.no_extra = False
    core.context.extra_logs = ["file1", "file2"]
    mock_isfile.side_effect = [False, True]
    collect.collect_extra_logs()
    mock_warning.assert_called_once_with("File %s not exist", "file1")
    mock_dump.assert_called_once_with("file2")


@mock.patch('crmsh.report.core.dump_logset')
@mock.patch('os.path.isfile')
@mock.patch('crmsh.report.collect.get_pcmk_log')
def test_dump_pcmk_log(mock_get_log, mock_isfile, mock_dump):
    mock_get_log.return_value = "pacemaker.log"
    mock_isfile.return_value = True
    collect.dump_pcmk_log()
    mock_get_log.assert_called_once_with()
    mock_isfile.assert_called_once_with(mock_get_log.return_value)
    mock_dump.assert_called_once_with(mock_get_log.return_value)


@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('os.path.basename')
@mock.patch('shutil.copy2')
@mock.patch('os.path.isfile')
def test_get_corosync_conf(mock_isfile, mock_copy2, mock_basename, mock_dest_path, mock_debug):
    mock_isfile.return_value = True
    mock_basename.return_value = "corosync.conf"
    mock_dest_path.return_value = "dest_path/corosync.conf"
    core.context.work_dir = "work_path"
    collect.get_corosync_conf()
    mock_isfile.assert_called_once_with(const.COROSYNC_CONF)
    mock_copy2.assert_called_once_with(const.COROSYNC_CONF, core.context.work_dir)
    mock_basename.assert_called_once_with(const.COROSYNC_CONF)
    mock_dest_path.assert_called_once_with(mock_basename.return_value)
    mock_debug.assert_called_once_with("Dump corosync config into %s", mock_dest_path.return_value)


@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('crmsh.report.utils.touch_file')
@mock.patch('crmsh.report.utils.work_path')
@mock.patch('crmsh.report.collect.crmutils.this_node')
@mock.patch('crmsh.report.collect.crmutils.get_dc')
def test_touch_dc(mock_dc, mock_this_node, mock_work_path, mock_touch, mock_dest_path, mock_debug):
    mock_dc.return_value = "node1"
    mock_this_node.return_value = "node1"
    mock_work_path.return_value = "work_path/{}".format(const.DC_FLAG)
    mock_dest_path.return_value = "dest_path/{}".format(const.DC_FLAG)
    collect.touch_dc()
    mock_dc.assert_called_once_with()
    mock_this_node.assert_called_once_with()
    mock_debug.assert_called_once_with("Node %s is DC, touch \"%s\" file", mock_dc.return_value, mock_dest_path.return_value)


@mock.patch('crmsh.report.collect.dump_corosync_log')
@mock.patch('crmsh.report.collect.dump_pcmk_log')
@mock.patch('crmsh.report.collect.get_crm_configure')
@mock.patch('crmsh.report.collect.dump_cluster_status')
@mock.patch('crmsh.report.collect.get_corosync_conf')
@mock.patch('crmsh.report.collect.touch_dc')
def test_collect_cluster_info(mock_dc, mock_corosync_conf, mock_cluster_status, mock_crm_config, mock_pcmk_log, mock_corosync_log):
    collect.collect_cluster_info()
    mock_corosync_conf.assert_called_once_with()
    mock_cluster_status.assert_called_once_with()
    mock_crm_config.assert_called_once_with()
    mock_pcmk_log.assert_called_once_with()
    mock_corosync_log.assert_called_once_with()


@mock.patch('logging.Logger.warning')
@mock.patch('os.path.isfile')
def test_get_pcmk_log_not_exist(mock_isfile, mock_warning):
    mock_isfile.return_value = False
    res = collect.get_pcmk_log()
    assert res is None
    mock_isfile.assert_called_once_with(const.PCMKCONF)
    mock_warning.assert_called_once_with("Not found \"%s\"", const.PCMKCONF)


@mock.patch('logging.Logger.warning')
@mock.patch('crmsh.report.utils.read_from_file')
@mock.patch('os.path.isfile')
def test_get_pcmk_log_empty(mock_isfile, mock_read, mock_warning):
    mock_isfile.return_value = True
    mock_read.return_value = None
    res = collect.get_pcmk_log()
    assert res is None
    mock_isfile.assert_called_once_with(const.PCMKCONF)
    mock_warning.assert_called_once_with("File \"%s\" is empty", const.PCMKCONF)


@mock.patch('crmsh.report.utils.read_from_file')
@mock.patch('os.path.isfile')
def test_get_pcmk_log(mock_isfile, mock_read):
    mock_isfile.return_value = True
    mock_read.return_value = """
# include messages of "info" severity (and, if debug and/or trace logging
# has been enabled, those as well). This log is of more use to developers and
# advanced system administrators, and when reporting problems.
PCMK_logfile=/var1/log/pacemaker/pacemaker.log
    """
    res = collect.get_pcmk_log()
    assert res == "/var1/log/pacemaker/pacemaker.log"
    mock_isfile.assert_called_once_with(const.PCMKCONF)
    mock_read.assert_called_once_with(const.PCMKCONF)


@mock.patch('logging.Logger._log')
@mock.patch('os.path.exists')
def test_collect_sbd_info_no_conf(mock_exits, mock_log):
    mock_exits.return_value = False
    collect.collect_sbd_info()
    mock_exits.assert_called_once_with(const.SBDCONF)


@mock.patch('logging.Logger.warning')
@mock.patch('crmsh.report.utils.which')
@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('os.path.basename')
@mock.patch('shutil.copy2')
@mock.patch('os.path.exists')
def test_collect_sbd_info_no_cmd(mock_exits, mock_copy2, mock_basename, mock_dest_path, mock_debug, mock_which, mock_warning):
    mock_exits.return_value = True
    mock_basename.return_value = "sbd"
    mock_dest_path.return_value = "dest_path/sbd"
    mock_which.return_value = False
    core.context.work_dir = "work_path"
    collect.collect_sbd_info()
    mock_exits.assert_called_once_with(const.SBDCONF)
    mock_copy2.assert_called_once_with(const.SBDCONF, core.context.work_dir)
    mock_debug.assert_called_once_with("Dump SBD config into %s", mock_dest_path.return_value)
    mock_which.assert_called_once_with("sbd")
    mock_warning.assert_called_once_with('Command "sbd" not exist')


@mock.patch('crmsh.report.collect.crmutils.str2file')
@mock.patch('crmsh.report.collect.crmutils.this_node')
@mock.patch('crmsh.report.utils.get_stdout_or_raise_error')
@mock.patch('crmsh.report.utils.work_path')
@mock.patch('crmsh.report.utils.which')
@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('os.path.basename')
@mock.patch('shutil.copy2')
@mock.patch('os.path.exists')
def test_collect_sbd_info(mock_exits, mock_copy2, mock_basename, mock_dest_path, mock_debug, mock_which, mock_work_path, mock_run, mock_this_node, mock_str2file):
    mock_exits.return_value = True
    mock_basename.return_value = "sbd"
    mock_dest_path.side_effect = ["dest_path/{}".format(const.SBDCONF), "dest_path/{}".format(const.SBD_F)]
    mock_which.return_value = True
    core.context.work_dir = "work_path"
    mock_this_node.return_value = "node1"
    mock_run.return_value = "data"
    mock_work_path.return_value = "work_path/{}".format(const.SBDCONF)

    collect.collect_sbd_info()

    mock_exits.assert_called_once_with(const.SBDCONF)
    mock_copy2.assert_called_once_with(const.SBDCONF, core.context.work_dir)
    mock_debug.assert_has_calls([
        mock.call("Dump SBD config into %s", "dest_path/{}".format(const.SBDCONF)),
        mock.call("Dump SBD info into %s", "dest_path/{}".format(const.SBD_F))
        ])
    mock_which.assert_called_once_with("sbd")
    cmd = ". {};export SBD_DEVICE;{};{}".format(const.SBDCONF, "sbd dump", "sbd list")
    mock_run.assert_called_once_with(cmd)
    out_string = '===== Run "{}" on node1 =====\ndata'.format(cmd)
    mock_str2file.assert_called_once_with(out_string, mock_work_path.return_value)


@mock.patch('crmsh.report.collect.run_cmd_and_record')
def test_get_journal_ha(mock_run):
    core.context.from_time_str = "2021-09-23 02:08"
    core.context.to_time_str = "2021-09-23 14:08"
    collect.get_journal_ha()
    expected_cmd = 'journalctl -u {} --since "{}" --until "{}" -o short-iso --no-pager | tail -n +2'.format(" -u ".join(const.HA_UNITS.split()), core.context.from_time_str, core.context.to_time_str)
    mock_run.assert_called_once_with("HA journal log", expected_cmd, const.HALOG_F)


@mock.patch('crmsh.report.collect.run_cmd_and_record')
def test_collect_journal_general(mock_run):
    core.context.from_time_str = "2021-09-23 02:08"
    core.context.to_time_str = "2021-09-23 14:08"
    collect.collect_journal_general()
    expected_cmd = 'journalctl --since "{}" --until "{}" -o short-iso --no-pager | tail -n +2'.format(core.context.from_time_str, core.context.to_time_str)
    mock_run.assert_called_once_with("All journal log", expected_cmd, const.JOURNAL_F)


@mock.patch('crmsh.report.utils.get_rpm_info')
def test_get_rpm_info(mock_rpm_info):
    mock_rpm_info.return_value = "rpm data"
    res = collect.get_rpm_info()
    assert res == "===== Cluster Stack Packages Version =====\n" + mock_rpm_info.return_value
    mock_rpm_info.assert_called_once_with(const.PACKAGES)


@mock.patch('logging.Logger.debug')
def test_rpm_verify_output_speed(mock_debug):
    core.context.speed_up = True
    res = collect.rpm_verify_output()
    assert res == ""
    mock_debug.assert_called_once_with("Skip verify cluster stack packages")


@mock.patch('crmsh.report.utils.verify_rpm')
def test_rpm_verify_output(mock_verify):
    core.context.speed_up = False
    mock_verify.return_value = "data"
    res = collect.rpm_verify_output()
    assert res == "\n===== Cluster Stack Packages Verify =====\n" + mock_verify.return_value
    mock_verify.assert_called_once_with(const.PACKAGES)


@mock.patch('crmsh.report.utils.distro_info')
@mock.patch('os.uname')
def test_get_system_info(mock_uname, mock_distro):
    mock_uname.return_value = ("Linux", None, "5.3.18-24.52-default", None, "x86_64")
    mock_distro.return_value = "SUSE Linux Enterprise Server 15 SP2"
    expected_output = """
===== System Info =====
Platform: Linux
Kernel release: 5.3.18-24.52-default
Architecture: x86_64
Distribution: SUSE Linux Enterprise Server 15 SP2
"""
    res = collect.get_system_info()
    assert res == expected_output
    mock_uname.assert_called_once_with()
    mock_distro.assert_called_once_with()


@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.collect.crmutils.str2file')
@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('crmsh.report.utils.work_path')
@mock.patch('crmsh.report.collect.get_system_info')
@mock.patch('crmsh.report.collect.rpm_verify_output')
@mock.patch('crmsh.report.collect.get_rpm_info')
def test_collect_sys_info(mock_rpm_info, mock_verify, mock_system_info, mock_work_path, mock_dest_path, mock_str2file, mock_debug):
    mock_rpm_info.return_value = "rpm data\n"
    mock_verify.return_value = "verify data\n"
    mock_system_info.return_value = "system data\n"
    mock_work_path.return_value = "work_path/{}".format(const.SYSINFO_F)
    mock_dest_path.return_value = "dest_path/{}".format(const.SYSINFO_F)

    collect.collect_sys_info()

    out_data = mock_rpm_info.return_value + mock_verify.return_value + mock_system_info.return_value
    mock_str2file.assert_called_once_with(out_data, mock_work_path.return_value)
    mock_debug.assert_called_once_with("Dump packages version and system info into %s", mock_dest_path.return_value)


@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.collect.crmutils.str2file')
@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('crmsh.report.utils.work_path')
@mock.patch('crmsh.report.collect.crmutils.this_node')
@mock.patch('logging.Logger.error')
@mock.patch('crmsh.report.collect.crmutils.get_stdout_stderr')
@mock.patch('crmsh.report.utils.get_stdout_stderr_timeout')
@mock.patch('crmsh.report.utils.which')
def test_collect_sys_stats(mock_which, mock_run_timeout, mock_run, mock_error, mock_this_node, mock_work_path, mock_dest_path, mock_str2file, mock_debug):
    mock_which.side_effect = [None for _ in range(len(const.SYSSTAT_CMD_LIST)-2)] + [True, True]
    mock_run_timeout.return_value = (0, "df data", None)
    mock_run.return_value = (1, None, "error data")
    mock_this_node.return_value = "node1"
    mock_work_path.return_value = "work_path/{}".format(const.SYSSTATS_F)
    mock_dest_path.return_value = "dest_path/{}".format(const.SYSSTATS_F)

    collect.collect_sys_stats()

    mock_which.assert_has_calls([mock.call(cmd.split()[0]) for cmd in const.SYSSTAT_CMD_LIST])
    mock_run_timeout.assert_called_once_with("df")
    mock_run.assert_called_once_with("cat /proc/cpuinfo")
    mock_debug.assert_called_once_with("Dump system stats into %s", mock_dest_path.return_value)
    mock_str2file.assert_called_once_with('===== Run "df" on node1 =====\ndf data\n\n', mock_work_path.return_value)


@mock.patch('crmsh.report.collect.run_cmd_and_record')
def test_dump_state(mock_run):
    collect.dump_state()
    mock_run.assert_has_calls([
        mock.call("crm_mon output", "crm_mon -1rR", const.CRM_MON_F),
        mock.call("cib xml", "cibadmin -Ql", const.CIB_F),
        mock.call("members of this partition", "crm_node -p", const.MEMBERSHIP_F)
        ])


@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.utils.touch_file')
@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('crmsh.report.utils.work_path')
@mock.patch('crmsh.report.collect.dump_state')
@mock.patch('crmsh.report.collect.crmutils.service_is_active')
def test_dump_cluster_status_running(mock_service_active, mock_dump, mock_work_path, mock_dest_path, mock_touch, mock_debug):
    mock_service_active.return_value = True
    mock_work_path.return_value = "work_path/{}".format(const.RUNNING_FLAG)
    mock_dest_path.return_value = "dest_path/{}".format(const.RUNNING_FLAG)

    collect.dump_cluster_status()

    mock_service_active.assert_called_once_with("pacemaker.service")
    mock_dump.assert_called_once_with()
    mock_work_path.assert_called_once_with(const.RUNNING_FLAG)
    mock_touch.assert_called_once_with(mock_work_path.return_value)
    mock_dest_path.assert_called_once_with(const.RUNNING_FLAG)
    mock_debug.assert_called_once_with('Cluster service is running, touch "%s" file', mock_dest_path.return_value)


@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.utils.touch_file')
@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('crmsh.report.utils.work_path')
@mock.patch('shutil.copy2')
@mock.patch('os.path.exists')
@mock.patch('os.path.join')
@mock.patch('crmsh.report.collect.crmutils.service_is_active')
def test_dump_cluster_status_stop(mock_service_active, mock_join, mock_exits, mock_copy, mock_work_path, mock_dest_path, mock_touch, mock_debug):
    mock_service_active.return_value = False
    core.context.crm_config = "/var/lib/pacemaker/cib"
    mock_join.return_value = "{}/{}".format(core.context.crm_config, const.CIB_F)
    mock_exits.return_value = True
    mock_dest_path.side_effect = ["dest_path/{}".format(const.CIB_F), "dest_path/{}".format(const.STOPPED_FLAG)]
    mock_work_path.return_value = "work_path/{}".format(const.STOPPED_FLAG)

    collect.dump_cluster_status()

    mock_service_active.assert_called_once_with("pacemaker.service")
    mock_join.assert_called_once_with(core.context.crm_config, const.CIB_F)
    mock_exits.assert_called_once_with(mock_join.return_value)
    mock_copy.assert_called_once_with(mock_join.return_value, core.context.work_dir)
    mock_dest_path.assert_has_calls([
        mock.call(const.CIB_F),
        mock.call(const.STOPPED_FLAG)
        ])
    mock_debug.assert_has_calls([
        mock.call("Dump cib xml into %s", "dest_path/{}".format(const.CIB_F)),
        mock.call("Cluster service is stopped, touch \"%s\" file", "dest_path/{}".format(const.STOPPED_FLAG))
        ])


@mock.patch('crmsh.report.collect.dump_crm_verify')
@mock.patch('crmsh.report.collect.run_cmd_and_record')
@mock.patch('os.path.isfile')
@mock.patch('crmsh.report.utils.work_path')
def test_get_crm_configure(mock_work_path, mock_isfile, mock_run, mock_verify):
    mock_work_path.return_value = "work_path/{}".format(const.CIB_F)
    mock_isfile.return_value = True
    collect.get_crm_configure()
    mock_work_path.assert_called_once_with(const.CIB_F)
    mock_isfile.assert_called_once_with(mock_work_path.return_value)
    cmd = "CIB_file={} crm configure show".format(mock_work_path.return_value)
    mock_run.assert_called_once_with("cib config", cmd, const.CIB_TXT_F)
    mock_verify.assert_called_once_with(mock_work_path.return_value)


@mock.patch('logging.Logger.error')
@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('crmsh.report.collect.crmutils.str2file')
@mock.patch('crmsh.report.utils.work_path')
@mock.patch('crmsh.report.collect.crmutils.get_stdout_stderr')
def test_dump_crm_verify(mock_run, mock_work_path, mock_str2file, mock_dest_path, mock_error):
    mock_run.return_value = (1, None, "error data")
    mock_work_path.return_value = "work_path/{}".format(const.CRM_VERIFY_F)
    mock_dest_path.return_value = "dest_path/{}".format(const.CRM_VERIFY_F)
    collect.dump_crm_verify("cib_file")
    mock_run.assert_called_once_with("crm_verify -V -x cib_file")
    mock_str2file.assert_called_once_with("error data", mock_work_path.return_value)
    mock_error.assert_called_once_with('Create %s because crm_verify failed: %s', mock_dest_path.return_value, 'error data')


@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('crmsh.report.utils.work_path')
@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.collect.crmutils.str2file')
@mock.patch('crmsh.report.utils.get_stdout_or_raise_error')
@mock.patch('logging.Logger._log')
def test_run_cmd_and_record(mock_log, mock_run, mock_str2file, mock_debug, mock_work_path, mock_dest_path):
    mock_run.return_value = "data"
    mock_work_path.return_value = "work_path/file.txt"
    mock_dest_path.return_value = "dest_path/file.txt"
    collect.run_cmd_and_record("HA log", "cmd", "file.txt")
    mock_run.assert_called_once_with("cmd")
    mock_work_path.assert_called_once_with("file.txt")
    mock_dest_path.assert_called_once_with("file.txt")
    mock_str2file.assert_called_once_with("data", mock_work_path.return_value)
    mock_debug.assert_called_once_with("Dump %s into %s", "HA log", mock_dest_path.return_value)


@mock.patch('logging.Logger.warning')
@mock.patch('os.path.isdir')
@mock.patch('os.path.join')
def test_collect_ratraces_return(mock_join, mock_isdir, mock_warning):
    core.context.ha_varlib = "/var/lib/heartbeat"
    mock_join.return_value = "/var/lib/heartbeat/trace_ra"
    mock_isdir.return_value = False
    collect.collect_ratraces()
    mock_join.assert_called_once_with(core.context.ha_varlib, const.TRACE_RA)
    mock_isdir.assert_called_once_with(mock_join.return_value)
    mock_warning.assert_called_once_with("Directory %s not exist", mock_join.return_value)


@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('shutil.copy2')
@mock.patch('crmsh.report.utils.crmutils.mkdirp')
@mock.patch('crmsh.report.utils.work_path')
@mock.patch('crmsh.report.utils.find_files')
@mock.patch('logging.Logger.debug')
@mock.patch('os.path.isdir')
@mock.patch('os.path.join')
def test_collect_ratraces(mock_join, mock_isdir, mock_debug, mock_find, mock_work_path, mock_mkdir, mock_copy, mock_dest_path):
    core.context.ha_varlib = "/var/lib/heartbeat"
    mock_join.return_value = "/var/lib/heartbeat/trace_ra"
    mock_isdir.return_value = True
    mock_find.return_value = ["/var/lib/heartbeat/trace_ra/Dummpy/file1",
            "/var/lib/heartbeat/trace_ra/IPaddr2/file1"]
    mock_work_path.side_effect = ["work_path/trace_ra/Dummpy",
            "work_path/trace_ra/IPaddr2"]
    mock_dest_path.return_value = "dest_path/trace_ra"

    collect.collect_ratraces()

    mock_join.assert_called_once_with(core.context.ha_varlib, const.TRACE_RA)
    mock_isdir.assert_called_once_with(mock_join.return_value)
    mock_find.assert_called_once_with(mock_join.return_value)
    mock_debug.assert_has_calls([
        mock.call("Found %d RA trace files in %s", 2, mock_join.return_value),
        mock.call("Dump RA trace files into %s", mock_dest_path.return_value)
        ])
    mock_work_path.assert_has_calls([
        mock.call("trace_ra/Dummpy"),
        mock.call("trace_ra/IPaddr2")
        ])
    mock_mkdir.assert_has_calls([
        mock.call("work_path/trace_ra/Dummpy"),
        mock.call("work_path/trace_ra/IPaddr2")
        ])
    mock_copy.assert_has_calls([
        mock.call("/var/lib/heartbeat/trace_ra/Dummpy/file1", "work_path/trace_ra/Dummpy"),
        mock.call("/var/lib/heartbeat/trace_ra/IPaddr2/file1", "work_path/trace_ra/IPaddr2")
        ])


@mock.patch('crmsh.report.utils.find_files')
@mock.patch('logging.Logger._log')
def test_find_pe_files(mock_debug, mock_find):
    core.context.pe_state_dir = "/var/lib/pe"
    mock_find.return_value = ["/var/lib/pe/file1", "/var/lib/pe/file2", "/var/lib/pe/file.last"]
    res = collect.find_pe_files()
    assert res == ["/var/lib/pe/file1", "/var/lib/pe/file2"]
    mock_find.assert_called_once_with("/var/lib/pe")


@mock.patch('os.path.isfile')
@mock.patch('crmsh.report.utils.work_path')
def test_collect_events_return(mock_work_path, mock_isfile):
    mock_work_path.return_value = "work_path/ha-log.txt"
    mock_isfile.return_value = False
    collect.collect_events()
    mock_work_path.assert_called_once_with(const.HALOG_F)
    mock_isfile.assert_called_once_with("work_path/ha-log.txt")


@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.collect.crmutils.str2file')
@mock.patch('crmsh.report.utils.read_from_file')
@mock.patch('crmsh.report.utils.is_file_empty')
@mock.patch('os.path.isfile')
@mock.patch('crmsh.report.utils.work_path')
def test_collect_events(mock_work_path, mock_isfile, mock_empty, mock_read, mock_str2file, mock_debug, mock_dest_path):
    mock_work_path.side_effect = ["work_path/ha-log.txt", "work_path/events.txt"]
    mock_isfile.return_value = True
    mock_empty.return_value = False
    mock_read.return_value = """
2021-09-20T08:15:38+0800 15sp2-1 corosync[1996]:   [TOTEM ] A processor failed, forming new configuration.
other line1
2021-09-20T08:24:19+0800 15sp2-1 corosync[1996]:   [TOTEM ] A processor failed, forming new configuration.
2021-09-20T08:24:19+0800 15sp2-1 corosync[1996]:   [TOTEM ] A new membership (192.168.122.89:84) was formed. Members
other line2
2021-09-20T09:19:36+0800 15sp2-1 corosync[1996]:   [TOTEM ] A new membership (192.168.122.89:88) was formed. Members
2021-09-20T09:21:48+0800 15sp2-1 pacemakerd[2016]:  notice: Shutdown complete
2021-09-20T09:21:51+0800 15sp2-1 corosync[19048]:   [MAIN  ] Corosync Cluster Engine ('2.4.5'): started and ready to provide service.
other line3
other line4
2021-09-20T09:21:52+0800 15sp2-1 corosync[19049]:   [TOTEM ] A new membership (192.168.122.89:96) was formed. Members joined: 1084783193
2021-09-20T09:21:53+0800 15sp2-1 pacemaker-controld[19062]:  notice: Node (null) state is now member"""

    collect.collect_events()

    mock_work_path.assert_has_calls([
        mock.call(const.HALOG_F),
        mock.call(const.EVENTS_F)
        ])
    mock_dest_path.assert_called_once_with(const.EVENTS_F)
    mock_isfile.assert_called_once_with("work_path/ha-log.txt")
    mock_empty.assert_called_once_with("work_path/ha-log.txt")
    mock_read.assert_called_once_with("work_path/ha-log.txt")
    re_result = """2021-09-20T08:15:38+0800 15sp2-1 corosync[1996]:   [TOTEM ] A processor failed, forming new configuration.
2021-09-20T08:24:19+0800 15sp2-1 corosync[1996]:   [TOTEM ] A processor failed, forming new configuration.
2021-09-20T08:24:19+0800 15sp2-1 corosync[1996]:   [TOTEM ] A new membership (192.168.122.89:84) was formed. Members
2021-09-20T09:19:36+0800 15sp2-1 corosync[1996]:   [TOTEM ] A new membership (192.168.122.89:88) was formed. Members
2021-09-20T09:21:48+0800 15sp2-1 pacemakerd[2016]:  notice: Shutdown complete
2021-09-20T09:21:51+0800 15sp2-1 corosync[19048]:   [MAIN  ] Corosync Cluster Engine ('2.4.5'): started and ready to provide service.
2021-09-20T09:21:52+0800 15sp2-1 corosync[19049]:   [TOTEM ] A new membership (192.168.122.89:96) was formed. Members joined: 1084783193
2021-09-20T09:21:53+0800 15sp2-1 pacemaker-controld[19062]:  notice: Node (null) state is now member
"""
    mock_str2file.assert_called_once_with(re_result, "work_path/events.txt")


@mock.patch('logging.Logger.error')
@mock.patch('crmsh.report.utils.get_stdout_or_raise_error')
@mock.patch('crmsh.report.utils.full_path')
def test_find_binary(mock_full_path, mock_run, mock_error):
    mock_full_path.side_effect = ["/usr/sbin/ls", "/usr/lib/pacemaker/pacemaker-controld"]
    mock_run.return_value = "Core was generated by `/usr/lib/pacemaker/pacemaker-controld'."
    res = collect.find_binary("core.1")
    assert res == "/usr/lib/pacemaker/pacemaker-controld"
    mock_full_path.assert_has_calls([
        mock.call("ls"),
        mock.call("/usr/lib/pacemaker/pacemaker-controld")
        ])
    mock_run.assert_called_once_with("gdb /usr/sbin/ls core.1 --batch")


@mock.patch('logging.Logger.warning')
@mock.patch('crmsh.report.utils.get_stdout_or_raise_error')
def test_detect_debuginfo_pkg(mock_run, mock_warning):
    mock_run.return_value = "Missing separate debuginfos, use: zypper in pacemaker"
    collect.detect_debuginfo_pkg("/usr/sbin/corosync", "core.1")
    mock_run.assert_called_once_with("gdb /usr/sbin/corosync core.1 </dev/null 2>/dev/null")
    mock_warning.assert_called_once_with('%s, then re-run "crm report"', 'Missing separate debuginfos, use: zypper in pacemaker')


@mock.patch('logging.Logger.error')
@mock.patch('crmsh.report.collect.find_binary')
def test_get_bt_no_binary(mock_find, mock_error):
    mock_find.return_value = None
    res = collect.get_bt("core.1")
    assert res == ""
    mock_find.assert_called_once_with("core.1")
    mock_error.assert_called_once_with("Could not find the program path for core %s", "core.1")


@mock.patch('crmsh.report.collect.utils.get_stdout_or_raise_error')
@mock.patch('crmsh.report.collect.detect_debuginfo_pkg')
@mock.patch('logging.Logger._log')
@mock.patch('logging.Logger.info')
@mock.patch('logging.Logger.error')
@mock.patch('crmsh.report.collect.find_binary')
def test_get_bt(mock_find, mock_error, mock_info, mock_log, mock_detect, mock_run):
    mock_find.return_value = "/usr/bin/corosync"
    mock_run.return_value = "bt data"

    res = collect.get_bt("core.1")
    assert res == '===== start backtrace for core.1 =====\nbt data\n===== end backtrace =====\n\n'

    mock_find.assert_called_once_with("core.1")
    mock_info.assert_called_once_with("Core %s was generated by %s", "core.1", "/usr/bin/corosync")
    mock_detect.assert_called_once_with("/usr/bin/corosync", "core.1")
    mock_run.assert_called_once_with('gdb -batch -n -quiet -ex "thread apply all bt full" -ex quit /usr/bin/corosync core.1')


@mock.patch('logging.Logger.info')
@mock.patch('crmsh.report.utils.which')
@mock.patch('logging.Logger.warning')
@mock.patch('os.path.basename')
@mock.patch('crmsh.report.utils.find_files')
def test_collect_bt_from_core_files_return(mock_find, mock_basename, mock_warning, mock_which,mock_info):
    core.context.cores_dirs = ["/var/lib1", "/var/lib2"]
    mock_find.side_effect = [["/var/lib1/core.1"], ["/var/lib2/core.2"]]
    mock_basename.side_effect = ["core.1", "core.2"]
    mock_which.return_value = False

    collect.collect_bt_from_core_files()

    mock_find.assert_has_calls([
        mock.call("/var/lib1"),
        mock.call("/var/lib2")
        ])
    mock_basename.assert_has_calls([
        mock.call("/var/lib1/core.1"),
        mock.call("/var/lib2/core.2")
        ])
    mock_which.assert_called_once_with("gdb")
    mock_info.assert_called_once_with('Please install gdb if want to collect backtraces, then re-run "crm report"')


@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('crmsh.report.utils.work_path')
@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.collect.crmutils.str2file')
@mock.patch('crmsh.report.collect.get_bt')
@mock.patch('logging.Logger.info')
@mock.patch('crmsh.report.utils.which')
@mock.patch('logging.Logger.warning')
@mock.patch('os.path.basename')
@mock.patch('crmsh.report.utils.find_files')
def test_collect_bt_from_core_files(mock_find, mock_basename, mock_warning, mock_which, mock_info,
        mock_getbt, mock_str2file, mock_debug, mock_work_path, mock_dest_path):
    core.context.cores_dirs = ["/var/lib1", "/var/lib2"]
    mock_find.side_effect = [["/var/lib1/core.1"], ["/var/lib2/core.2"]]
    mock_basename.side_effect = ["core.1", "core.2"]
    mock_which.return_value = True
    mock_getbt.side_effect = ["data1", "data2"]
    mock_work_path.return_value = "work_path"
    mock_dest_path.return_value = "dest_path"

    collect.collect_bt_from_core_files()

    mock_find.assert_has_calls([
        mock.call("/var/lib1"),
        mock.call("/var/lib2")
        ])
    mock_basename.assert_has_calls([
        mock.call("/var/lib1/core.1"),
        mock.call("/var/lib2/core.2")
        ])
    mock_which.assert_called_once_with("gdb")
    mock_getbt.assert_has_calls([
        mock.call("/var/lib1/core.1"),
        mock.call("/var/lib2/core.2")
        ])
    mock_work_path.assert_called_once_with(const.BT_F)
    mock_dest_path.assert_called_once_with(const.BT_F)
    mock_str2file.assert_called_once_with("data1data2", "work_path")


@mock.patch('crmsh.report.utils.which')
def test_collect_dlm_return(mock_which):
    mock_which.return_value = False
    collect.collect_dlm_info()
    mock_which.assert_called_once_with(const.DLM_TOOL)


@mock.patch('logging.Logger.debug')
@mock.patch('crmsh.report.utils.dest_path')
@mock.patch('crmsh.report.collect.crmutils.str2file')
@mock.patch('crmsh.report.utils.work_path')
@mock.patch('crmsh.report.collect.dlm_lockspace_history')
@mock.patch('crmsh.report.collect.dlm_lockspace_dump')
@mock.patch('crmsh.report.utils.which')
def test_collect_dlm(mock_which, mock_dlm_dump, mock_dlm_hist, mock_work_path, mock_str2file, mock_dest_path, mock_debug):
    mock_which.return_value = True
    mock_dlm_dump.return_value = "data1\n"
    mock_dlm_hist.return_value = "data2\n"
    mock_work_path.return_value = "work_path/{}".format(const.DLM_DUMP_F)
    mock_dest_path.return_value = "dest_path/{}".format(const.DLM_DUMP_F)
    collect.collect_dlm_info()
    mock_which.assert_called_once_with(const.DLM_TOOL)
    mock_str2file.assert_called_once_with("data1\ndata2\n", mock_work_path.return_value)
    mock_debug.assert_called_once_with("Dump DLM info into %s", mock_dest_path.return_value)


@mock.patch('crmsh.report.utils.get_stdout_or_raise_error')
def test_dlm_lockspace_history(mock_run):
    mock_run.return_value = "data"
    res = collect.dlm_lockspace_history()
    assert res == "\n===== DLM lockspace history =====\ndata\n"
    mock_run.assert_called_once_with("{} dump".format(const.DLM_TOOL))


@mock.patch('crmsh.report.utils.get_stdout_or_raise_error')
def test_dlm_lockspace_dump(mock_run):
    mock_run.side_effect = ["data\nname    1234567\ndata", "debug data"]
    res = collect.dlm_lockspace_dump()
    output = """===== DLM lockspace overview =====
data
name    1234567
data

-- DLM lockspace 1234567 --
debug data
"""
    assert res == output
