import sys
sys.path.append("/usr/share/crmsh/hb_report")

import os
import shutil
from nose.tools import eq_, ok_
from hb_report.utillib import which, ts_to_dt, sub_string, random_string,\
                              head, create_tempfile, tail, grep,\
                              get_stamp_rfc5424, get_stamp_syslog,\
                              find_getstampproc_raw, find_getstampproc,\
                              get_ts, is_our_log, find_first_ts, arch_logs,\
                              drop_tempfiles, add_tmpfiles, make_temp_dir,\
                              find_decompressor, find_files, filter_lines,\
                              findln_by_time, get_conf_var, is_conf_set,\
                              line_time, get_command_info
import hb_report
import crmsh.utils


######## test data begin ########
from_time_1 = crmsh.utils.parse_to_timestamp("2017/06/01 14:00")
to_time_1 = crmsh.utils.parse_to_timestamp("2017/06/01 15:00")
to_time_2 = crmsh.utils.parse_to_timestamp("2017/06/01 14:27:09")
from_time_2 = crmsh.utils.parse_to_timestamp("2017/06/01 16:00")
from_time_3 = crmsh.utils.parse_to_timestamp("2017/06/01 14:27:09")

line5424_1 = r"2017-01-26T11:04:19.562885+08:00 12sp2-4 kernel: [    0.000000]"
line5424_2 = r"2017-07-10T01:33:54.993374+08:00 12sp2-1 pengine[2020]:   notice: Calculated transition 221"

linesyslog_1 = r"May 17 15:52:40 [13042] 12sp2-4 pacemakerd:   notice: main:"
linesyslog_2 = r"Jul 09 18:33:54 [2020] 12sp2-1    pengine:     info: determine_online_status:   Node 12sp2-1 is online"

log_file_string = """logging {
        fileline:       off
        to_stderr:      no
        to_logfile:     no
        logfile:        /var/log/cluster/corosync.log
        to_syslog:      yes
        debug:          off
        timestamp:      on
        logger_subsys {
                subsys: QUORUM
                debug:  off
        }
}"""

sample_string1 = """some aaa
some bbbb
some cccc
some dddd"""

var_log_message = """2017-06-01T14:27:08.406823+08:00 12sp2-1 cib[13314]:   notice: Defaulting to uname -n for the local corosync node name
2017-06-01T14:27:08.412531+08:00 12sp2-1 cib[13320]:  warning: Could not verify cluster configuration file /var/lib/pacemaker/cib/cib.xml: No such file or directory (2)
2017-06-01T14:27:09.364616+08:00 12sp2-1 crmd[13319]:   notice: Connecting to cluster infrastructure: corosync
2017-06-01T14:27:09.371355+08:00 12sp2-1 crmd[13319]:   notice: Could not obtain a node name for corosync nodeid 168430081
2017-06-01T14:27:09.373693+08:00 12sp2-1 crmd[13319]:   notice: Defaulting to uname -n for the local corosync node name
2017-06-01T14:27:09.377372+08:00 12sp2-1 crmd[13319]:   notice: Quorum acquired
2017-06-01T14:27:09.384191+08:00 12sp2-1 cib[13314]:   notice: Defaulting to uname -n for the local corosync node name
2017-06-01T14:27:09.384862+08:00 12sp2-1 crmd[13319]:   notice: Node 12sp2-1 state is now member
2017-06-01T14:27:09.388897+08:00 12sp2-1 crmd[13319]:   notice: Defaulting to uname -n for the local corosync node name
2017-06-01T14:27:09.390853+08:00 12sp2-1 crmd[13319]:   notice: The local CRM is operational
2017-06-01T14:27:09.391030+08:00 12sp2-1 crmd[13319]:   notice: State transition S_STARTING -> S_PENDING
2017-06-01T14:27:09.512035+08:00 12sp2-1 puma[13242]: [13242] - Worker 0 (pid: 13298) booted, phase: 0
2017-06-01T14:27:30.394271+08:00 12sp2-1 crmd[13319]:  warning: Input I_DC_TIMEOUT received in state S_PENDING from crm_timer_popped
2017-06-01T14:27:30.395603+08:00 12sp2-1 crmd[13319]:   notice: State transition S_ELECTION -> S_INTEGRATION
2017-06-01T14:27:30.447374+08:00 12sp2-1 crmd[13319]:  warning: Input I_ELECTION_DC received in state S_INTEGRATION from do_election_check
2017-06-01T14:27:30.468758+08:00 12sp2-1 attrd[13317]:   notice: Defaulting to uname -n for the local corosync node name
2017-06-01T14:27:30.475533+08:00 12sp2-1 crmd[13319]:   notice: Updating quorum status to true (call=30)
2017-06-01T14:27:31.492875+08:00 12sp2-1 pengine[13318]:    error: Resource start-up disabled since no STONITH resources have been defined
2017-06-01T14:27:31.493258+08:00 12sp2-1 pengine[13318]:    error: Either configure some or disable STONITH with the stonith-enabled option
2017-06-01T14:27:31.493496+08:00 12sp2-1 pengine[13318]:    error: NOTE: Clusters with shared data need STONITH to ensure data integrity
2017-06-01T14:27:31.493683+08:00 12sp2-1 pengine[13318]:   notice: Delaying fencing operations until there are resources to manage
2017-06-01T14:27:31.493865+08:00 12sp2-1 pengine[13318]:   notice: Calculated transition 0, saving inputs in /var/lib/pacemaker/pengine/pe-input-0.bz2
2017-06-01T14:27:31.494056+08:00 12sp2-1 pengine[13318]:   notice: Configuration ERRORs found during PE processing.  Please run "crm_verify -L" to identify issues.
2017-06-01T14:27:31.494928+08:00 12sp2-1 crmd[13319]:   notice: Processing graph 0 (ref=pe_calc-dc-1496298451-9) derived from /var/lib/pacemaker/pengine/pe-input-0.bz2
2017-06-01T14:27:31.495290+08:00 12sp2-1 crmd[13319]:   notice: Transition 0 (Complete=0, Pending=0, Fired=0, Skipped=0, Incomplete=0, Source=/var/lib/pacemaker/pengine/pe-input-0.bz2): Complete
2017-06-01T14:27:31.495496+08:00 12sp2-1 crmd[13319]:   notice: State transition S_TRANSITION_ENGINE -> S_IDLE
2017-06-01T14:27:33.731039+08:00 12sp2-1 crmd[13319]:   notice: State transition S_IDLE -> S_POLICY_ENGINE
2017-06-01T14:27:34.746270+08:00 12sp2-1 pengine[13318]:   notice: Delaying fencing operations until there are resources to manage
2017-06-01T14:27:34.746614+08:00 12sp2-1 pengine[13318]:   notice: Calculated transition 1, saving inputs in /var/lib/pacemaker/pengine/pe-input-1.bz2
2017-06-01T14:27:34.747333+08:00 12sp2-1 crmd[13319]:   notice: Processing graph 1 (ref=pe_calc-dc-1496298454-10) derived from /var/lib/pacemaker/pengine/pe-input-1.bz2
2017-06-01T14:27:34.747749+08:00 12sp2-1 crmd[13319]:   notice: Transition 1 (Complete=0, Pending=0, Fired=0, Skipped=0, Incomplete=0, Source=/var/lib/pacemaker/pengine/pe-input-1.bz2): Complete
2017-06-01T14:27:34.748259+08:00 12sp2-1 crmd[13319]:   notice: State transition S_TRANSITION_ENGINE -> S_IDLE
2017-06-01T14:28:01.763321+08:00 12sp2-1 sshd[13364]: Accepted keyboard-interactive/pam for root from 10.10.10.2 port 57220 ssh2
2017-06-01T14:28:01.785840+08:00 12sp2-1 sshd[13364]: pam_unix(sshd:session): session opened for user root by (uid=0)
2017-06-01T14:28:01.805092+08:00 12sp2-1 systemd[1]: Started Session 3 of user root.
2017-06-01T14:28:01.807545+08:00 12sp2-1 systemd-logind[1014]: New session 3 of user root.
2017-06-01T14:28:02.002597+08:00 12sp2-1 sshd[13364]: Received disconnect from 10.10.10.2 port 57220:11: disconnected by user
2017-06-01T14:28:02.002899+08:00 12sp2-1 sshd[13364]: Disconnected from 10.10.10.2 port 57220
2017-06-01T14:28:02.003083+08:00 12sp2-1 sshd[13364]: pam_unix(sshd:session): session closed for user root
2017-06-01T14:28:02.015270+08:00 12sp2-1 systemd-logind[1014]: Removed session 3.
2017-06-01T14:28:02.149728+08:00 12sp2-1 sshd[13394]: Accepted publickey for root from 10.10.10.2 port 57222 ssh2: RSA SHA256:krPRwUg3Q09frDZ5LydCjAeogNvsvw+Sh7gqGcyUXTs
2017-06-01T14:28:02.151558+08:00 12sp2-1 sshd[13394]: pam_unix(sshd:session): session opened for user root by (uid=0)
2017-06-01T14:28:02.156243+08:00 12sp2-1 systemd[1]: Started Session 4 of user root.
2017-06-01T14:28:02.158372+08:00 12sp2-1 systemd-logind[1014]: New session 4 of user root."""
######## test data end ########


def test_arch_logs():
    # test blank file
    temp_file = create_tempfile()
    ok_(not arch_logs(temp_file, from_time_1, to_time_1))

    with(open(temp_file, 'w')) as f:
        f.write(var_log_message)
    # from_time > last_time
    ok_(not arch_logs(temp_file, from_time_2, to_time_1))
    # from_time >= first_time
    eq_(arch_logs(temp_file, from_time_3, to_time_1)[0], temp_file)
    # to_time == 0
    eq_(arch_logs(temp_file, from_time_1, 0)[0], temp_file)
    # to_time >= first_time
    eq_(arch_logs(temp_file, from_time_1, to_time_2)[0], temp_file)

    temp_file_extra = temp_file + temp_file[-1]+"1"
    with(open(temp_file_extra, 'w')) as f:
        f.write(var_log_message)
    eq_(arch_logs(temp_file_extra, from_time_3, to_time_1)[0], temp_file_extra)

    # from_time >= first_time
    eq_(arch_logs(temp_file, from_time_3, to_time_1)[0], temp_file)

    os.remove(temp_file)
    os.remove(temp_file_extra)


def test_drop_tempfiles():
    hb_report.constants.TMPFLIST = create_tempfile()
    tmpdir = make_temp_dir()
    add_tmpfiles(tmpdir)
    tmpfile = create_tempfile()
    add_tmpfiles(tmpfile)

    ok_(os.path.isdir(tmpdir))
    ok_(os.path.isfile(tmpfile))
    ok_(os.path.isfile(hb_report.constants.TMPFLIST))

    drop_tempfiles()

    ok_(not os.path.isdir(tmpdir))
    ok_(not os.path.isfile(tmpfile))
    ok_(not os.path.isfile(hb_report.constants.TMPFLIST))


def test_filter_lines():
    temp_file = create_tempfile()
    with open(temp_file, 'w') as f:
        f.write(var_log_message)

    begin_line = findln_by_time(temp_file, from_time_1)
    end_line = findln_by_time(temp_file, from_time_3)

    out1 = filter_lines(temp_file, begin_line)
    out2 = filter_lines(temp_file, begin_line, end_line)

    eq_(len(out1.split('\n')), 44)
    eq_(len(out2.split('\n')), 12)

    os.remove(temp_file)


def test_find_decompressor():
    log_file = "testfile"
    eq_(find_decompressor(log_file), "echo")
    log_file = "log.bz2"
    eq_(find_decompressor(log_file), "bzip2 -dc")
    log_file = "log.gz"
    eq_(find_decompressor(log_file), "gzip -dc")
    log_file = "log.tar.xz"
    eq_(find_decompressor(log_file), "xz -dc")

    log_file = create_tempfile()
    with open(log_file, 'w') as f:
        f.write("test")
    eq_(find_decompressor(log_file), "cat")
    os.remove(log_file)


def test_find_first_ts():
    res = find_first_ts(var_log_message.split('\n'))
    eq_(ts_to_dt(res).strftime("%Y/%m/%d %H:%M:%S"), "2017/06/01 14:27:08")


def test_find_files():
    ok_(not find_files("test", "testtime", to_time_1))
    ok_(not find_files("test", 0, to_time_1))

    hb_report.constants.TMPFLIST = create_tempfile()
    
    dirs = make_temp_dir()
    add_tmpfiles(dirs)

    tmpfile1 = create_tempfile(from_time_2)
    tmpfile2 = create_tempfile(from_time_3)
    add_tmpfiles(tmpfile1)
    add_tmpfiles(tmpfile2)

    shutil.copy2(tmpfile1, dirs)
    shutil.copy2(tmpfile2, dirs)

    eq_(find_files(dirs, from_time_1, 0), [os.path.join(dirs, os.path.basename(tmpfile1)), 
                                           os.path.join(dirs, os.path.basename(tmpfile2))])
    eq_(find_files(dirs, from_time_1, to_time_2), [os.path.join(dirs, os.path.basename(tmpfile2))])

    drop_tempfiles()


def test_find_getstampproc():
    temp_file = create_tempfile()

    in_string1 = """abcd
efg"""
    with open(temp_file, 'w') as f:
        f.write(in_string1)
    ok_(not find_getstampproc(temp_file))

    in_string2 = """%s
%s""" % (line5424_1, line5424_2)
    with open(temp_file, 'w') as f:
        f.write(in_string2)
    eq_(find_getstampproc(temp_file), "rfc5424")
 
    in_string3 = """%s
%s""" % (linesyslog_1, linesyslog_2)
    with open(temp_file, 'w') as f:
        f.write(in_string3)
    eq_(find_getstampproc(temp_file), "syslog")

    os.remove(temp_file)


def test_find_getstampproc_raw():
    eq_(find_getstampproc_raw(line5424_1), "rfc5424")
    eq_(find_getstampproc_raw(line5424_2), "rfc5424")
    eq_(find_getstampproc_raw(linesyslog_1), "syslog")
    eq_(find_getstampproc_raw(linesyslog_2), "syslog")


def test_findln_by_time():
    temp_file = create_tempfile()
    with open(temp_file, 'w') as f:
        f.write(var_log_message)

    # time before log happen
    eq_(findln_by_time(temp_file, from_time_1), 1)
    # time after log happen
    eq_(findln_by_time(temp_file, from_time_2), 44)
    # time between log happen
    eq_(findln_by_time(temp_file, from_time_3), 11)

    os.remove(temp_file)


def test_get_conf_var():
    temp_file = create_tempfile()
    with open(temp_file, 'w') as f:
        f.write(log_file_string)

    hb_report.constants.CONF = temp_file
    eq_(get_conf_var("debug"), "off")
    eq_(get_conf_var("test", "none"), "none")
    ok_(not is_conf_set("test"))

    os.remove(temp_file)


def test_get_stamp_rfc5424():
    ok_(get_stamp_rfc5424(line5424_1))      
    ok_(get_stamp_rfc5424(line5424_2))      


def test_get_stamp_syslog():
    ok_(get_stamp_syslog(linesyslog_1))
    ok_(get_stamp_syslog(linesyslog_2))


def test_get_ts():
    eq_(ts_to_dt(get_ts(line5424_1)).strftime("%Y/%m/%d %H:%M"), "2017/01/26 11:04")
    eq_(ts_to_dt(get_ts(linesyslog_1)).strftime("%m/%d %H:%M:%S"), "05/17 15:52:40")


def test_grep():
    res = grep("^Name", incmd="rpm -qi crmsh")[0]
    _, out = get_command_info("rpm -qi crmsh|grep \"^Name\"")
    eq_(res, out.strip("\n"))

    in_string = """aaaa
bbbb
"""
    temp_file = create_tempfile()
    with open(temp_file, 'w') as f:
        f.write(in_string)
    res = grep("aaaa", infile=temp_file, flag='v')[0]
    _, out = get_command_info("grep -v aaaa %s"%temp_file)
    os.remove(temp_file)
    eq_(res, out.strip("\n"))


def test_head():
    temp_file = create_tempfile()
    with open(temp_file, 'w') as f:
        f.write(sample_string1)
    _, out = get_command_info("cat %s|head -3" % temp_file)
    with open(temp_file, 'r') as f:
        data = f.read()
    res = head(3, data)

    os.remove(temp_file)
    eq_(out.rstrip('\n'), '\n'.join(res))


def test_is_our_log():
    # empty log
    temp_file = create_tempfile()
    eq_(is_our_log(temp_file, from_time_1, to_time_1), 0)

    with(open(temp_file, 'w')) as f:
        f.write(var_log_message)
    # from_time > last_time
    eq_(is_our_log(temp_file, from_time_2, to_time_1), 2)
    # from_time >= first_time
    eq_(is_our_log(temp_file, from_time_3, to_time_1), 3)
    # to_time == 0
    eq_(is_our_log(temp_file, from_time_1, 0), 1)
    # to_time >= first_time
    eq_(is_our_log(temp_file, from_time_1, to_time_2), 1)

    os.remove(temp_file)


def test_line_time():
    temp_file = create_tempfile()
    with(open(temp_file, 'w')) as f:
        f.write(var_log_message)

    eq_(ts_to_dt(line_time(temp_file, 2)).strftime("%Y/%m/%d %H:%M:%S"), "2017/06/01 14:27:08")
    eq_(ts_to_dt(line_time(temp_file, 17)).strftime("%Y/%m/%d %H:%M:%S"), "2017/06/01 14:27:30")

    os.remove(temp_file)


def test_random_string():
    eq_(len(random_string(8)), 8)


def test_sub_string():
    in_string = """
some text some text
I like name="OSS" value="redhat" target="mememe".
I like name="password" value="123456" some="more".
some number some number
"""

    out_string = """
some text some text
I like name="OSS" value="******" target="mememe".
I like name="password" value="******" some="more".
some number some number
"""
    pattern = "passw.* OSS"
    eq_(sub_string(in_string, pattern), out_string)


def test_tail():
    temp_file = create_tempfile()
    with open(temp_file, 'w') as f:
        f.write(sample_string1)
    _, out = get_command_info("cat %s|tail -3" % temp_file)
    with open(temp_file, 'r') as f:
        data = f.read()
    res = tail(3, data)

    os.remove(temp_file)
    eq_(out.rstrip('\n'), '\n'.join(res))


def test_ts_to_dt():
    ts1 = crmsh.utils.parse_to_timestamp("2pm")
    ts2 = crmsh.utils.parse_to_timestamp("2007/9/5 12:30")
    ts3 = crmsh.utils.parse_to_timestamp("1:00")
    ts4 = crmsh.utils.parse_to_timestamp("09-Sep-15 2:00")
    
    eq_(ts_to_dt(ts1).strftime("%-I%P"), "2pm")
    eq_(ts_to_dt(ts2).strftime("%Y/%-m/%-d %H:%M"), "2007/9/5 12:30")
    eq_(ts_to_dt(ts3).strftime("%-H:%M"), "1:00")
    eq_(ts_to_dt(ts4).strftime("%d-%b-%y %-H:%M"), "09-Sep-15 2:00")


def test_which():
    ok_(which("ls"))
    ok_(not which("llll"))
