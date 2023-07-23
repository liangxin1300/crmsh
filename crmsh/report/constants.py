# Copyright (C) 2017 Xin Liang <XLiang@suse.com>
# See COPYING for license information.
BIN_CRM = "/usr/sbin/crm"
BIN_COLLECTOR = f"{BIN_CRM} report __collector"
COMPRESS_DATA_FLAG = "COMPRESS CRM_REPORT DATA:::"
LOG_PATTERNS = "CRIT: ERROR: error: warning: crit:"
PTEST = "crm_simulate"
SSH_OPTS = "-o StrictHostKeyChecking=no -o EscapeChar=none -o ConnectTimeout=15"
CHECK_LOG_LINES = 10
STAMP_TYPE = ""

# Important events
#
# Patterns format:
#  title extended_regexp
# NB: don't use spaces in titles or regular expressions!
EVENT_PATTERNS = """
membership crmd.*(NEW|LOST)|pcmk.*(lost|memb|LOST|MEMB):
quorum crmd.*Updating.quorum.status|crmd.*quorum.(lost|ac?quir)
pause Process.pause.detected
resources lrmd.*(start|stop)
stonith crmd.*Exec|stonith-ng.*log_oper.*reboot|stonithd.*(requests|(Succeeded|Failed).to.STONITH|result=)
start_stop Configuration.validated..Starting.heartbeat|Corosync.Cluster.Engine|Executive.Service.RELEASE|Requesting.shutdown|Shutdown.complete
"""

DECRIPTION_TMPLATE = """
Please edit this template and describe the issue/problem you
encountered. Then, post to
    http://clusterlabs.org/mailman/listinfo/users
or file a bug at
    https://github.com/ClusterLabs/crmsh/issues

Thank you.

Date: {0}
By: crm report {1}
Subject: [short problem description]
Severity: [choose one] enhancement minor normal major critical blocking
--------------------------------------------------------

Detailed description:

"""

PACKAGES = "booth cluster-glue cluster-glue-libs corosync corosync-qdevice corosync-qnetd corosync-testagents crmsh crmsh-scripts csync2 doxygen2man drbd-utils gfs2-kmp-default gfs2-utils hawk-apiserver ldirectord libcfg6 libcmap4 libcorosync_common4 libcpg4 libdlm libdlm3 libqb-tools libqb100 libquorum5 libsam4 libtotem_pg5 libvotequorum8 linstor linstor-common linstor-controller linstor-satellite monitoring-plugins-metadata o2locktop ocfs2-tools ocfs2-tools-o2cb omping pacemaker pacemaker-cli pacemaker-cts pacemaker-libs pacemaker-remote pacemaker-schemas patterns-ha pssh python-pssh python3-linstor python3-linstor-client python3-pacemaker python3-parallax resource-agents resource-agents-zfs ruby2.5-rubygem-sass-listen ruby2.5-rubygem-sass-listen-doc sbd"

ANALYSIS_F = "analysis.txt"
COREDUMP_F = "coredump_info.txt"
CIB_F = "cib.xml"
CONFIGURE_SHOW_F = "configure_show.txt"
CONFIGURATIONS = [
    "/etc/drbd.conf",
    "/etc/drbd.d",
    "/etc/booth/booth.conf"
]
COROSYNC_RECORDER_F = "fdata.txt"
COROSYNC_F = "corosync.conf"
CRM_MON_F = "crm_mon.txt"
CRM_VERIFY_F = "crm_verify.txt"
DESCRIPTION_F = "description.txt"
DLM_DUMP_F = "dlm_dump.txt"
JOURNAL_F = "journal.log"
JOURNAL_PCMK_F = "journal_pacemaker.log"
JOURNAL_COROSYNC_F = "journal_corosync.log"
JOURNAL_SBD_F = "journal_sbd.log"
MEMBERSHIP_F = "members.txt"
PERMISSIONS_F = "permissions.txt"
SBDCONF = "/etc/sysconfig/sbd"
PCMKCONF = "/etc/sysconfig/pacemaker"
SYSINFO_F = "sysinfo.txt"
SYSSTATS_F = "sysstats.txt"
TIME_F = "time.txt"
OCFS2_F = "ocfs2.txt"
SBD_F = "sbd.txt"
OSRELEASE = "/etc/os-release"
TIME_FORMAT = "%Y-%m-%d %H:%M"
RESULT_TIME_SUFFIX = "%a-%d-%b-%Y"
NAME = "crm report"
COROSYNC_LIB = "/var/lib/corosync"

EXTRA_HELP = '''
Examples
  # collect from 2pm, today
  {name} -f 2pm report_1

  # collect from "2007/9/5 12:30" to "2007/9/5 14:00"
  {name} -f "2007/9/5 12:30" -t "2007/9/5 14:00" report_2

  # collect from 1:00 to 3:00, today; include /var/log/cluster/ha-debug as extra log
  {name} -f 1:00 -t 3:00 -E /var/log/cluster/ha-debug report_3

  # collect from "09sep07 2:00" and use 'hacluster' as ssh user
  {name} -f "09sep07 2:00" -u hacluster report_4

  # collect from 18:00, today; replace sensitive message like "usern.*" or "admin.*"
  {name} -f 18:00 -s -p "usern.*" -p "admin.*" report_5

  # collect from 1 mounth ago
  {name} -f 1m

  # collect from 75 hours ago
  {name} -f 75H

  # collect from 10 minutes ago
  {name} -f 10M

  # collect from 2 days ago to 1 day ago
  {name} -f 2d -t 1d

. WARNING . WARNING . WARNING . WARNING . WARNING . WARNING .

We won't sanitize the CIB and the peinputs files, because that
would make them useless when trying to reproduce the PE behaviour.
You may still choose to obliterate sensitive information if you
use the -s and -p options, but in that case the support may be
lacking as well.

Additional system logs are collected in order to have a more
complete report. If you don't want that specify -M.

IT IS YOUR RESPONSIBILITY TO PROTECT THE DATA FROM EXPOSURE!

SEE ALSO
  crmsh_hb_report(8)'''.format(name=NAME)
# vim:ts=4:sw=4:et:
