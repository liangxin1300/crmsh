"""
Constants for crm report
"""
NAME = "crm_report"
COLLECTOR = "__collector"
TIME_TYPE = "YmdHM"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
TIME_FORMAT_FOR_TAR = "%a-%d-%b-%Y"
DELTA_TIME_REG = "^-?([1-9][0-9]*)([{}])$".format(TIME_TYPE)
DELTA_TIME_EXAMPLE = "30M; 12H; 10d; 2m; 1Y"
TRY_SSH_USER = "root hacluster"
SSH_OPTS_DEFAULT = "StrictHostKeyChecking=no EscapeChar=none ConnectTimeout=15"
COMPRESS_DATA_FLAG = "COMPRESS HB_REPORT DATA:::"
HA_UNITS = "pacemaker corosync sbd"
PTEST = "crm_simulate"
DLM_TOOL = "dlm_tool"
MAX_PE_FILES = 20
STAMP_TYPE_SYSLOG = "syslog"
STAMP_TYPE_RFC5424 = "rfc5424"
SANITIZE_STR = "******"
SENSITIVE_DEFAULT = "passw.*"
SYSSTAT_CMD_LIST = ["uname -n", "uptime", "ps axf", "ps auxw", "top -b -n 1",
        "ip addr", "ip -s link", "ip n show", "ip -o route show", "netstat -i",
        "arp -an", "lsscsi", "lspci", "mount", "cat /proc/cpuinfo", "df"]
OCFS2_CMD_LIST = ["dmesg", "ps -efL",
        "lsblk -o 'NAME,KNAME,MAJ:MIN,FSTYPE,LABEL,RO,RM,MODEL,SIZE,OWNER,GROUP,MODE,ALIGNMENT,MIN-IO,OPT-IO,PHY-SEC,LOG-SEC,ROTA,SCHED,MOUNTPOINT'",
        "mounted.ocfs2 -f", "findmnt", "mount",
        "cat /sys/fs/ocfs2/cluster_stack"]

HALOG_F = "ha-log.txt"
JOURNAL_F = "journal.log"
OSRELEASE = "/etc/os-release"
SYSINFO_F = "sysinfo.txt"
SYSSTATS_F = "sysstats.txt"
OCFS2_F = "ocfs2.txt"
SBDCONF = "/etc/sysconfig/sbd"
SBD_F = "sbd.txt"
CIB_F = "cib.xml"
CIB_TXT_F = "cib.txt"
CRM_VERIFY_F = "crm_verify.txt"
CRM_MON_F = "crm_mon.txt"
MEMBERSHIP_F = "members.txt"
PCMKCONF = "/etc/sysconfig/pacemaker"
COROSYNC_F = "corosync.conf"
COROSYNC_CONF = "/etc/corosync/corosync.conf"
COROSYNC_LIB = "/var/lib/corosync"
EVENTS_F = "events.txt"
TRACE_RA = "trace_ra"
RUNNING_FLAG = "HA_SERVICE_RUNNING"
STOPPED_FLAG = "HA_SERVICE_STOPPED"
DC_FLAG = "DC"
TIMESPAN_F = "timespan.txt"
BT_F = "backtraces.txt"
CTX_F = "context.txt"
DLM_DUMP_F = "dlm_dump.txt"
CRMSH_CONF = "/etc/crm/crm.conf"
ANALYSIS_F = "analysis.txt"

ANALYZE_LIST = [MEMBERSHIP_F, CRM_MON_F, COROSYNC_F, SYSINFO_F, CIB_F]
EVENT_PATTERNS = """pacemaker-controld.*(now lost|Quorum lost|is now member|Updating quorum status)
pacemaker-controld.*Result of
pacemaker-controld.*Stonith operation
pacemakerd.*Shutdown complete
pacemaker-fenced.*Requesting.*fencing
corosync.* started and ready
corosync.*membership .* was formed
corosync.* new configuration
corosync.* (FAULTY|recovered ring)
lack of quorum
healthy
unclean"""

# packages from network:/ha-clustering:/Factory x86_64+noarch
# filter out -devel-|-32bit-|-tests-|-test-|debug
PACKAGES = "booth cluster-glue corosync corosync-qdevice corosync-qnetd corosync-testagents crmsh crmsh-scripts csync2 doxygen2man drbd drbd-kmp-default drbd-utils fence-agents fence-agents-amt_ws gfs2-kmp-default gfs2-utils gradle gradle-kit ha-cluster-bootstrap hawk-apiserver hawk2 ldirectord libcfg6 libcmap4 libcorosync_common4 libcpg4 libdlm libdlm3 libglue2 libknet1 libknet1-compress-bzip2-plugin libknet1-compress-lz4-plugin libknet1-compress-lzma-plugin libknet1-compress-lzo2-plugin libknet1-compress-plugins-all libknet1-compress-zlib-plugin libknet1-compress-zstd-plugin libknet1-crypto-nss-plugin libknet1-crypto-openssl-plugin libknet1-crypto-plugins-all libknet1-plugins-all libnozzle1 libpacemaker3 libqb-tools libqb100 libquorum5 libsam4 libtotem_pg5 libvotequorum8 linstor linstor-common linstor-controller linstor-satellite monitoring-plugins-metadata o2locktop ocfs2-tools ocfs2-tools-o2cb omping pacemaker pacemaker-cli pacemaker-cts pacemaker-remote pssh python-pssh python36-linstor python36-linstor-client python36-parallax python38-linstor python38-linstor-client python38-parallax python39-linstor python39-linstor-client python39-parallax resource-agents ruby2.7-rubygem-sass-listen ruby3.0-rubygem-sass-listen sbd"


EXTRA_HELP = '''
Examples
  # collect from 2pm, today
  hb_report -f 2pm report_1

  # collect from "2007/9/5 12:30" to "2007/9/5 14:00"
  hb_report -f "2007/9/5 12:30" -t "2007/9/5 14:00" report_2

  # collect from 1:00 to 3:00, today; include /var/log/cluster/ha-debug as extra log
  hb_report -f 1:00 -t 3:00 -E /var/log/cluster/ha-debug report_3

  # collect from "09sep07 2:00" and use 'hacluster' as ssh user
  hb_report -f "09sep07 2:00" -u hacluster report_4

  # collect from 18:00, today; replace sensitive message like "usern.*" or "admin.*"
  hb_report -f 18:00 -s -p "usern.*" -p "admin.*" report_5

  # collect from 1 mounth ago
  hb_report -b 1m

  # collect from 12 days ago
  hb_report -b 12d

  # collect from 75 hours ago
  hb_report -b 75H

  # collect from 10 minutes ago
  hb_report -b 10M

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
  crmsh_hb_report(8)'''
