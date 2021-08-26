"""
Constants for hb_report
"""
COLLECTOR = "__collector"
TIME_TYPE = "YmdHM"
TIME_FORMAT = "%Y-%m-%d %H:%M"
TIME_FORMAT_FOR_TAR = "%a-%d-%b-%Y"
DELTA_TIME_REG = "^-?([1-9][0-9]*)([{}])$".format(TIME_TYPE)
DELTA_TIME_EXAMPLE = "30M; 12H; 10d; 2m; 1Y"

HALOG_F = "ha-log.txt"
JOURNAL_F = "journal.log"
OSRELEASE = "/etc/os-release"
SYSINFO_F = "sysinfo.txt"
SYSSTATS_F = "sysstats.txt"
OCFS2_F = "ocfs2.txt"
SBDCONF = "/etc/sysconfig/sbd"
SBD_F = "sbd.txt"
CIB_F = "cib.xml"
CRM_MON_F = "crm_mon.txt"
MEMBERSHIP_F = "members.txt"
PCMKCONF = "/etc/sysconfig/pacemaker"
COROCONF = "/etc/corosync/corosync.conf"
COROSYNC_LIB = "/var/lib/corosync"

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
