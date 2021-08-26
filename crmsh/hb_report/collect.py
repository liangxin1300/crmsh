import os
import re
import shutil

from crmsh import log
from crmsh import utils as crmutils
from crmsh.hb_report import const, utils, main


logger = log.setup_logger(__name__)
logger_utils = log.LoggerUtils(logger)
logger_utils.set_debug2_level()


def run_cmd_and_record(context, cmd_type, cmd, output_file):
    logger.debug2("Running command: %s", cmd)
    _, out, err = crmutils.get_stdout_stderr(cmd)
    if err:
        logger.error(err)
    if out:
        crmutils.str2file(out, output_file)
        dest_file = os.path.join(context.dest_path, os.path.basename(output_file))
        logger.debug1("Dump %s into %s", cmd_type, dest_file)


def journal_ha(context):
    """
    Using journalctl collect ha related log as ha-log.txt
    """
    cmd = 'journalctl -u pacemaker -u corosync -u sbd \
            --since "{}" --until "{}" \
            -o short-iso --no-pager | tail -n +2'.\
            format(context.from_time_str, context.to_time_str)
    outf = os.path.join(context.work_dir, const.HALOG_F)
    run_cmd_and_record(context, "HA journal log", cmd, outf)


def journal_general(context):
    """
    Using journalctl collect system log as journal.log
    """
    cmd = 'journalctl --since "{}" --until "{}" \
            -o short-iso --no-pager | tail -n +2'.\
            format(context.from_time_str, context.to_time_str)
    outf = os.path.join(context.work_dir, const.JOURNAL_F)
    run_cmd_and_record(context, "All journal log", cmd, outf)


def sys_info(context):
    """
    packages version and system info
    """
    out_string = "===== Cluster Stack Packages Version =====\n"
    out_string += utils.get_rpm_info(const.PACKAGES)
    if not context.speed_up:
        out_string += "\n===== Cluster Stack Packages Verify =====\n"
        out_string += utils.verify_rpm(const.PACKAGES)
    else:
        logger.debug("Skip verify cluster stack packages")

    platform, _, release, _, arch = os.uname()
    out_string += """
===== System Info =====
Platform: {platform}
Kernel release: {kernel}
Architecture: {arch}
Distribution: {dist}
""".format(platform=platform,
        kernel=release,
        arch=arch,
        dist=utils.distro_info())

    crmutils.str2file(out_string, os.path.join(context.work_dir, const.SYSINFO_F))
    logger.debug("Dump packages version and system info into {}/{}".format(context.dest_path, const.SYSINFO_F))


def sys_stats(context):
    out_string = ""

    cmd_list = ["uname -n", "uptime", "ps axf", "ps auxw", "top -b -n 1",
                "ip addr", "ip -s link", "ip n show", "ip -o route show", "netstat -i",
                "arp -an", "lsscsi", "lspci", "mount", "cat /proc/cpuinfo", "df"]
    for cmd in cmd_list:
        cmd_name = cmd.split()[0]
        if not utils.which(cmd_name):
            continue
        # df maybe block, run in background, allow for 5 seconds (!)
        if cmd_name == "df":
            rc, out, err = utils.get_stdout_stderr_timeout(cmd)
        else:
            rc, out, err = crmutils.get_stdout_stderr(cmd)
        if err:
            logger.error(err)
        if rc == 0 and out:
            out_string += "===== Run \"{}\" on {} =====\n".format(cmd, crmutils.this_node())
            out_string += out + "\n\n"

    crmutils.str2file(out_string, os.path.join(context.work_dir, const.SYSSTATS_F))
    logger.debug("Dump system stats into {}/{}".format(context.dest_path, const.SYSSTATS_F))


def get_ratraces(context):
    trace_dir = os.path.join(context.ha_varlib, "trace_ra")
    if not os.path.isdir(trace_dir):
        return
    flist = utils.find_files(context, trace_dir)
    logger.debug("Found %d RA trace files in %s", len(flist), trace_dir)
    for f in flist:
        dest_dir = os.path.join(constants.work_dir, '/'.join(f.split('/')[-3:-1]))
        crmutils.mkdirp(dest_dir)
        shutil.copy2(f, dest_dir)


def dump_D_process():
    '''
    dump D-state process stack
    '''
    out_string = ""
    _, out, _ = crmutils.get_stdout_stderr("ps aux|awk '$8 ~ /^D/{print $2}'")
    len_D_process = len(out.split('\n')) if out else 0
    out_string += "Dump D-state process stack: {}\n".format(len_D_process)
    if len_D_process == 0:
        return out_string
    for pid in out.split('\n'):
        _, cmd_out, _ = crmutils.get_stdout_stderr("cat /proc/{}/comm".format(pid))
        out_string += "pid: {}     comm: {}\n".format(pid, cmd_out)
        _, stack_out, _ = crmutils.get_stdout_stderr("cat /proc/{}/stack".format(pid))
        out_string += stack_out + "\n\n"
    return out_string


def lsof_ocfs2_device():
    """
    List open files for OCFS2 device
    """
    out_string = ""
    _, out, _ = crmutils.get_stdout_stderr("mount")
    dev_list = re.findall("\n(.*) on .* type ocfs2 ", out)
    for dev in dev_list:
        cmd = "lsof {}".format(dev)
        out_string += "\n\n#=====[ Command ] ==========================#\n"
        out_string += "# {}\n".format(cmd)
        _, cmd_out, _ = crmutils.get_stdout_stderr(cmd)
        if cmd_out:
            out_string += cmd_out
    return out_string


def dump_ocfs2(context):
    """
    Dump OCFS2 info
    """
    ocfs2_f = os.path.join(context.work_dir, context.OCFS2_F)
    with open(ocfs2_f, "w") as f:
        rc, out, err = crmutils.get_stdout_stderr("mounted.ocfs2 -d")
        if rc != 0:
            err_msg = "Failed to run \"mounted.ocfs2 -d\": {}".format(err)
            logger.error(err_msg)
            f.write(err_msg)
            return
        # No ocfs2 device, just header line printed
        elif len(out.split('\n')) == 1:
            f.write("No ocfs2 partitions found")
            return

        f.write(dump_D_process())
        f.write(lsof_ocfs2_device())

        cmds = [ "dmesg",  "ps -efL",
                "lsblk -o 'NAME,KNAME,MAJ:MIN,FSTYPE,LABEL,RO,RM,MODEL,SIZE,OWNER,GROUP,MODE,ALIGNMENT,MIN-IO,OPT-IO,PHY-SEC,LOG-SEC,ROTA,SCHED,MOUNTPOINT'",
                "mounted.ocfs2 -f", "findmnt", "mount",
                "cat /sys/fs/ocfs2/cluster_stack"]
        for cmd in cmds:
            cmd_name = cmd.split()[0]
            if not utils.which(cmd_name) or \
               cmd_name == "cat" and not os.path.exists(cmd.split()[1]):
                continue
            _, out, err = crmutils.get_stdout_stderr(cmd)
            if err:
                logger.error(err)
            f.write("\n\n#=====[ Command ] ==========================#\n")
            f.write("# %s\n"%(cmd))
            f.write(out)


def sbd_info(context):
    """
    Save sbd configuration file and collect sbd dump info
    """
    if not os.path.exists(const.SBDCONF):
        logger.debug2("SBD config file %s not exist", const.SBDCONF)
        return
    shutil.copy2(const.SBDCONF, context.work_dir)
    logger.debug("Dump SBD config into {}/{}".format(context.dest_path, os.path.basename(const.SBDCONF)))

    if not utils.which("sbd"):
        logger.warning("Command \"sbd\" not exist")
        return
    cmd = ". {};export SBD_DEVICE;{};{}".format(const.SBDCONF, "sbd dump", "sbd list")
    with open(os.path.join(context.work_dir, const.SBD_F), "w") as f:
        rc, out, err = crmutils.get_stdout_stderr(cmd)
        if err:
            logger.error(err)
        if rc == 0 and out:
            f.write("===== Run \"{}\" on {} =====\n".format(cmd, crmutils.this_node()))
            f.write(out)
            logger.debug("Dump SBD info into {}/{}".format(context.dest_path, const.SBD_F))


def dump_state(context):
    """
    Dump output of crm_mon, cibadmin and crm_node
    """
    for cmd, outf, means in [("crm_mon -1rR", const.CRM_MON_F, "crm_mon output"),
            ("cibadmin -Ql", const.CIB_F, "cib xml"),
            ("crm_node -p", const.MEMBERSHIP_F, "members of this partition")]:
        rc, out, err = crmutils.get_stdout_stderr(cmd)
        if err:
            logger.error(err)
        if rc == 0 and out:
            crmutils.str2file(out, os.path.join(context.work_dir, outf))
            logger.debug("Dump {} into {}/{}".format(means, context.dest_path, outf))


def dump_cluster_status(context):
    if crmutils.service_is_active("pacemaker.service"):
        dump_state(context)
        utils.touch_file(os.path.join(context.work_dir, "RUNNING"))
        logger.debug("Cluster service is running, touch \"RUNNING\" file in %s", context.dest_path)
    else:
        cib_f = os.path.join(context.cib_dir, const.CIB_F)
        if os.path.exists(cib_f):
            shutil.copy2(cib_f, context.work_dir)
            logger.debug("Dump cib xml into {}/{}".format(context.dest_path, const.CIB_F))
        utils.touch_file(os.path.join(context.work_dir, "STOPPED"))
        logger.debug("Cluster service is stopped, touch \"STOPPED\" file in %s", context.dest_path)


def get_pcmk_log():
    """
    """
    if not os.path.isfile(const.PCMKCONF):
        logger.warning("Not found \"%s\"", const.PCMKCONF)
        return None
    with open(const.PCMKCONF) as f:
        data = f.read()
    if not data:
        logger.warning("File \"%s\" is empty", const.PCMKCONF)
        return None
    res = re.search(r'^ *PCMK_logfile *= *(.*)', data, re.M)
    return res.group(1) if res else None


def dump_pcmk_log(context):
    """
    """
    for pcmk_log in [get_pcmk_log(),
            "/var/log/pacemaker/pacemaker.log",
            "/var/log/pacemaker.log"]:
        if pcmk_log and os.path.isfile(pcmk_log):
            main.dump_logset(context, pcmk_log)
            break


def dump_corosync_log(context):
    """
    """
    if not os.path.isfile(const.COROCONF):
        return
    logfile = corosync.get_value('logging.logfile')
    if logfile and os.path.isfile(logfile):
        main.dump_logset(context, logfile)
