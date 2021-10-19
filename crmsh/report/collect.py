"""
Define functions to collect log and info
Function starts with "collect_" will be called in parallel
"""
import os
import re
import shutil

from crmsh import log, corosync
from crmsh import utils as crmutils
from crmsh.report import const, utils, core


logger = log.setup_report_logger(__name__)


def run_cmd_and_record(cmd_type, cmd, out_file):
    """
    Run command, dump to specific file, and record to log
    """
    logger.debug2("Running command: %s", cmd)
    out = utils.get_stdout_or_raise_error(cmd)
    crmutils.str2file(out, utils.work_path(out_file))
    logger.debug("Dump %s into %s", cmd_type, utils.dest_path(out_file))


def get_journal_ha():
    """
    Using journalctl collect ha related log as ha-log.txt
    """
    cmd = 'journalctl -u {} --since "{}" --until "{}" -o short-iso --no-pager | tail -n +2'.\
            format(" -u ".join(const.HA_UNITS.split()), core.context.from_time_str, core.context.to_time_str)
    run_cmd_and_record("HA journal log", cmd, const.HALOG_F)


def collect_journal_general():
    """
    Using journalctl collect system log as journal.log
    """
    cmd = 'journalctl --since "{}" --until "{}" -o short-iso --no-pager | tail -n +2'.\
            format(core.context.from_time_str, core.context.to_time_str)
    run_cmd_and_record("All journal log", cmd, const.JOURNAL_F)


def get_rpm_info():
    """
    Get rpm info for HA related packages
    """
    out_string = "===== Cluster Stack Packages Version =====\n"
    out_string += utils.get_rpm_info(const.PACKAGES)
    return out_string


def rpm_verify_output():
    """
    Get rpm verify output for HA related packages
    """
    out_string = ""
    if not core.context.speed_up:
        out_string += "\n===== Cluster Stack Packages Verify =====\n"
        out_string += utils.verify_rpm(const.PACKAGES)
    else:
        logger.debug("Skip verify cluster stack packages")
    return out_string


def get_system_info():
    """
    Get system info
    """
    platform, _, release, _, arch = os.uname()
    out_string = """
===== System Info =====
Platform: {platform}
Kernel release: {kernel}
Architecture: {arch}
Distribution: {dist}
""".format(platform=platform,
        kernel=release,
        arch=arch,
        dist=utils.distro_info())
    return out_string


def collect_sys_info():
    """
    Collect packages version and system info
    """
    out_string = get_rpm_info()
    out_string += rpm_verify_output()
    out_string += get_system_info()

    crmutils.str2file(out_string, utils.work_path(const.SYSINFO_F))
    logger.debug("Dump packages version and system info into %s", utils.dest_path(const.SYSINFO_F))


def collect_sys_stats():
    """
    Collect system state
    """
    out_string = ""

    for cmd in const.SYSSTAT_CMD_LIST:
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

    crmutils.str2file(out_string, utils.work_path(const.SYSSTATS_F))
    logger.debug("Dump system stats into %s", utils.dest_path(const.SYSSTATS_F))


def collect_ratraces():
    """
    Collect ra trace files
    """
    trace_dir = os.path.join(core.context.ha_varlib, const.TRACE_RA)
    if not os.path.isdir(trace_dir):
        logger.warning("Directory %s not exist", trace_dir)
        return
    flist = utils.find_files(trace_dir)
    logger.debug("Found %d RA trace files in %s", len(flist), trace_dir)
    for f in flist:
        work_dir = utils.work_path('/'.join(f.split('/')[-3:-1]))
        crmutils.mkdirp(work_dir)
        shutil.copy2(f, work_dir)
    logger.debug("Dump RA trace files into %s", utils.dest_path(const.TRACE_RA))


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
    out = utils.get_stdout_or_raise_error("mount")
    dev_list = re.findall("\n(.*) on .* type ocfs2 ", out)
    for dev in dev_list:
        cmd = "lsof {}".format(dev)
        out_string += "\n\n#=====[ Command ] ==========================#\n"
        out_string += "# {}\n".format(cmd)
        _, cmd_out, _ = crmutils.get_stdout_stderr(cmd)
        if cmd_out:
            out_string += cmd_out
    return out_string


def get_ocfs2_related_output():
    """
    Get OCFS2 related commands' outputs
    """
    out_string = ""
    for cmd in const.OCFS2_CMD_LIST:
        cmd_name = cmd.split()[0]
        if not utils.which(cmd_name) or \
           cmd_name == "cat" and not os.path.exists(cmd.split()[1]):
            continue
        _, out, err = crmutils.get_stdout_stderr(cmd)
        if err:
            logger.error(err)
        out_string += "\n\n#=====[ Command ] ==========================#\n"
        out_string += "# %s\n"%(cmd)
        out_string += out
    return out_string


def collect_ocfs2_info():
    """
    Dump OCFS2 info
    """
    out_string = ""
    rc, out, err = crmutils.get_stdout_stderr("mounted.ocfs2 -d")
    if rc != 0:
        out_string += "Failed to run \"mounted.ocfs2 -d\": {}".format(err)
    # No ocfs2 device, just header line printed
    elif len(out.split('\n')) == 1:
        out_string += "No ocfs2 partitions found"
    else:
        out_string += dump_D_process()
        out_string += lsof_ocfs2_device()
        out_string += get_ocfs2_related_output()

    crmutils.str2file(out_string, utils.work_path(const.OCFS2_F))
    logger.debug("Dump OCFS2 info into %s", utils.dest_path(const.OCFS2_F))


def collect_sbd_info():
    """
    Save sbd configuration file and collect sbd dump info
    """
    if not os.path.exists(const.SBDCONF):
        logger.debug2("SBD config file %s not exist", const.SBDCONF)
        return
    shutil.copy2(const.SBDCONF, core.context.work_dir)
    logger.debug("Dump SBD config into %s", utils.dest_path(os.path.basename(const.SBDCONF)))

    if not utils.which("sbd"):
        logger.warning("Command \"sbd\" not exist")
        return
    cmd = ". {};export SBD_DEVICE;{};{}".format(const.SBDCONF, "sbd dump", "sbd list")
    out = utils.get_stdout_or_raise_error(cmd)
    out_string = "===== Run \"{}\" on {} =====\n".format(cmd, crmutils.this_node())
    out_string += out
    crmutils.str2file(out_string, utils.work_path(const.SBD_F))
    logger.debug("Dump SBD info into %s", utils.dest_path(const.SBD_F))


def dump_state():
    """
    Dump output of crm_mon, cibadmin and crm_node
    """
    for cmd, target_f, means in [("crm_mon -1rR", const.CRM_MON_F, "crm_mon output"),
            ("cibadmin -Ql", const.CIB_F, "cib xml"),
            ("crm_node -p", const.MEMBERSHIP_F, "members of this partition")]:
        run_cmd_and_record(means, cmd, target_f)


def dump_cluster_status():
    """
    Dump cluser service status file, RUNNING or STOPPED
    """
    if crmutils.service_is_active("pacemaker.service"):
        dump_state()
        utils.touch_file(utils.work_path(const.RUNNING_FLAG))
        logger.debug("Cluster service is running, touch \"%s\" file", utils.dest_path(const.RUNNING_FLAG))
    else:
        cib_f = os.path.join(core.context.crm_config, const.CIB_F)
        if os.path.exists(cib_f):
            shutil.copy2(cib_f, core.context.work_dir)
            logger.debug("Dump cib xml into %s", utils.dest_path(const.CIB_F))
        utils.touch_file(utils.work_path(const.STOPPED_FLAG))
        logger.debug("Cluster service is stopped, touch \"%s\" file", utils.dest_path(const.STOPPED_FLAG))


def get_crm_configure():
    cib_file = utils.work_path(const.CIB_F)
    if os.path.isfile(cib_file):
        cmd = "CIB_file={} crm configure show".format(cib_file)
        run_cmd_and_record("cib config", cmd, const.CIB_TXT_F)
        dump_crm_verify(cib_file)


def dump_crm_verify(cib_file):
    cmd = "crm_verify -V -x {}".format(cib_file)
    rc, _, err = crmutils.get_stdout_stderr(cmd)
    if rc != 0 and err:
        crmutils.str2file(err, utils.work_path(const.CRM_VERIFY_F))
        logger.error("Create %s because crm_verify failed: %s", utils.dest_path(const.CRM_VERIFY_F), err)


def get_corosync_conf():
    """
    Dump corosync.conf
    """
    if os.path.isfile(const.COROSYNC_CONF):
        shutil.copy2(const.COROSYNC_CONF, core.context.work_dir)
        logger.debug("Dump corosync config into %s", utils.dest_path(os.path.basename(const.COROSYNC_CONF)))


def touch_dc():
    """
    Touch DC file
    """
    node = crmutils.get_dc()
    if node and node == crmutils.this_node():
        utils.touch_file(utils.work_path(const.DC_FLAG))
        logger.debug("Node %s is DC, touch \"%s\" file", node, utils.dest_path(const.DC_FLAG))


def collect_cluster_info():
    """
    Collect cluster related config and log files
    """
    touch_dc()
    get_corosync_conf()
    dump_cluster_status()
    get_crm_configure()
    dump_pcmk_log()
    dump_corosync_log()


def get_pcmk_log():
    """
    Get pacemaker log file
    """
    if not os.path.isfile(const.PCMKCONF):
        logger.warning("Not found \"%s\"", const.PCMKCONF)
        return None
    data = utils.read_from_file(const.PCMKCONF)
    if not data:
        logger.warning("File \"%s\" is empty", const.PCMKCONF)
        return None
    res = re.search(r'^ *PCMK_logfile *= *(.*)', data, re.M)
    return res.group(1) if res else None


def dump_pcmk_log():
    """
    Collect pacemaker log
    """
    for pcmk_log in [get_pcmk_log(),
            "/var/log/pacemaker/pacemaker.log",
            "/var/log/pacemaker.log"]:
        if pcmk_log and os.path.isfile(pcmk_log):
            core.dump_logset(pcmk_log)
            break


def dump_corosync_log():
    """
    Collect corosync log
    """
    if not os.path.isfile(const.COROSYNC_CONF):
        return
    logfile = corosync.get_value('logging.logfile')
    if logfile and os.path.isfile(logfile):
        core.dump_logset(logfile)


def collect_extra_logs():
    """
    Collect extra logs
    """
    if core.context.no_extra:
        logger.debug("Skip collecting extra logs")
        return
    for l in core.context.extra_logs:
        if not os.path.isfile(l):
            logger.warning("File %s not exist", l)
            continue
        core.dump_logset(l)


def collect_pe_inputs():
    """
    Collect PE files
    """
    flist = find_pe_files()
    if flist:
        pe_basename = os.path.basename(core.context.pe_state_dir)
        flist_dir = utils.work_path(pe_basename)
        crmutils.mkdirp(flist_dir)
        for f in flist:
            os.symlink(f, os.path.join(flist_dir, os.path.basename(f)))
        logger.debug("Dump %d pengine input files into %s", len(flist), utils.dest_path(pe_basename))

        convert_pe_dot_files(flist, flist_dir)
    else:
        logger.debug("Nothing found for PE files in the giving time")


def convert_pe_dot_files(flist, flist_dir):
    if core.context.speed_up:
        logger.debug("Skip converting PE inputs to dot files")
        return
    if len(flist) > const.MAX_PE_FILES:
        logger.debug("Too many PE inputs to create dot files")
        return
    for f in flist:
        pe_to_dot(os.path.join(flist_dir, os.path.basename(f)))


def pe_to_dot(pe_file):
    dotf = '.'.join(pe_file.split('.')[:-1]) + '.dot'
    cmd = "%s -D %s -x %s" % (const.PTEST, dotf, pe_file)
    rc, _, err = crmutils.get_stdout_stderr(cmd)
    if rc != 0 or err:
        logger.error("pe_to_dot: %s -> %s failed: %s", pe_file, dotf, err)


def find_pe_files():
    """
    Find PE files
    """
    flist = []
    logger.debug2("Looking for PE files in %s", core.context.pe_state_dir)
    for f in utils.find_files(core.context.pe_state_dir):
        if re.search("[.]last$", f):
            continue
        flist.append(f)
    return flist


def collect_events():
    """
    Extract important events from ha-log.txt
    """
    ha_log = utils.work_path(const.HALOG_F)
    if not os.path.isfile(ha_log) or utils.is_file_empty(ha_log):
        return
    out_string = ""
    patt_string = "|".join(const.EVENT_PATTERNS.split('\n'))
    for line in utils.read_from_file(ha_log).split('\n'):
        if re.search(patt_string, line):
            out_string += line + '\n'
    crmutils.str2file(out_string, utils.work_path(const.EVENTS_F))
    logger.debug("Dump events file into %s", utils.dest_path(const.EVENTS_F))


def find_binary(core_file):
    """
    Find binary full path for giving core file
    """
    cmd = "gdb {} {} --batch".format(utils.full_path("ls"), core_file)
    out = utils.get_stdout_or_raise_error(cmd)
    res = re.search("Core was generated by `(.*)'.", out)
    return utils.full_path(res.group(1)) if res else None


def detect_debuginfo_pkg(binary, core_file):
    """
    Detect if missing debuginfo pakges for giving binary and core file
    """
    cmd = "gdb {} {} </dev/null 2>/dev/null".format(binary, core_file)
    out = utils.get_stdout_or_raise_error(cmd)
    res = re.search("Missing separate debuginfos, use: (.*)", out)
    if res:
        logger.warning("%s, then re-run \"crm report\"", res.group(0))


def get_bt(core_file):
    """
    Try to get the backtraces for giving core file
    """
    binary = find_binary(core_file)
    if not binary:
        logger.error("Could not find the program path for core %s", core_file)
        return ""
    logger.info("Core %s was generated by %s", core_file, binary)

    detect_debuginfo_pkg(binary, core_file)

    cmd = 'gdb -batch -n -quiet -ex "thread apply all bt full" -ex quit {} {}'.format(binary, core_file)
    logger.debug2("Running command: %s", cmd)
    out_string = "===== start backtrace for {} =====\n".format(core_file)
    out_string += utils.get_stdout_or_raise_error(cmd) + "\n"
    out_string += "===== end backtrace =====\n\n"
    return out_string


def collect_bt_from_core_files():
    """
    Try to collect backtraces if detect core files
    """
    flist = []
    for core_dir in core.context.cores_dirs:
        flist += utils.find_files(core_dir)
    core_list = [f for f in flist if "core" in os.path.basename(f)]
    if core_list:
        logger.warning("Found %d core files: %s", len(core_list), core_list)
        if not utils.which("gdb"):
            logger.info("Please install gdb if want to collect backtraces, then re-run \"crm report\"")
            return
    out_string = ""
    for core_file in core_list:
        out_string += get_bt(core_file)
    if out_string:
        crmutils.str2file(out_string, utils.work_path(const.BT_F))
        logger.debug("Dump backtraces into %s", utils.dest_path(const.BT_F))


def dlm_lockspace_dump():
    """
    Dump DLM lockspace
    """
    out_string = "===== DLM lockspace overview =====\n"
    out = utils.get_stdout_or_raise_error("{} ls".format(const.DLM_TOOL))
    out_string += out + '\n\n'
    for lock_name in re.findall('\nname\s*(.*)', out):
        out_string += "-- DLM lockspace {} --\n".format(lock_name)
        cmd = "{} lockdebug {}".format(const.DLM_TOOL, lock_name)
        debug_out = utils.get_stdout_or_raise_error(cmd)
        out_string += debug_out + '\n'
    return out_string


def dlm_lockspace_history():
    """
    Dump DLM lockspace history
    """
    out_string = "\n===== DLM lockspace history =====\n"
    out = utils.get_stdout_or_raise_error("{} dump".format(const.DLM_TOOL))
    out_string += out + '\n'
    return out_string


def collect_dlm_info():
    """
    Collect DLM info
    """
    if not utils.which(const.DLM_TOOL):
        return
    out_string = dlm_lockspace_dump()
    out_string += dlm_lockspace_history()
    crmutils.str2file(out_string, utils.work_path(const.DLM_DUMP_F))
    logger.debug("Dump DLM info into %s", utils.dest_path(const.DLM_DUMP_F))
