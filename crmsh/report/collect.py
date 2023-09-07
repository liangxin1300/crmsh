"""
Define functions to collect log and info
Function starts with "collect_" will be called in parallel
"""
import sys
import os
import shutil
import re
import stat
import pwd
import datetime
from subprocess import TimeoutExpired
from typing import List

from crmsh import log, corosync
from crmsh import utils as crmutils
from crmsh.report import constants, utils, core


logger = log.setup_report_logger(__name__)


def get_pcmk_log() -> str:
    """
    Get the path of the pacemaker log file
    """
    pcmk_log_candidates = [
        "/var/log/pacemaker/pacemaker.log",
        "/var/log/pacemaker.log"
    ]

    if os.path.isfile(constants.PCMKCONF):
        data = utils.read_from_file(constants.PCMKCONF)
        if data:
            res = re.search(r'^ *PCMK_logfile *= *(.*)', data, re.M)
            if res:
                pcmk_log_candidates.insert(0, res.group(1))

    for log in pcmk_log_candidates:
        if os.path.isfile(log):
            return log

    logger.warning("No valid pacemaker log file found")
    return ""


def collect_ha_logs(context: core.Context) -> None:
    """
    Collect pacemaker, corosync and extra logs
    """
    corosync_log = corosync.get_value("logging.logfile") or ""
    log_list = [get_pcmk_log(), corosync_log] + context.extra_log_list
    for log in log_list:
        if os.path.isfile(log):
            utils.dump_logset(context, log)


def collect_journal_logs(context: core.Context) -> None:
    """
    Collect journal logs from a specific time range
    """
    from_time_str = utils.ts_to_str(context.from_time)
    to_time_str = utils.ts_to_str(context.to_time)
    logger.debug(f"Collect journal logs since: {from_time_str} until: {to_time_str}")

    journal_target_dict = {
        "default": constants.JOURNAL_F,
        "pacemaker": constants.JOURNAL_PCMK_F,
        "corosync": constants.JOURNAL_COROSYNC_F,
        "sbd": constants.JOURNAL_SBD_F
    }
    for item, outf in journal_target_dict.items():
        journalctl_unit = "" if item == "default" else f" -u {item}"
        cmd = f'journalctl{journalctl_unit} -o short-iso-precise --since "{from_time_str}" --until "{to_time_str}" --no-pager | tail -n +2'
        output = utils.get_cmd_output(cmd)
        logger.debug2(f"Running command: {cmd}")
        _file = os.path.join(context.work_dir, outf)
        crmutils.str2file(output, _file)
        logger.debug2(f"Dump jounal log for {item} into {_file}")


def dump_D_process() -> str:
    """
    Dump D-state process stack
    """
    out_string = ""

    _, out, _ = crmutils.get_stdout_stderr("ps aux|awk '$8 ~ /^D/{print $2}'")
    len_D_process = len(out.split('\n')) if out else 0
    out_string += f"Dump D-state process stack: {len_D_process}\n"
    if len_D_process == 0:
        return out_string

    for pid in out.split('\n'):
        _, cmd_out, _ = crmutils.get_stdout_stderr(f"cat /proc/{pid}/comm")
        out_string += f"pid: {pid}     comm: {cmd_out}\n"
        _, stack_out, _ = crmutils.get_stdout_stderr(f"cat /proc/{pid}/stack")
        out_string += stack_out + "\n\n"

    return out_string


def lsof_ocfs2_device() -> str:
    """
    List open files for OCFS2 device
    """
    out_string = ""

    _, out, _ = crmutils.get_stdout_stderr("mount")
    dev_list = re.findall("\n(.*) on .* type ocfs2 ", out)
    for dev in dev_list:
        cmd = f"lsof {dev}"
        out_string += "\n\n#=====[ Command ] ==========================#\n"
        out_string += f"# {cmd}\n"
        _, cmd_out, _ = crmutils.get_stdout_stderr(cmd)
        if cmd_out:
            out_string += cmd_out

    return out_string


def ocfs2_commands_output() -> str:
    """
    Run ocfs2 related commands, return outputs
    """
    out_string = ""

    cmds = [
        "dmesg",
        "ps -efL",
        "lsblk -o 'NAME,KNAME,MAJ:MIN,FSTYPE,LABEL,RO,RM,MODEL,SIZE,OWNER,GROUP,MODE,ALIGNMENT,MIN-IO,OPT-IO,PHY-SEC,LOG-SEC,ROTA,SCHED,MOUNTPOINT'",
        "mounted.ocfs2 -f",
        "findmnt",
        "mount",
        "cat /sys/fs/ocfs2/cluster_stack"
    ]
    for cmd in cmds:
        cmd_name = cmd.split()[0]
        if not shutil.which(cmd_name):
            continue
        if cmd_name == "cat" and not os.path.exists(cmd.split()[1]):
            continue
        out_string += "\n\n#===== [ Command ] ==========================#\n"
        out_string += f"# {cmd}\n"
        out_string += utils.get_cmd_output(cmd)

    return out_string


def collect_ocfs2_info(context: core.Context) -> None:
    """
    Collects OCFS2 information
    """
    out_string = ""
    rc, out, err = crmutils.get_stdout_stderr("mounted.ocfs2 -d")
    if rc != 0:
        out_string += f"Failed to run \"mounted.ocfs2 -d\": {err}"
    # No ocfs2 device, just header line printed
    elif len(out.split('\n')) == 1:
        out_string += "No ocfs2 partitions found"
    else:
        out_string += dump_D_process()
        out_string += lsof_ocfs2_device()
        out_string += ocfs2_commands_output()

    ocfs2_f = os.path.join(context.work_dir, constants.OCFS2_F)
    logger.debug2(f"Dump OCFS2 information into {ocfs2_f}")
    crmutils.str2file(out_string, ocfs2_f)


def collect_ratraces(context: core.Context) -> None:
    """
    Collect ra trace file from default /var/lib/heartbeat/trace_ra and custom one
    """
    # since the "trace_dir" attribute been removed from cib after untrace
    # need to parse crmsh log file to extract custom trace ra log directory on each node
    log_contents = ""
    cmd = f"grep 'INFO: Trace for .* is written to ' {log.CRMSH_LOG_FILE}*|grep -v 'collect'"
    for node in context.node_list:
        log_contents += crmutils.get_stdout_or_raise_error(cmd, remote=node, no_raise=True) + "\n"
    trace_dir_str = ' '.join(list(set(re.findall("written to (.*)/.*", log_contents))))
    if not trace_dir_str:
        return

    logger.debug("Looking for RA trace files in \"%s\"", trace_dir_str)
    for f in utils.find_files_in_timespan(context, trace_dir_str.split()):
        dest_dir = os.path.join(context.work_dir, '/'.join(f.split('/')[-3:-1]))
        crmutils.mkdirp(dest_dir)
        shutil.copy2(f, dest_dir)
        logger.debug2(f"Dump RA trace files into {dest_dir}")


def collect_corosync_blackbox(context: core.Context) -> None:
    fdata_list = []
    for f in utils.find_files_in_timespan(context, ["/var/lib/corosync"]):
        if re.search("fdata", f):
            fdata_list.append(f)
    if fdata_list:
        blackbox_f = os.path.join(context.work_dir, constants.COROSYNC_RECORDER_F)
        out_string = utils.get_cmd_output("corosync-blackbox")
        crmutils.str2file(out_string, blackbox_f)
        logger.debug2(f"Dump corosync blackbox info into {blackbox_f}")


def collect_dlm_info(context: core.Context) -> None:
    """
    Get DLM information
    """
    if shutil.which("dlm_tool"):
        name_list = []
        out_string = "##### NOTICE - Lockspace overview:\n"
        out_string += utils.get_cmd_output("dlm_tool ls")
        name_list = re.findall("\nname\s*(.*)\n", out_string)

        for name in name_list:
            out_string += f"\n\n## NOTICE - Lockspace {name}\n"
            lockdebug_cmd = f"dlm_tool lockdebug {name}"
            out_string += utils.get_cmd_output(lockdebug_cmd)

        out_string += "\n\n##### NOTICE - Lockspace history:\n"
        out_string += utils.get_cmd_output("dlm_tool dump")

        dlm_f = os.path.join(context.work_dir, constants.DLM_DUMP_F)
        crmutils.str2file(out_string, dlm_f)
        logger.debug2(f"Dump DLM information into {dlm_f}")


def collect_perms_state(context: core.Context) -> None:
    """
    Check and collect permissions and ownership information for specific directories
    """
    results = []

    for check_dir in [context.pcmk_lib_dir, context.pe_dir, context.cib_dir]:
        if not os.path.isdir(check_dir):
            result = f"{check_dir} is not a directory or does not exist"
        else:
            stat_info = os.stat(check_dir)
            pwd_inst = pwd.getpwnam('hacluster')
            expected_uid = pwd_inst.pw_uid
            expected_gid = pwd_inst.pw_gid
            expected_mode = 0o750

            uid_match = stat_info.st_uid == expected_uid
            gid_match = stat_info.st_gid == expected_gid
            mode_match = stat_info.st_mode & 0o7777 == expected_mode

            if uid_match and gid_match and mode_match:
                result = "OK"
            else:
                result = f"Permissions or ownership for {check_dir} are incorrect"
        results.append(f"##### Check perms for {check_dir}: {result}\n")

    perms_f = os.path.join(context.work_dir, constants.PERMISSIONS_F)
    crmutils.str2file(''.join(results), perms_f)


def dump_configurations(workdir: str) -> None:
    config_list = constants.CONFIGURATIONS
    config_list.append(corosync.conf())

    for conf in config_list:
        if os.path.isfile(conf):
            shutil.copy2(conf, workdir)
        elif os.path.isdir(conf):
            shutil.copytree(conf, os.path.join(workdir, os.path.basename(conf)))


def find_binary_path_for_core(core_file: str) -> str:
    """
    Find the binary that generated the given core file
    """
    path_str = ""
    cmd = f"gdb --batch cat {core_file}"
    _, out, _ = crmutils.get_stdout_stderr(cmd)
    if out:
        res = re.search("Core was generated by `(.*)'", out, re.M)
        path_str = res.group(1) if res else ""

    if path_str:
        return f"Core {core_file} was generated by {path_str}"
    else:
        return f"Cannot find the program path for core {core_file}"


def dump_core_info(workdir: str, core_file_list: List[str]) -> None:
    """
    Dump coredump files information into file
    """
    out_string = ""
    if shutil.which("gdb"):
        for core_file in core_file_list:
            out_string += find_binary_path_for_core(core_file) + "\n"
        out_string += "\nPlease utilize the gdb and debuginfo packages to obtain more detailed information locally"
    else:
        msg = "Please install gdb to get more info for coredump files"
        out_string += msg
        logger.warning(msg)

    core_f = os.path.join(workdir, constants.COREDUMP_F)
    crmutils.str2file(out_string, core_f)
    logger.debug2(f"Dump coredump info into {core_f}")


def collect_coredump_info(context: core.Context) -> None:
    """
    Collects coredump files information from the library path of Pacemaker and Corosync
    """
    cores = utils.find_files_in_timespan(context, context.cores_dir_list)
    flist = [f for f in cores if "core" in os.path.basename(f)]
    if flist:
        logger.warning(f"Found coredump file: {flist}")
        dump_core_info(context.work_dir, flist)


def dump_runtime_state(workdir: str) -> None:
    """
    Dump runtime state files
    """
    for cmd, f, desc in [
        ("crm_mon -1", constants.CRM_MON_F, "cluster state"),
        ("cibadmin -Ql", constants.CIB_F, "CIB contents"),
        ("crm_node -p", constants.MEMBERSHIP_F, "members of this partition")
    ]:
        out = crmutils.get_stdout_or_raise_error(cmd)
        target_f = os.path.join(workdir, f)
        crmutils.str2file(out, target_f)
        logger.debug2(f"Dump {desc} into {target_f}")

    node = crmutils.get_dc()
    if node and node == crmutils.this_node():
        crmutils.str2file("", os.path.join(workdir, "DC"))
        logger.debug2(f"Current DC is {node}; Touch file 'DC' in {workdir}")


def consume_cib_in_workdir(workdir: str) -> None:
    """
    Generate 'crm configure show' and 'crm_verify' outputs based on the cib.xml file in the work directory
    """
    cib_in_workdir = os.path.join(workdir, constants.CIB_F)
    if os.path.isfile(cib_in_workdir):
        cmd = f"CIB_file={cib_in_workdir} crm configure show"
        out = crmutils.get_stdout_or_raise_error(cmd)
        crmutils.str2file(out, os.path.join(workdir, constants.CONFIGURE_SHOW_F))

        cmd = f"crm_verify -V -x {cib_in_workdir}"
        out = crmutils.get_stdout_or_raise_error(cmd)
        crmutils.str2file(out, os.path.join(workdir, constants.CRM_VERIFY_F))


def collect_config(context: core.Context) -> None:
    """
    """
    workdir = context.work_dir

    if crmutils.service_is_active("pacemaker.service"):
        dump_runtime_state(workdir)
        crmutils.str2file("", os.path.join(workdir, "RUNNING"))
        logger.debug2(f"Touch file 'RUNNING' in {workdir}")
    else:
        # TODO should determine offline node was ha node
        shutil.copy2(os.path.join(context.cib_dir, constants.CIB_F), workdir)
        crmutils.str2file("", os.path.join(workdir, "STOPPED"))
        logger.debug2(f"Touch file 'STOPPED' in {workdir}")

    consume_cib_in_workdir(workdir)
    dump_configurations(workdir)


def pe_to_dot(pe_file: str) -> None:
    dotf = os.path.splitext(pe_file)[0] + '.dot'
    cmd = f"{constants.PTEST} -D {dotf} -x {pe_file}"
    code, _, _ = crmutils.get_stdout_stderr(cmd)
    if code != 0:
        logger.warning("pe_to_dot: %s -> %s failed", pe_file, dotf)


def collect_pe_inputs(context: core.Context) -> None:
    """
    Collects PE files in the specified directory and generates DOT files if needed
    """
    logger.debug(f"Looking for PE files in {context.pe_dir}")

    _list = utils.find_files_in_timespan(context, [context.pe_dir])
    pe_file_list = [f for f in _list if not f.endswith(".last")]
    if pe_file_list:
        pe_flist_dir = os.path.join(context.work_dir, os.path.basename(context.pe_dir))
        crmutils.mkdirp(pe_flist_dir)

        gen_dot = len(pe_file_list) <= 20 and not context.speed_up
        for f in pe_file_list:
            pe_file_path_in_report = os.path.join(pe_flist_dir, os.path.basename(f))
            os.symlink(f, pe_file_path_in_report)
            if gen_dot:
                pe_to_dot(pe_file_path_in_report)
        logger.debug(f"Found {len(pe_file_list)} PE files in {context.pe_dir}")
        dump_path = f"{context.work_dir}/{os.path.basename(context.pe_dir)}"
        logger.debug(f"Dump PE files into {dump_path}")
    else:
        logger.debug("No PE file found for the giving time")


def collect_sbd_info(context: core.Context) -> None:
    """
    Collect SBD config file and information
    """
    if not os.path.exists(constants.SBDCONF):
        logger.debug2(f"SBD config file {constants.SBDCONF} does not exist")
        return
    shutil.copy2(constants.SBDCONF, context.work_dir)
    if not shutil.which("sbd"):
        return

    sbd_f = os.path.join(context.work_dir, constants.SBD_F)
    cmd = ". {};export SBD_DEVICE;{};{}".format(constants.SBDCONF, "sbd dump", "sbd list")
    with open(sbd_f, "w") as f:
        f.write("\n\n#=====[ Command ] ==========================#\n")
        f.write(f"# {cmd}\n")
        f.write(utils.get_cmd_output(cmd))

    logger.debug2(f"Dump SBD config file into {sbd_f}")


def collect_sys_stats(context: core.Context) -> None:
    """
    Collect system statistics
    """
    cmd_list = [
        "hostname", "uptime", "ps axf", "ps auxw", "top -b -n 1",
        "ip addr", "ip -s link", "ip n show", "lsscsi", "lspci",
        "mount", "cat /proc/cpuinfo", "df"
    ]

    out_string = ""
    for cmd in cmd_list:
        out_string += f"##### Run \"{cmd}\" #####\n"
        try:
            out_string += utils.get_cmd_output(cmd, timeout=5)
        except TimeoutExpired:
            logger.warning(f"Timeout while running command: {cmd}")

    _file = os.path.join(context.work_dir, constants.SYSSTATS_F)
    crmutils.str2file(out_string, _file)
    logger.debug2(f"Dump system statistics into {_file}")


def collect_sys_info(context: core.Context) -> None:
    """
    Collect the versions of cluster-related packages and platform information
    """
    pkg_inst = utils.Package(constants.PACKAGES)
    version_info = pkg_inst.version()
    packages_info = "##### Installed cluster related packages #####\n"
    packages_info += version_info
    if not context.speed_up:
        packages_info += pkg_inst.verify()

    platform, _, release, _, arch = os.uname()
    sys_info = (
            f"##### System info #####\n"
            f"Platform: {platform}\n"
            f"Kernel release: {release}\n"
            f"Architecture: {arch}\n"
            )
    if platform == "Linux":
        sys_info += f"Distribution: {utils.get_distro_info()}\n"
    out_string = f"{packages_info}\n\n{sys_info}"

    _file = os.path.join(context.work_dir, constants.SYSINFO_F)
    crmutils.str2file(out_string, _file)
    logger.debug2(f"Dump packages and platform info into {_file}")
