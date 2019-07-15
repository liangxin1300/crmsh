import re
import os
import sys
import shutil
import stat
import pwd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from hb_report import const, utils
from crmsh import utils as crmutils
from crmsh import bootstrap


def distro():
    if os.path.exists(const.OSRELEASE):
        utils.log_debug2("Using {} for distribution info".format(const.OSRELEASE))
        cmd = "cat {}|awk -F'=' '/PRETTY_NAME/{{print $2}}'".format(const.OSRELEASE)
        rc, out = crmutils.get_stdout(cmd)
        if rc == 0:
            return out.strip('"')

    if utils.which("lsb_release"):
        utils.log_debug2("Using lsb_release for distribution info")
        rc, out = crmutils.get_stdout("lsb_release -d|awk -F: '{print $2}'")
        if rc == 0:
            return out

    return "Unknown"


def sys_info(context):
    '''
    packages version and system info
    '''
    pkg_inst = utils.Package(const.PACKAGES)
    out_string = "===== Cluster Stack Packages Verion =====\n"
    out_string += pkg_inst.version()
    if not context.speed_up:
        out_string += "\n===== Cluster Stack Packages Verify =====\n"
        out_string += pkg_inst.verify()

    platform, _, release, _, arch = os.uname()
    out_string += "\n===== System Info =====\n"
    out_string += "Platform: %s\n" % platform
    out_string += "Kernel release: %s\n" % release
    out_string += "Architecture: %s\n" % arch
    if os.uname()[0] == "Linux":
        out_string += "Distribution: %s\n" % distro()

    crmutils.str2file(out_string, os.path.join(context.work_dir, const.SYSINFO_F))
    utils.log_debug1("Dump packages version and system info into {}/{}".format(context.dest_path, const.SYSINFO_F))


def sbd_info(context):
    """
    save sbd configuration file
    """
    if os.path.exists(const.SBDCONF):
        shutil.copy2(const.SBDCONF, context.work_dir)
        utils.log_debug1("Dump SBD config into {}/{}".format(context.dest_path, os.path.basename(const.SBDCONF)))
    if not utils.which("sbd"):
        utils.log_debug2("Command \"sbd\" not exist")
        return

    cmd = ". {};export SBD_DEVICE;{};{}".format(const.SBDCONF, "sbd dump", "sbd list")
    with open(os.path.join(context.work_dir, const.SBD_F), "w") as f:
        rc, out, _ = crmutils.get_stdout_stderr(cmd)
        if rc == 0 and out:
            f.write("===== Run \"{}\" on {} =====\n".format(cmd, utils.me()))
            f.write(out)
    utils.log_debug1("Dump SBD info into {}/{}".format(context.dest_path, const.SBD_F))


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
            rc, out, _ = utils.get_stdout_stderr_timeout(cmd)
        else:
            rc, out, _ = crmutils.get_stdout_stderr(cmd)
        if rc == 0 and out:
            out_string += "===== Run \"{}\" on {} =====\n".format(cmd, utils.me())
            out_string += out + "\n\n"

    crmutils.str2file(out_string, os.path.join(context.work_dir, const.SYSSTATS_F))
    utils.log_debug1("Dump system stats into {}/{}".format(context.dest_path, const.SYSSTATS_F))


def dump_state(context):
    for cmd, outf, means in [("crm_mon -1", const.CRM_MON_F, "crm_mon output"),
            ("cibadmin -Ql", const.CIB_F, "cib xml"),
            ("crm_node -p", const.MEMBERSHIP_F, "members of this partition")]:
        rc, out, _ = crmutils.get_stdout_stderr(cmd)
        if rc == 0 and out:
            crmutils.str2file(out, os.path.join(context.work_dir, outf))
            utils.log_debug1("Dump {} into {}/{}".format(means, context.dest_path, outf))


def get_config(context):
    if os.path.isfile(const.CONF):
        shutil.copy2(const.CONF, context.work_dir)
        utils.log_debug1("Dump corosync config into {}/{}".format(context.dest_path, os.path.basename(const.CONF)))

    if bootstrap.service_is_active("pacemaker.service"):
        dump_state(context)
        utils.touch_file(os.path.join(context.work_dir, "RUNNING"))
        utils.log_debug1("Cluster service is running, touch \"RUNNING\" file at {}".format(context.dest_path))
    else:
        cib_f = os.path.join(context.cib_dir, const.CIB_F)
        if os.path.exists(cib_f):
            shutil.copy2(cib_f, context.work_dir)
            utils.log_debug1("Dump cib xml into {}/{}".format(context.dest_path, const.CIB_F))
        utils.touch_file(os.path.join(context.work_dir, "STOPPED"))
        utils.log_debug1("Cluster service is stopped, touch \"STOPPED\" file at {}".format(context.dest_path))

    if os.path.isfile(os.path.join(context.work_dir, const.CIB_F)):
        cmd = r"CIB_file=%s/%s crm configure show" % (context.work_dir, const.CIB_F)
        rc, out, _ = crmutils.get_stdout_stderr(cmd)
        if rc == 0 and out:
            crmutils.str2file(out, os.path.join(context.work_dir, const.CIB_TXT_F))
            utils.log_debug1("Dump cib config into {}/{}".format(context.dest_path, const.CIB_TXT_F))

        cmd = "crm_verify -V -x %s" % os.path.join(context.work_dir, const.CIB_F)
        rc, _, err = crmutils.get_stdout_stderr(cmd)
        if rc != 0 and err:
            crmutils.str2file(err, os.path.join(context.work_dir, const.CRM_VERIFY_F))
            utils.log_error("Create {} because crm_verify failed".format(const.CRM_VERIFY_F))


def get_pe_inputs(context):
    flist = find_pe_files(context)
    if flist:
        flist_dir = os.path.join(context.work_dir, os.path.basename(context.pe_dir))
        utils._mkdir(flist_dir)
        for f in flist:
            os.symlink(f, os.path.join(flist_dir, os.path.basename(f)))
        utils.log_debug2("Found %d pengine input files in %s" % (len(flist), context.pe_dir))
        utils.log_debug1("Dump {} pengine input files into {}/{}".\
                format(len(flist), context.dest_path, os.path.basename(context.pe_dir)))

        convert_pe_dot_files(context, flist, flist_dir)
    else:
        utils.log_debug2("Nothing found for the giving time")


def convert_pe_dot_files(context, flist, flist_dir):
    if len(flist) <= 20:
        if not context.speed_up:
            for f in flist:
                pe_to_dot(os.path.join(flist_dir, os.path.basename(f)))
    else:
        utils.log_debug2("Too many PE inputs to create dot files")


def find_pe_files(context):
    flist = []
    utils.log_debug2("Looking for PE files in {}".format(context.pe_dir))
    for f in utils.find_files(context, context.pe_dir):
        if re.search("[.]last$", f):
            continue
        flist.append(f)
    return flist


def pe_to_dot(pe_file):
    dotf = '.'.join(pe_file.split('.')[:-1]) + '.dot'
    cmd = "%s -D %s -x %s" % (const.PTEST, dotf, pe_file)
    code, _ = crmutils.get_stdout(cmd)
    if code != 0:
        utils.log_warning("pe_to_dot: %s -> %s failed" % (pe_file, dotf))


def touch_dc(context):
    if context.speed_up:
        return
    node = crmutils.get_dc()
    if node and node == utils.me():
        utils.touch_file(os.path.join(context.work_dir, "DC"))
        utils.log_debug1("Node {} is DC, touch \"DC\" file at {}".format(node, context.dest_path))


def get_core_files(context):
    """
    Collect for core files within the report timeframe
    """
    cores = utils.find_files(context, context.cores_dirs)
    flist = [f for f in cores if "core" in os.path.basename(f)]
    if flist:
        utils.log_debug2("Found core files: %s" % ' '.join(flist))
        utils.log_debug1("Dump {} core files into {}/{}".\
                format(len(flist), context.dest_path, os.path.basename(context.cores_dirs)))
        flist_dir = os.path.join(context.work_dir, "cores")
        for f in flist:
            shutil.copy2(f, flist_dir)


def get_other_confs(context):
    for conf in const.OTHER_CONFS:
        if os.path.isfile(conf):
            shutil.copy2(conf, context.work_dir)
        elif os.path.isdir(conf):
            shutil.copytree(conf, os.path.join(context.work_dir, os.path.basename(conf)))
        else:
            continue
        utils.log_debug1("Dump {} into {}".format(conf, context.dest_path))


def check_perms(context):
    """
    Check permissions for key directories
    """
    out_string = ""
    for check_dir in (context.pcmk_lib, context.pe_dir, context.cib_dir):
        OK = True
        out_string += "===== Check permissions for {} on {} ===== ".format(check_dir, utils.me())
        stat_info = os.stat(check_dir)
        if not stat.S_ISDIR(stat_info.st_mode):
            OK = False
            out_string += "\n{} wrong type or doesn't exist\n".format(check_dir)
            continue
        if stat_info.st_uid != pwd.getpwnam('hacluster')[2] or\
           stat_info.st_gid != pwd.getpwnam('hacluster')[3] or\
           "%04o" % (stat_info.st_mode & 0o7777) != "0750":
            OK = False
            out_string += "\nwrong permissions or ownership for {}: ".format(check_dir)
            out_string += crmutils.get_stdout("ls -ld {}".format(check_dir))[1] + '\n'
        if OK:
            out_string += "\nOK\n"
    crmutils.str2file(out_string, os.path.join(context.work_dir, const.PERMISSIONS_F))
    utils.log_debug1("Dump permissions info into {}".format(context.dest_path))


def dlm_dump(context):
    '''
    Get dlm info
    '''
    def has_error(cmd, rc, out, err):
        if rc != 0:
            utils.log_debug2("Error running \"{}\": {}".format(cmd, err))
            return True
        if not out:
            utils.log_debug2("No output for \"{}\"".format(cmd))
            return True
        return False

    if not utils.which("dlm_tool"):
        utils.log_debug2("Command dlm_tool not exist")
        return

    out_string = "===== DLM lockspace overview =====\n"
    cmd = "dlm_tool ls"
    rc, out, err = crmutils.get_stdout_stderr(cmd)
    if has_error(cmd, rc, out, err):
        return
    out_string += out + '\n'
    for item in re.findall("^name", out, re.M):
        lock_name = item.split()[1]
        out_string += "-- DLM lockspace {} --\n".format(lock_name)
        cmd = "dlm_tool lockdebug {}".format(lock_name)
        rc, debug_out, err = crmutils.get_stdout_stderr(cmd)
        if has_error(cmd, rc, debug_out, err):
            return
        out_string += debug_out + '\n'

    out_string += "===== DLM lockspace history =====\n"
    cmd = "dlm_tool dump"
    rc, out, err = crmutils.get_stdout_stderr(cmd)
    if has_error(cmd, rc, out, err):
        return
    out_string += out + '\n'
    
    crmutils.str2file(out_string, os.path.join(context.work_dir, const.DLM_DUMP_F))
    utils.log_debug1("Dump DLM info into {}/{}".format(context.dest_path, const.DLM_DUMP_F))


def time_status(context):
    out_string = "Current time: "
    out_string += utils.now('%c') + '\n'
    if utils.which("ntpdc"):
        rc, out, err = crmutils.get_stdout_stderr("ntpdc -pn")
        if out:
            out_string += "ntpdc: {}\n".format(out)
    crmutils.str2file(out_string, os.path.join(context.work_dir, const.TIME_F))
    utils.log_debug1("Dump time info into {}/{}".format(context.dest_path, const.TIME_F))


def corosync_blackbox(context):
    for cmd in ["corosync-blackbox", "qb-blackbox"]:
        if not utils.which(cmd):
            utils.log_debug2("Command {} not exist".format(cmd))
            return
    fdata_list = []
    for f in utils.find_files(context, const.COROSYNC_LIB):
        if re.search("fdata", f):
            fdata_list.append(f)
    if fdata_list:
        rc, out, err = crmutils.get_stdout_stderr("corosync-blackbox")
        if rc == 0 and out:
            crmutils.str2file(out, os.path.join(context.work_dir, const.COROSYNC_RECORDER_F))
            utils.log_debug1("Dump corosync flight data info {}/{}".format(context.dest_path, const.COROSYNC_RECORDER_F))


def get_ratraces(context):
    trace_dir = os.path.join(context.ha_varlib, "trace_ra")
    if not os.path.exists(trace_dir):
        return
    utils.log_debug2("Looking for RA trace files in {}".format(trace_dir))
    flist = []
    for f in utils.find_files(context, trace_dir):
        flist.append(os.path.join("trace_ra", '/'.join(f.split('/')[-2:])))
    if flist:
        cmd = "tar -cf - -C {} {} | tar -xf - -C {}".format(os.path.dirname(trace_dir), ' '.join(flist), context.work_dir)
        crmutils.get_stdout_stderr(cmd)
        utils.log_debug1("Dump RA trace files at {}".format(context.dest_path))
