import re
import socket
import tarfile
import glob
from crmsh import utils, bootstrap, parallax


def get_file_type(file_path):
    rc, out, _ = utils.get_stdout_stderr("file {}".format(file_path))
    if re.search(r'{}: bzip2'.format(file_path), out):
        return "bzip2"
    if re.search(r'{}: directory'.format(file_path), out):
        return "directory"


def get_all_files(archive_path):
    archive_type = get_file_type(archive_path)
    if archive_type == "bzip2":
        with tarfile.open(archive_path) as tar:
            return tar.getnames()
    if archive_type == "directory":
        all_files = glob.glob("{}/*".format(archive_path)) + glob.glob("{}/*/*".format(archive_path))
        return all_files


def me():
    return socket.gethostname()


def run_command(context, cmd, err_record=False):
    rc, out, err = utils.get_stdout_stderr(cmd)
    if rc != 0 and err:
        if err_record:
            context.command_error_output = err
            return
        if out:
            context.logger.info("\n{}\n".format(out))
        context.logger.error("\n{}\n".format(err))
        context.failed = True
    return out


def run_command_local_or_remote(context, cmd, addr, err_record=False):
    if addr == me():
        out = run_command(context, cmd, err_record)
        return out
    else:
        try:
            results = parallax.parallax_call([addr], cmd)
        except ValueError as err:
            if err_record:
                context.command_error_output = str(err)
                return
            context.logger.error("\n{}\n".format(err))
            context.failed = True
        else:
            return utils.to_ascii(results[0][1][1])


def check_service_state(context, service_name, state, addr):
    if state not in ["started", "stopped"]:
        context.logger.error("\nService state should be \"started/stopped\"\n")
        context.failed = True

    state_dict = {"started": True, "stopped": False}

    if addr == me():
        return bootstrap.service_is_active(service_name) is state_dict[state]
    else:
        test_active = "systemctl -q is-active {}".format(service_name)
        try:
            parallax.parallax_call([addr], test_active)
        except ValueError:
            return state_dict[state] is False
        else:
            return state_dict[state] is True


def check_cluster_state(context, state, addr):
    return check_service_state(context, 'pacemaker.service', state, addr)


def online(context, nodelist):
    rc = True
    _, out = utils.get_stdout("crm_node -l")
    for node in nodelist.split():
        node_info = "{} member".format(node)
        if not node_info in out:
            rc = False
            context.logger.error("\nNode \"{}\" not online\n".format(node))
    return rc
