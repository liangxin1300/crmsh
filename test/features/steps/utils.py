import os
from crmsh import utils, bootstrap

def run_command(cmd, stdout=False, stderr=False):
    rc, out, err = utils.get_stdout_stderr(cmd)
    if out and stdout:
        print(out)
    if err and stderr:
        print(err)
    return rc, out, err

def check_cluster_status(nodelist):
    if nodelist == "local":
        return bootstrap.service_is_active('pacemaker.service')

def check_service_active(service_name, addr):
    if addr == "local":
        return bootstrap.service_is_active(service_name)
