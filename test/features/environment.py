import re
from crmsh import utils, bootstrap

def run_command(cmd):
    _, _, err = utils.get_stdout_stderr(cmd)
    if err:
        print(err)


def before_scenario(context, scenario):
    if scenario.name == "Second node join and start qdevice":
        return
    if scenario.name == "Remove qdevice on a two nodes cluster":
        return
    if re.search(r'Validation [0-9]+', scenario.name):
        return
    if bootstrap.service_is_active('corosync.service'):
        run_command('crm cluster stop')
    if scenario.name == "Setup qdevice/qnetd after init process":
        run_command('crm cluster init -y')
    if scenario.name == "Setup qdevice/qnetd on a two nodes cluster":
        cmd = "crm cluster stop"
        addr = "hanode2"
        utils.parallax_call([addr], cmd)
        run_command('crm cluster init -y')
        cmd = "crm cluster join -c hanode1 -y"
        utils.parallax_call([addr], cmd)
