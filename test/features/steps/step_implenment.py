import os
import re
import time
import datetime
from behave import given, when, then
from crmsh import corosync, parallax
from utils import check_cluster_state, check_service_state, online, run_command, me, \
        run_command_local_or_remote, get_file_type, get_all_files


@given('Cluster service is "{state}" on "{addr}"')
def step_impl(context, state, addr):
    assert check_cluster_state(context, state, addr) is True


@given('Service "{name}" is "{state}" on "{addr}"')
def step_impl(context, name, state, addr):
    assert check_service_state(context, name, state, addr) is True


@given('Online nodes are "{nodelist}"')
def step_impl(context, nodelist):
    assert online(context, nodelist) is True


@given('IP "{addr}" is belong to "{iface}"')
def step_impl(context, addr, iface):
    cmd = 'ip address show dev {}'.format(iface)
    res = re.search(r' {}/'.format(addr), run_command(context, cmd))
    assert bool(res) is True


@when('Run "{cmd}" on "{addr}"')
def step_impl(context, cmd, addr):
    out = run_command_local_or_remote(context, cmd, addr)
    if out:
        context.stdout = out
        context.logger.info("\n{}".format(out))


@when('Try "{cmd}"')
def step_impl(context, cmd):
    run_command(context, cmd, err_record=True)


@when('Wait "{second}" seconds')
def step_impl(context, second):
    time.sleep(int(second))


@then('Got output "{msg}"')
def step_impl(context, msg):
    assert context.stdout == msg
    context.stdout = None


@then('Except "{msg}"')
def step_impl(context, msg):
    assert context.command_error_output == msg
    context.command_error_output = None


@then('Except multiline')
def step_impl(context):
    assert context.command_error_output == context.text
    context.command_error_output = None


@then('Cluster service is "{state}" on "{addr}"')
def step_impl(context, state, addr):
    assert check_cluster_state(context, state, addr) is True


@then('Service "{name}" is "{state}" on "{addr}"')
def step_impl(context, name, state, addr):
    assert check_service_state(context, name, state, addr) is True


@then('Online nodes are "{nodelist}"')
def step_impl(context, nodelist):
    assert online(context, nodelist) is True


@then('IP "{addr}" is used by corosync')
def step_impl(context, addr):
    out = run_command(context, 'corosync-cfgtool -s')
    res = re.search(r' {}\n'.format(addr), out)
    assert bool(res) is True


@then('Cluster name is "{name}"')
def step_impl(context, name):
    out = run_command(context, 'corosync-cmapctl -b totem.cluster_name')
    assert out.split()[-1] == name


@then('Cluster virtual IP is "{addr}"')
def step_impl(context, addr):
    out = run_command(context, 'crm configure show|grep -A1 IPaddr2')
    res = re.search(r' ip={}'.format(addr), out)
    assert bool(res) is True


@then('Cluster is using udpu transport mode')
def step_impl(context):
    assert corosync.get_value('totem.transport') == 'udpu'


@then('Show cluster status on "{addr}"')
def step_impl(context, addr):
    out = run_command_local_or_remote(context, 'crm_mon -1', addr)
    if out:
        context.logger.info("\n{}".format(out))


@then('Show corosync ring status')
def step_impl(context):
    out = run_command(context, 'crm corosync status ring')
    if out:
        context.logger.info("\n{}".format(out))


@then('Show status from qnetd')
def step_impl(context):
    out = run_command(context, 'crm corosync status qnetd')
    if out:
        context.logger.info("\n{}".format(out))


@then('Show corosync qdevice configuration')
def step_impl(context):
    out = run_command(context, "sed -n -e '/quorum/,/^}/ p' /etc/corosync/corosync.conf")
    if out:
        context.logger.info("\n{}".format(out))


@then('Resource "{res}" type "{res_type}" is "{state}"')
def step_impl(context, res, res_type, state):
    try_count = 0
    result = None
    while try_count < 5:
        time.sleep(1)
        out = run_command(context, "crm_mon -1")
        if out:
            result = re.search(r'\s{}\s+.*:{}\):\s+{} '.format(res, res_type, state), out)
            if not result:
                try_count += 1
            else:
                break
    assert result is not None


@then('Resource "{res}" failcount on "{node}" is "{number}"')
def step_impl(context, res, node, number):
    cmd = "crm resource failcount {} show {}".format(res, node)
    out = run_command(context, cmd)
    if out:
        result = re.search(r'name=fail-count-{} value={}'.format(res, number), out)
        assert result is not None


@then('Default hb_report tar file created')
def step_impl(context):
    default_file_name = 'hb_report-{}.tar.bz2'.format(datetime.datetime.now().strftime("%a-%d-%b-%Y"))
    assert os.path.exists(default_file_name) is True


@then('Default hb_report directory created')
def step_impl(context):
    default_file_name = 'hb_report-{}'.format(datetime.datetime.now().strftime("%a-%d-%b-%Y"))
    assert os.path.isdir(default_file_name) is True


@then('"{file_name}" created')
def step_impl(context, file_name):
    file_type = get_file_type(file_name)
    if file_type == "bzip2":
        assert os.path.exists(file_name) is True
    if file_type == "directory":
        assert os.path.isdir(file_name) is True


@then('"{archive_name}" include essential files for "{nodes}"')
def step_impl(context, archive_name, nodes):
    files = 'cib.txt cib.xml context.txt corosync.conf crm_mon.txt journal.log sysinfo.txt'
    essential_files_list = []
    base_archive_name = ""
    archive_type = get_file_type(archive_name)

    if archive_type == "bzip2":
        base_archive_name = '.'.join(os.path.basename(archive_name).split('.')[:-2])
    if archive_type == "directory":
        base_archive_name = archive_name
    for node in nodes.split():
        essential_files_list += ["{}/{}/{}".format(base_archive_name, node, f) for f in files.split()]
    
    all_files = get_all_files(archive_name)
    for ef in essential_files_list:
        assert ef in all_files
