import re
from behave import given, when, then
from crmsh import utils, bootstrap

def run_command(cmd, stdout=True, stderr=True):
    rc, out, err = utils.get_stdout_stderr(cmd)
    if out and stdout:
        print(out)
    if err and stderr:
        print(err)
    return rc, out, err

def check_service_active(service_name, addr):
    if addr == "local":
        return bootstrap.service_is_active(service_name)
    test_active = "systemctl -q is-active {}".format(service_name)
    try:
        utils.parallax_call([addr], test_active)
    except ValueError:
        return False
    else:
        return True

def check_cluster_status(nodelist):
    if nodelist == "local":
        return bootstrap.service_is_active('pacemaker.service')
    _, out = utils.get_stdout("crm_node -l")
    for node in nodelist.split():
        node_info = "{} member".format(node)
        if not node_info in out:
            return False
    return True

@given('Packages should be installed')
def step_impl(context):
    for row in context.table:
        cmd = "rpm -qi {}".format(row["pkg_name"])
        assert run_command(cmd, stdout=False)[0] == 0

@given('Cluster is not running on "{addr}"')
def step_impl(context, addr):
    assert check_service_active('corosync.service', addr) is False

@given('Cluster is running on "{nodelist}"')
def step_impl(context, nodelist):
    assert check_cluster_status(nodelist) is True

@given('Service "{service_name}" is not running on "{addr}"')
def step_impl(context, service_name, addr):
    assert check_service_active(service_name, addr) is False

@given('Service "{service_name}" is running on "{addr}"')
def step_impl(context, service_name, addr):
    assert check_service_active(service_name, addr) is True

@when('Run "{cmd}" on "{addr}"')
def step_impl(context, cmd, addr):
    if addr == "local":
        rc, out, err = run_command(cmd)
        context.command_rc = rc
        context.command_out = out
        context.command_err = err
    else:
        results = utils.parallax_call([addr], cmd)
        assert isinstance(results, list)

@then('Cluster is running on "{nodelist}"')
def step_impl(context, nodelist):
    assert check_cluster_status(nodelist) is True

@then('Service "{service_name}" is running on "{addr}"')
def step_impl(context, service_name, addr):
    assert check_service_active(service_name, addr) is True

@then('Service "{service_name}" is not running on "{addr}"')
def step_impl(context, service_name, addr):
    assert check_service_active(service_name, addr) is False

@then('Got "{output}"')
def step_impl(context, output):
    if re.search(r'Validation [0-9]+', context.scenario.name):
        assert context.command_rc != 0
        assert context.command_err == output
