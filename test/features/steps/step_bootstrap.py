import os
from behave import given, when, then
import utils

@given('Have "{cmd}" command')
def step_impl(context, cmd):
    cmd = "which {}".format(cmd)
    rc, _, _ = utils.run_command(cmd)
    assert rc == 0

@given('Cluster is not running on "{addr}"')
def step_impl(context, addr):
    assert utils.check_service_active('corosync.service', addr) is False

@given('Already have ssh key')
def step_impl(context):
    assert os.path.exists("/root/.ssh/id_rsa") is True
    context.sshkey_mtime = os.path.getmtime("/root/.ssh/id_rsa")

@given('"{file_path}" not exists')
def step_impl(context, file_path):
    assert os.path.exists(file_path) is False

@when('Run "{cmd}" on "{addr}"')
def step_impl(context, cmd, addr):
    if addr == "local":
        rc, out, err = utils.run_command(cmd)
        context.command_rc = rc
        context.command_out = out
        context.command_err = err
    else:
        pass

@then('Got right outputs')
def step_impl(context):
    if context.scenario.name == "Show init help messages":
        assert context.command_rc == 0
        assert context.command_out == context.init_help_message

@then('ssh key have no changes')
def step_impl(context):
    assert context.sshkey_mtime == os.path.getmtime("/root/.ssh/id_rsa")

@then('ssh key have changed')
def step_impl(context):
    assert context.sshkey_mtime != os.path.getmtime("/root/.ssh/id_rsa")

@then('Cluster is running on "{nodelist}"')
def step_impl(context, nodelist):
    assert utils.check_cluster_status(nodelist) is True

@then('"{file_path}" exists')
def step_impl(context, file_path):
    assert os.path.exists(file_path) is True
