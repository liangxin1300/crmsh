# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

import os
from . import command
from . import completers
from . import utils
from .msg import err_buf
from . import corosync
from . import parallax


def _push_completer(args):
    try:
        n = utils.list_cluster_nodes()
        n.remove(utils.this_node())
        if args[-1] in n:
            # continue complete
            return [args[-1]]
        for item in args:
            if item in n:
                n.remove(item)
        return n
    except:
        n = []


def _diff_nodes(args):
    try:
        if len(args) > 3:
            return []
        n = utils.list_cluster_nodes()
        if args[-1] in n:
            # continue complete
            return [args[-1]]
        for item in args:
            if item in n:
                # remove already complete item
                n.remove(item)
        return n
    except:
        return []


class Corosync(command.UI):
    '''
    Corosync is the underlying messaging layer for most HA clusters.
    This level provides commands for editing and managing the corosync
    configuration.
    '''
    name = "corosync"

    def requires(self):
        stack = utils.cluster_stack()
        if len(stack) > 0 and stack != 'corosync':
            err_buf.warning("Unsupported cluster stack %s detected." % (stack))
            return False
        return corosync.check_tools()

    @command.completers(completers.choice(['ring', 'quorum', 'qnetd']))
    def do_status(self, context, status_type="ring"):
        '''
        Quick cluster health status. Corosync status or QNetd status
        '''
        rc, _ = utils.get_stdout('systemctl -q is-active corosync.service')
        if rc != 0:
            err_buf.error("corosync.service is not running!")
            return False

        if status_type == "ring":
            print(corosync.cfgtool('-s')[1])
            return
        if status_type == "quorum":
            print(corosync.quorumtool('-s')[1])
            return
        if status_type == "qnetd":
            if not utils.is_qdevice_configured():
                err_buf.error("QDevice/QNetd not configured!")
                return False
            cluster_name = corosync.get_value('totem.cluster_name')
            if not cluster_name:
                err_buf.error("cluster_name not configured!")
                return False
            qnetd_addr = corosync.get_value('quorum.device.net.host')
            if not qnetd_addr:
                err_buf.error("host for qnetd not configured!")
                return False

            cmd = "corosync-qnetd-tool -lv -c {}".format(cluster_name)
            try:
                result = parallax.parallax_call([qnetd_addr], cmd)
            except ValueError as err:
                err_buf.error(err)
                return False
            _, qnetd_result_stdout, _ = result[0][1]
            if qnetd_result_stdout:
                print(utils.to_ascii(qnetd_result_stdout))
            return

    @command.skill_level('administrator')
    def do_reload(self, context):
        '''
        Reload the corosync configuration
        '''
        return corosync.cfgtool('-R')[0] == 0

    @command.skill_level('administrator')
    @command.completers_repeating(_push_completer)
    def do_push(self, context, *nodes):
        '''
        Push corosync configuration to other cluster nodes.
        If no nodes are provided, configuration is pushed to
        all other cluster nodes.
        '''
        if not nodes:
            nodes = utils.list_cluster_nodes()
            nodes.remove(utils.this_node())
        return corosync.push_configuration(nodes)

    @command.skill_level('administrator')
    @command.completers(_push_completer)
    def do_pull(self, context, node):
        '''
        Pull corosync configuration from another node.
        '''
        return corosync.pull_configuration(node)

    @command.completers_repeating(_diff_nodes)
    def do_diff(self, context, *nodes):
        '''
        Compare corosync configuration between nodes.
        '''
        checksum = False
        if nodes and nodes[0] == '--checksum':
            checksum = True
            nodes = nodes[1:]
        if not nodes:
            nodes = utils.list_cluster_nodes()
        return corosync.diff_configuration(nodes, checksum=checksum)

    @command.skill_level('administrator')
    def do_edit(self, context):
        '''
        Edit the corosync configuration.
        '''
        cfg = corosync.conf()
        try:
            utils.edit_file_ext(cfg, template='')
        except IOError as e:
            context.fatal_error(str(e))

    def do_show(self, context):
        '''
        Display the corosync configuration.
        '''
        cfg = corosync.conf()
        if not os.path.isfile(cfg):
            context.fatal_error("No corosync configuration found on this node.")
        utils.page_string(open(cfg).read())

    def do_log(self, context):
        '''
        Display the corosync log file (if any).
        '''
        logfile = corosync.get_value('logging.logfile')
        if not logfile:
            context.fatal_error("No corosync log file configured")
        utils.page_file(logfile)

    @command.name('add-node')
    @command.alias('add_node')
    @command.skill_level('administrator')
    def do_addnode(self, context, addr, name=None):
        "Add a node to the corosync nodelist"
        corosync.add_node(addr, name)

    @command.name('del-node')
    @command.alias('del_node')
    @command.skill_level('administrator')
    @command.completers(_push_completer)
    def do_delnode(self, context, name):
        "Remove a node from the corosync nodelist"
        transport = corosync.get_value('totem.transport')
        if not transport or transport != "udpu":
            context.fatal_error("Only support udpu transport now")
        corosync.del_node(name)

    @command.skill_level('administrator')
    @command.completers(completers.call(corosync.get_all_paths))
    def do_get(self, context, path):
        "Get a corosync configuration value"
        for v in corosync.get_values(path):
            print(v)

    @command.skill_level('administrator')
    def do_set(self, context, path, value):
        "Set a corosync configuration value"
        corosync.set_value(path, value)
