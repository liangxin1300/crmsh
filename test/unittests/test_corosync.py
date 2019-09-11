from __future__ import print_function
from __future__ import unicode_literals
# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.
#
# unit tests for parse.py

from builtins import str
from builtins import object
import os
import unittest
from unittest import mock
from crmsh import corosync
from crmsh.corosync import Parser, make_section, make_value


F1 = open(os.path.join(os.path.dirname(__file__), 'corosync.conf.1')).read()
F2 = open(os.path.join(os.path.dirname(__file__), 'corosync.conf.2')).read()
F3 = open(os.path.join(os.path.dirname(__file__), 'bug-862577_corosync.conf')).read()


def _valid(parser):
    depth = 0
    for t in parser._tokens:
        if t.token not in (corosync._tCOMMENT,
                           corosync._tBEGIN,
                           corosync._tEND,
                           corosync._tVALUE):
            raise AssertionError("illegal token " + str(t))
        if t.token == corosync._tBEGIN:
            depth += 1
        if t.token == corosync._tEND:
            depth -= 1
    if depth != 0:
        raise AssertionError("Unbalanced sections")


def _print(parser):
    print(parser.to_string())


class TestCorosyncParser(unittest.TestCase):
    def test_parse(self):
        p = Parser(F1)
        _valid(p)
        self.assertEqual(p.get('logging.logfile'), '/var/log/cluster/corosync.log')
        self.assertEqual(p.get('totem.interface.ttl'), '1')
        p.set('totem.interface.ttl', '2')
        _valid(p)
        self.assertEqual(p.get('totem.interface.ttl'), '2')
        p.remove('quorum')
        _valid(p)
        self.assertEqual(p.count('quorum'), 0)
        p.add('', make_section('quorum', []))
        _valid(p)
        self.assertEqual(p.count('quorum'), 1)
        p.set('quorum.votequorum', '2')
        _valid(p)
        self.assertEqual(p.get('quorum.votequorum'), '2')
        p.set('bananas', '5')
        _valid(p)
        self.assertEqual(p.get('bananas'), '5')

    def test_logfile(self):
        self.assertEqual(corosync.logfile(F1), '/var/log/cluster/corosync.log')
        self.assertEqual(corosync.logfile('# nothing\n'), None)

    def test_udpu(self):
        p = Parser(F2)
        _valid(p)
        self.assertEqual(p.count('nodelist.node'), 5)
        p.add('nodelist',
              make_section('nodelist.node',
                           make_value('nodelist.node.ring0_addr', '10.10.10.10') +
                           make_value('nodelist.node.nodeid', str(corosync.get_free_nodeid(p)))))
        _valid(p)
        self.assertEqual(p.count('nodelist.node'), 6)
        self.assertEqual(p.get_all('nodelist.node.nodeid'),
                         ['1', '2', '3'])

    def test_add_node_no_nodelist(self):
        "test checks that if there is no nodelist, no node is added"
        from crmsh.corosync import make_section, make_value, get_free_nodeid

        p = Parser(F1)
        _valid(p)
        nid = get_free_nodeid(p)
        self.assertEqual(p.count('nodelist.node'), nid - 1)
        p.add('nodelist',
              make_section('nodelist.node',
                           make_value('nodelist.node.ring0_addr', 'foo') +
                           make_value('nodelist.node.nodeid', str(nid))))
        _valid(p)
        self.assertEqual(p.count('nodelist.node'), nid - 1)

    def test_add_node_nodelist(self):
        from crmsh.corosync import make_section, make_value, get_free_nodeid

        p = Parser(F2)
        _valid(p)
        nid = get_free_nodeid(p)
        c = p.count('nodelist.node')
        p.add('nodelist',
              make_section('nodelist.node',
                           make_value('nodelist.node.ring0_addr', 'foo') +
                           make_value('nodelist.node.nodeid', str(nid))))
        _valid(p)
        self.assertEqual(p.count('nodelist.node'), c + 1)
        self.assertEqual(get_free_nodeid(p), nid + 1)

    def test_remove_node(self):
        p = Parser(F2)
        _valid(p)
        self.assertEqual(p.count('nodelist.node'), 5)
        p.remove_section_where('nodelist.node', 'nodeid', '2')
        _valid(p)
        self.assertEqual(p.count('nodelist.node'), 4)
        self.assertEqual(p.get_all('nodelist.node.nodeid'),
                         ['1'])

    def test_bnc862577(self):
        p = Parser(F3)
        _valid(p)
        self.assertEqual(p.count('service.ver'), 1)

    def test_get_free_nodeid(self):
        def ids(*lst):
            class Ids(object):
                def get_all(self, _arg):
                    return lst
            return Ids()
        self.assertEqual(1, corosync.get_free_nodeid(ids('2', '5')))
        self.assertEqual(3, corosync.get_free_nodeid(ids('1', '2', '5')))
        self.assertEqual(4, corosync.get_free_nodeid(ids('1', '2', '3')))


class TestQDevice(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    def setUp(self):
        """
        Test setUp.
        """
        # Use the setup to create a fresh instance for each test
        self.qdevice_with_ip = corosync.QDevice("10.10.10.123")
        self.qdevice_with_hostname = corosync.QDevice("node.qnetd")
        self.qdevice_with_invalid_port = corosync.QDevice("10.10.10.123", port=100)
        self.qdevice_with_invalid_algo = corosync.QDevice("10.10.10.123", algo="wrong")
        self.qdevice_with_invalid_tie_breaker = corosync.QDevice("10.10.10.123", tie_breaker="wrong")

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.utils.ip_in_local")
    def test_valid_attr_remote_exception(self, mock_ip_in_local, mock_this_node):
        mock_ip_in_local.return_value = ["192.168.1.1", "10.10.10.123"]
        mock_this_node.return_value = "node1.com"
        with self.assertRaises(ValueError) as err:
            self.qdevice_with_ip.valid_attr()
        self.assertEqual("host for qnetd must be a remote one", str(err.exception))
        mock_ip_in_local.assert_called_once_with()
        mock_this_node.assert_called_once_with()

    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.utils.ip_in_local")
    @mock.patch("crmsh.utils.resolve_hostnames")
    def test_valid_attr_unreachable_exception(self,
                                              mock_resolve,
                                              mock_ip_in_local,
                                              mock_this_node):
        mock_resolve.return_value = (False, "node.qnetd")
        mock_ip_in_local.return_value = ["192.168.1.1", "10.10.10.123"]
        mock_this_node.return_value = "node1.com"
        with self.assertRaises(ValueError) as err:
            self.qdevice_with_hostname.valid_attr()
        self.assertEqual("host \"node.qnetd\" is unreachable", str(err.exception))
        mock_ip_in_local.assert_called_once_with()
        mock_this_node.assert_called_once_with()
        mock_resolve.assert_called_once_with(["node.qnetd"])


    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.utils.ip_in_local")
    @mock.patch("crmsh.utils.resolve_hostnames")
    @mock.patch("crmsh.utils.check_port_open")
    def test_valid_attr_ssh_service_exception(self,
                                              mock_port_open,
                                              mock_resolve,
                                              mock_ip_in_local,
                                              mock_this_node):
        mock_resolve.return_value = (True, None)
        mock_ip_in_local.return_value = ["192.168.1.1", "10.10.10.11"]
        mock_this_node.return_value = "node1.com"
        mock_port_open.return_value = False
        with self.assertRaises(ValueError) as err:
            self.qdevice_with_ip.valid_attr()
        self.assertEqual("ssh service on \"10.10.10.123\" not available", str(err.exception))
        mock_ip_in_local.assert_called_once_with()
        mock_this_node.assert_called_once_with()
        mock_resolve.assert_called_once_with(["10.10.10.123"])
        mock_port_open.assert_called_once_with("10.10.10.123", 22)

    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.utils.ip_in_local")
    @mock.patch("crmsh.utils.resolve_hostnames")
    @mock.patch("crmsh.utils.check_port_open")
    @mock.patch("crmsh.utils.valid_port")
    def test_valid_attr_invalid_port_exception(self,
                                               mock_valid_port,
                                               mock_port_open,
                                               mock_resolve,
                                               mock_ip_in_local,
                                               mock_this_node):
        mock_resolve.return_value = (True, None)
        mock_ip_in_local.return_value = ["192.168.1.1", "10.10.10.11"]
        mock_this_node.return_value = "node1.com"
        mock_port_open.return_value = True
        mock_valid_port.return_value = False
        with self.assertRaises(ValueError) as err:
            self.qdevice_with_invalid_port.valid_attr()
        self.assertEqual("invalid qdevice port range(1024 - 65535)", str(err.exception))
        mock_ip_in_local.assert_called_once_with()
        mock_this_node.assert_called_once_with()
        mock_resolve.assert_called_once_with(["10.10.10.123"])
        mock_port_open.assert_called_once_with("10.10.10.123", 22)
        mock_valid_port.assert_called_once_with(100)

    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.utils.ip_in_local")
    @mock.patch("crmsh.utils.resolve_hostnames")
    @mock.patch("crmsh.utils.check_port_open")
    @mock.patch("crmsh.utils.valid_port")
    def test_valid_attr_invalid_port_exception(self,
                                               mock_valid_port,
                                               mock_port_open,
                                               mock_resolve,
                                               mock_ip_in_local,
                                               mock_this_node):
        mock_resolve.return_value = (True, None)
        mock_ip_in_local.return_value = ["192.168.1.1", "10.10.10.11"]
        mock_this_node.return_value = "node1.com"
        mock_port_open.return_value = True
        mock_valid_port.return_value = True
        with self.assertRaises(ValueError) as err:
            self.qdevice_with_invalid_algo.valid_attr()
        self.assertEqual("invalid qdevice algorithm(ffsplit/lms)", str(err.exception))
        mock_ip_in_local.assert_called_once_with()
        mock_this_node.assert_called_once_with()
        mock_resolve.assert_called_once_with(["10.10.10.123"])
        mock_port_open.assert_called_once_with("10.10.10.123", 22)
        mock_valid_port.assert_called_once_with(5403)

    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.utils.ip_in_local")
    @mock.patch("crmsh.utils.resolve_hostnames")
    @mock.patch("crmsh.utils.check_port_open")
    @mock.patch("crmsh.utils.valid_port")
    @mock.patch("crmsh.utils.valid_nodeid")
    def test_valid_attr_invalid_nodeid_exception(self,
                                                 mock_valid_nodeid,
                                                 mock_valid_port,
                                                 mock_port_open,
                                                 mock_resolve,
                                                 mock_ip_in_local,
                                                 mock_this_node):
        mock_resolve.return_value = (True, None)
        mock_ip_in_local.return_value = ["192.168.1.1", "10.10.10.11"]
        mock_this_node.return_value = "node1.com"
        mock_port_open.return_value = True
        mock_valid_port.return_value = True
        mock_valid_nodeid.return_value = False
        with self.assertRaises(ValueError) as err:
            self.qdevice_with_invalid_tie_breaker.valid_attr()
        self.assertEqual("invalid qdevice tie_breaker(lowest/highest/valid_node_id)", str(err.exception))
        mock_ip_in_local.assert_called_once_with()
        mock_this_node.assert_called_once_with()
        mock_resolve.assert_called_once_with(["10.10.10.123"])
        mock_port_open.assert_called_once_with("10.10.10.123", 22)
        mock_valid_port.assert_called_once_with(5403)
        mock_valid_nodeid.assert_called_once_with("wrong")
    '''
    @mock.patch("crmsh.utils.parallax_call")
    def test_remote_running_cluster_false(self, mock_call, mock_error):
        mock_error = mock.Mock(side_effect=ValueError)
        mock_call.return_value = ["10.10.10.123", mock_error]
        self.assertFalse(self.qdevice_with_ip.remote_running_cluster())
        mock_call.assert_called_once_with(["10.10.10.123"], "systemctl -q is-active pacemaker", False)
    '''

    @mock.patch("crmsh.utils.parallax_call")
    def test_remote_running_cluster_true(self, mock_call):
        mock_call.return_value = ["10.10.10.123", (0, None, None)]
        self.assertTrue(self.qdevice_with_ip.remote_running_cluster())
        mock_call.assert_called_once_with(["10.10.10.123"], "systemctl -q is-active pacemaker", False)

    @mock.patch("crmsh.utils.parallax_call")
    def test_manage_qnetd(self, mock_call):
        mock_call.return_value = ["10.10.10.123", (0, None, None)]
        self.qdevice_with_ip.manage_qnetd("test")
        mock_call.assert_called_once_with(["10.10.10.123"], "systemctl test corosync-qnetd.service", False)

    @mock.patch("crmsh.corosync.QDevice.manage_qnetd")
    def test_enable_qnetd(self, mock_manage_qnetd):
        self.qdevice_with_ip.enable_qnetd()
        mock_manage_qnetd.assert_called_once_with("enable")

    @mock.patch("crmsh.corosync.QDevice.manage_qnetd")
    def test_disable_qnetd(self, mock_manage_qnetd):
        self.qdevice_with_ip.disable_qnetd()
        mock_manage_qnetd.assert_called_once_with("disable")

    @mock.patch("crmsh.corosync.QDevice.manage_qnetd")
    def test_start_qnetd(self, mock_manage_qnetd):
        self.qdevice_with_ip.start_qnetd()
        mock_manage_qnetd.assert_called_once_with("start")

    @mock.patch("crmsh.corosync.QDevice.manage_qnetd")
    def test_stop_qnetd(self, mock_manage_qnetd):
        self.qdevice_with_ip.stop_qnetd()
        mock_manage_qnetd.assert_called_once_with("stop")

    @mock.patch("crmsh.utils.parallax_call")
    @mock.patch("crmsh.corosync.QDevice.qnetd_cacert_on_qnetd", new_callable=mock.PropertyMock)
    def test_init_db_on_qnetd_already_exists(self, mock_qnetd_cacert, mock_call):
        mock_call.return_value = [("10.10.10.123", (0, None, None))]
        mock_qnetd_cacert.return_value = "/etc/corosync/qnetd/nssdb/qnetd-cacert.crt"
        self.qdevice_with_ip.init_db_on_qnetd()
        mock_call.assert_called_once_with(["10.10.10.123"],
                                          "test -f {}".format(mock_qnetd_cacert.return_value),
                                          False)
        mock_qnetd_cacert.assert_called_once_with()

    '''
    @mock.patch("parallax.Error")
    @mock.patch("crmsh.utils.parallax_call")
    @mock.patch("crmsh.corosync.QDevice.qnetd_cacert_on_qnetd", new_callable=mock.PropertyMock)
    def test_init_db_on_qnetd(self, mock_qnetd_cacert, mock_call, mock_error):
        mock_error = mock.Mock()
        mock_call.side_effect = [[("10.10.10.123", mock_error)], [("10.10.10.123", (0, None, None))]]
        mock_qnetd_cacert.return_value = "/etc/corosync/qnetd/nssdb/qnetd-cacert.crt"

        self.qdevice_with_ip.init_db_on_qnetd()

        mock_call.assert_has_calls([
            mock.call(["10.10.10.123"], "test -f {}".format(mock_qnetd_cacert.return_value), False),
            mock.call(["10.10.10.123"], "corosync-qnetd-certutil -i", False)
        ])
        mock_qnetd_cacert.assert_called_once_with()
    '''

    @mock.patch("os.path.exists")
    @mock.patch("crmsh.utils.parallax_slurp")
    @mock.patch("crmsh.corosync.QDevice.qnetd_cacert_on_local", new_callable=mock.PropertyMock)
    def test_fetch_qnetd_crt_from_qnetd(self, mock_qnetd_cacert_local,
                                        mock_slurp, mock_exists):
        mock_qnetd_cacert_local.return_value = "/etc/corosync/qdevice/net/10.10.10.123/qnetd-cacert.crt"
        mock_exists.return_value = False
        mock_slurp.return_value = [("10.10.10.123", (0, None, None, "test"))]

        self.qdevice_with_ip.fetch_qnetd_crt_from_qnetd()

        mock_exists.assert_called_once_with(mock_qnetd_cacert_local.return_value)
        mock_slurp.assert_called_once_with(["10.10.10.123"], "/etc/corosync/qdevice/net",
                                           "/etc/corosync/qnetd/nssdb/qnetd-cacert.crt", False)

    @mock.patch("crmsh.utils.list_cluster_nodes")
    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.utils.parallax_copy")
    def test_copy_qnetd_crt_to_cluster_one_node(self, mock_copy, mock_this_node, mock_list_nodes):
        mock_this_node.return_value = "node1.com"
        mock_list_nodes.return_value = ["node1.com"]

        self.qdevice_with_ip.copy_qnetd_crt_to_cluster()

        mock_this_node.assert_called_once_with()
        mock_list_nodes.assert_called_once_with()
        mock_copy.assert_not_called()

    @mock.patch("crmsh.utils.list_cluster_nodes")
    @mock.patch("crmsh.utils.this_node")
    @mock.patch("crmsh.utils.parallax_copy")
    @mock.patch("crmsh.corosync.QDevice.qnetd_cacert_on_local", new_callable=mock.PropertyMock)
    @mock.patch("os.path.dirname")
    def test_copy_qnetd_crt_to_cluster(self, mock_dirname, mock_qnetd_cacert_local,
                                       mock_copy, mock_this_node, mock_list_nodes):
        mock_qnetd_cacert_local.return_value = "/etc/corosync/qdevice/net/10.10.10.123/qnetd-cacert.crt"
        mock_dirname.return_value = "/etc/corosync/qdevice/net/10.10.10.123"
        mock_this_node.return_value = "node1.com"
        mock_list_nodes.return_value = ["node1.com", "node2.com"]
        mock_copy.return_value = [("node1.com", (0, None, None)), ("node2", (0, None, None))]

        self.qdevice_with_ip.copy_qnetd_crt_to_cluster()

        mock_this_node.assert_not_called()
        mock_list_nodes.assert_called_once_with()
        mock_copy.assert_called_once_with(["node1.com", "node2.com"],
                                          mock_dirname.return_value,
                                          "/etc/corosync/qdevice/net",
                                          False)

    @mock.patch("crmsh.utils.parallax_call")
    @mock.patch("crmsh.corosync.QDevice.qnetd_cacert_on_local", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.utils.list_cluster_nodes")
    def test_init_db_on_cluster(self, mock_list_nodes, mock_qnetd_cacert_local, mock_call):
        mock_list_nodes.return_value = ["node1", "node2"]
        mock_qnetd_cacert_local.return_value = "/etc/corosync/qdevice/net/10.10.10.123/qnetd-cacert.crt"
        mock_call.return_value = [("node1", (0, None, None)), ("node2", (0, None, None))]

        self.qdevice_with_ip.init_db_on_cluster()

        mock_list_nodes.assert_called_once_with()
        mock_qnetd_cacert_local.assert_called_once_with()
        mock_call.assert_called_once_with(mock_list_nodes.return_value,
                                          "corosync-qdevice-net-certutil -i -c {}".format(mock_qnetd_cacert_local.return_value),
                                          False)

    @mock.patch("crmsh.corosync.conf")
    @mock.patch("crmsh.corosync.get_value")
    def test_create_ca_request_exception(self, mock_get_value, mock_conf):
        mock_get_value.return_value = None
        mock_conf.return_value = "/etc/corosync/corosync.conf"

        with self.assertRaises(ValueError) as err:
            self.qdevice_with_ip.create_ca_request()
        self.assertEqual("No cluster_name found in {}".format(mock_conf.return_value), str(err.exception))

        mock_get_value.assert_called_once_with("totem.cluster_name")
        mock_conf.assert_called_once_with()

    @mock.patch("crmsh.utils.get_stdout_stderr")
    @mock.patch("crmsh.corosync.conf")
    @mock.patch("crmsh.corosync.get_value")
    def test_create_ca_request(self, mock_get_value, mock_conf, mock_stdout_stderr):
        mock_get_value.return_value = "hacluster"
        mock_stdout_stderr.return_value = (0, None, None)

        self.qdevice_with_ip.create_ca_request()

        mock_get_value.assert_called_once_with("totem.cluster_name")
        mock_conf.assert_not_called()
        mock_stdout_stderr.assert_called_once_with("corosync-qdevice-net-certutil -r -n {}".format(mock_get_value.return_value))

    @mock.patch("os.path.dirname")
    @mock.patch("crmsh.corosync.QDevice.qdevice_crq_on_qnetd", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.corosync.QDevice.qdevice_crq_on_local", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.utils.parallax_copy")
    def test_copy_crq_to_qnetd(self, mock_copy, mock_qdevice_crq_local,
                               mock_qdevice_crq_qnetd, mock_dirname):
        mock_copy.return_value = [("10.10.10.123", (0, None, None))]
        mock_qdevice_crq_local.return_value = "/etc/corosync/qdevice/net/nssdb/qdevice-net-node.crq"
        mock_qdevice_crq_qnetd.return_value = "/etc/corosync/qnetd/nssdb/qdevice-net-node.crq"
        mock_dirname.return_value = "/etc/corosync/qnetd/nssdb"

        self.qdevice_with_ip.copy_crq_to_qnetd()

        mock_copy.assert_called_once_with(["10.10.10.123"],
                                          mock_qdevice_crq_local.return_value,
                                          mock_dirname.return_value,
                                          False)
        mock_qdevice_crq_local.assert_called_once_with()
        mock_qdevice_crq_qnetd.assert_called_once_with()
        mock_dirname.assert_called_once_with(mock_qdevice_crq_qnetd.return_value)

    '''
    @mock.patch("crmsh.corosync.QDevice.handle_parallax_results")
    @mock.patch("crmsh.utils.parallax_call")
    @mock.patch("crmsh.corosync.QDevice.qdevice_crq_on_qnetd", new_callable=mock.PropertyMock)
    def test_sign_crq_on_qnetd(self, mock_qdevice_crq_qnetd, mock_call, mock_handle_results):
        mock_qdevice_crq_qnetd.return_value = "/etc/corosync/qnetd/nssdb/qdevice-net-node.crq"
        mock_call.return_value = ["10.10.10.123", (0, None, None)]

        self.qdevice_with_ip.sign_crq_on_qnetd()

        mock_qdevice_crq_qnetd.assert_called_once_with()
        mock_call.assert_called_once_with(["10.10.10.123"],
                                          "corosync-qnetd-certutil -s -c {} -n hacluster".format(mock_qdevice_crq_qnetd.return_value),
                                          False)
        mock_handle_results.assert_called_once_with(mock_copy.return_value)
    @mock.patch("crmsh.corosync.QDevice.handle_parallax_results")
    @mock.patch("crmsh.corosync.QDevice.qnetd_cluster_crt_on_qnetd", new_callable=mock.PropertyMock)
    @mock.patch("crmsh.utils.parallax_slurp")
    def test_fetch_cluster_crt_from_qnetd(self):
        pass
    '''


if __name__ == '__main__':
    unittest.main()
