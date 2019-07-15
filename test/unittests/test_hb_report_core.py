import sys
import unittest
from hb_report import core

try:
    from unittest import mock
except ImportError:
    import mock

class TestCore(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Global setUp.
        """

    def setUp(self):
        """
        Test setUp.
        """
        self.context = core.ctx

    def tearDown(self):
        """
        Test tearDown.
        """

    @classmethod
    def tearDownClass(cls):
        """
        Global tearDown.
        """

    def test_is_collector_false(self):
        with mock.patch.object(sys, 'argv', ["hb_report", "test"]):
            self.assertFalse(core.is_collector())
    
    def test_is_collector_true(self):
        with mock.patch.object(sys, 'argv', ["hb_report", "__slave"]):
            self.assertTrue(core.is_collector())

    @mock.patch('hb_report.utils.me')
    def test_include_me_false(self, mock_me):
        mock_me.return_value = "node1.com"
        self.context.nodes = ["node2", "node3"]
        self.assertFalse(core.include_me(self.context))
        mock_me.assert_called_once_with()

    @mock.patch('hb_report.utils.me')
    def test_include_me_true(self, mock_me):
        mock_me.return_value = "node1"
        self.context.nodes = ["node1", "node2", "node3"]
        self.assertTrue(core.include_me(self.context))
        mock_me.assert_called_once_with()

    @mock.patch('hb_report.core.crmutils.list_cluster_nodes')
    @mock.patch('hb_report.core.utils.log_fatal')
    @mock.patch('hb_report.core.utils.log_warning')
    @mock.patch('hb_report.core.utils.log_debug')
    @mock.patch('hb_report.core.include_me')
    def test_get_nodes(self, mock_me, mock_debug, mock_warning,
                                      mock_fatal, mock_list_nodes):
        self.context.nodes = None
        mock_list_nodes.return_value = ["node1", "node2"]
        mock_me.return_value = True

        core.get_nodes(self.context)

        mock_list_nodes.assert_called_once_with()
        mock_fatal.assert_not_called()
        mock_me.assert_called_once_with(self.context)
        mock_warning.assert_not_called()
        mock_debug.assert_called_once_with('nodes: {}'.format(mock_list_nodes.return_value))

    @mock.patch('hb_report.core.crmutils.list_cluster_nodes')
    @mock.patch('hb_report.core.utils.log_fatal')
    @mock.patch('hb_report.core.utils.log_warning')
    @mock.patch('hb_report.core.utils.log_debug')
    @mock.patch('hb_report.core.include_me')
    def test_get_nodes_set_by_user(self, mock_me, mock_debug, mock_warning,
                                   mock_fatal, mock_list_nodes):
        self.context.nodes = ["node1", "node2", "node3"]

        core.get_nodes(self.context)

        mock_debug.assert_called_once_with('nodes: {}'.format(self.context.nodes))
        mock_list_nodes.assert_not_called()
        mock_fatal.assert_not_called()
        mock_me.assert_not_called()
        mock_warning.assert_not_called()
    
    @mock.patch('hb_report.core.crmutils.list_cluster_nodes')
    @mock.patch('hb_report.core.utils.log_fatal')
    @mock.patch('hb_report.core.utils.log_warning')
    @mock.patch('hb_report.core.utils.log_debug')
    @mock.patch('hb_report.core.include_me')
    def test_get_nodes_not_include_me(self, mock_me, mock_debug, mock_warning,
                                      mock_fatal, mock_list_nodes):
        self.context.nodes = None
        mock_list_nodes.return_value = ["node1", "node2"]
        mock_me.return_value = False

        core.get_nodes(self.context)

        mock_list_nodes.assert_called_once_with()
        mock_fatal.assert_not_called()
        mock_me.assert_called_once_with(self.context)
        mock_warning.assert_called_once_with("this is not a node and you didn't specify a list of nodes using -n")
        mock_debug.assert_called_once_with('nodes: {}'.format(mock_list_nodes.return_value))

    @mock.patch('hb_report.core.crmutils.list_cluster_nodes')
    @mock.patch('hb_report.core.utils.log_fatal')
    @mock.patch('hb_report.core.utils.log_warning')
    @mock.patch('hb_report.core.utils.log_debug')
    @mock.patch('hb_report.core.include_me')
    def test_get_nodes_fatal(self, mock_me, mock_debug, mock_warning,
                             mock_fatal, mock_list_nodes):
        self.context.nodes = None
        mock_list_nodes.return_value = []
        mock_fatal.side_effect = SystemExit

        with self.assertRaises(SystemExit):
            core.get_nodes(self.context)

        mock_list_nodes.assert_called_once_with()
        mock_fatal.assert_called_once_with("could not figure out a list of nodes; is this a cluster node?")
        mock_debug.assert_not_called()
        mock_me.assert_not_called()
        mock_warning.assert_not_called()

    '''
    @mock.patch('hb_report.utils.crmmsg.common_info')
    @mock.patch('hb_report.utils.me')
    def test_log_info(self, mock_me, mock_info):
        mock_me.return_value = "host1"
        utils.log_info("This is a test message")
        mock_me.assert_called_once_with()
        mock_info.assert_called_once_with("host1# This is a test message")

    @mock.patch('hb_report.utils.crmmsg.common_warn')
    @mock.patch('hb_report.utils.me')
    def test_log_warn(self, mock_me, mock_warn):
        mock_me.return_value = "host1"
        utils.log_warning("This is a test message")
        mock_me.assert_called_once_with()
        mock_warn.assert_called_once_with("host1# This is a test message")

    @mock.patch('hb_report.utils.crmmsg.common_err')
    @mock.patch('hb_report.utils.me')
    @mock.patch('sys.exit')
    def test_log_fatal(self, mock_exit, mock_me, mock_error):
        mock_me.return_value = "host1"
        utils.log_fatal("This is a test message")
        mock_me.assert_called_once_with()
        mock_error.assert_called_once_with("host1# This is a test message")
        mock_exit.assert_called_once_with(1)

    @mock.patch('os.path.dirname')
    def test_dirname1(self, mock_dirname):
        mock_dirname.return_value = ''
        result = utils.dirname('.')
        self.assertEqual(result, '.')
        mock_dirname.assert_called_once_with('.')

    @mock.patch('os.path.dirname')
    def test_dirname2(self, mock_dirname):
        mock_dirname.return_value = '/usr/local'
        result = utils.dirname('/usr/local/test.bin')
        self.assertEqual(result, '/usr/local')
        mock_dirname.assert_called_once_with('/usr/local/test.bin')
    '''
