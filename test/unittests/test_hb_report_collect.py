import sys
import unittest
from hb_report import collect, utils
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

    @mock.patch('os.uname')
    @mock.patch('hb_report.utils.Package')
    def test_sys_info(self, mock_package, mock_uname):
        mock_instance = mock.Mock()
        mock_package.return_value = mock_instance

        collect.sys_info(self.context)

        mock_package.assert_called_once_with()
