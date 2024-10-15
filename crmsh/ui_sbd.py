import logging
import typing
import re
import os

from crmsh import sbd
from crmsh import watchdog
from crmsh import command
from crmsh import utils
from crmsh import bootstrap
from crmsh import completers
from crmsh import sh
from crmsh import xmlutil
from crmsh import constants
from crmsh.service_manager import ServiceManager


logger = logging.getLogger(__name__)


def sbd_device_completer(completed_list: typing.List[str]) -> typing.List[str]:
    '''
    Completion for sbd device command
    '''
    if not sbd.SBDUtils.is_using_disk_based_sbd():
        return []
    if len(completed_list) == 2:
        return ["add", "remove"]
    if len(completed_list) > 2 and completed_list[1] != "remove":
        return []

    # completer for sbd device remove
    dev_list = sbd.SBDUtils.get_sbd_device_from_config()
    not_complete_list = [dev for dev in dev_list if dev not in completed_list[2:]]
    # not allow to remove the last device
    if len(not_complete_list) == 1:
        return []
    return not_complete_list


def sbd_configure_completer(completed_list: typing.List[str]) -> typing.List[str]:
    '''
    completion for sbd configure command
    '''
    service_manager = ServiceManager()
    if not service_manager.service_is_active(constants.PCMK_SERVICE):
        return []

    is_diskbased = sbd.SBDUtils.is_using_disk_based_sbd()
    parameters_pool = []
    if completed_list[1] == '':
        parameters_pool = ["show"]
    elif completed_list[1] == "show":
        if len(completed_list) == 3:
            show_types = SBD.SHOW_TYPES if is_diskbased else SBD.DISKLESS_SHOW_TYPES
            return [t for t in show_types if t not in completed_list]
        else:
            return []

    is_diskless = sbd.SBDUtils.is_using_diskless_sbd()
    if is_diskbased:
        timeout_types = SBD.TIMEOUT_TYPES
    elif is_diskless:
        timeout_types = SBD.DISKLESS_TIMEOUT_TYPES
    else:
        return parameters_pool
    parameters_pool.extend([f"{t}-timeout=" for t in timeout_types])
    parameters_pool.append("watchdog-device=")
    parameters_pool = [
        p
        for p in parameters_pool
        if not any(c.startswith(p) for c in completed_list)
    ]

    return parameters_pool


class SBD(command.UI):
    '''
    Class for sbd sub-level

    Includes commands:
    - sbd configure
    - sbd remove
    - sbd status
    '''
    name = "sbd"
    TIMEOUT_TYPES = ("watchdog", "allocate", "loop", "msgwait")
    DISKLESS_TIMEOUT_TYPES = ("watchdog",)
    SHOW_TYPES = ("disk_metadata", "sysconfig", "property")
    DISKLESS_SHOW_TYPES = ("sysconfig", "property")
    RESTART_INFO = "Requires to restart cluster service to take effect"
    PCMK_ATTRS = (
        "have-watchdog",
        "stonith-timeout",
        "stonith-watchdog-timeout",
        "stonith-enabled",
        "priority-fencing-delay",
        "pcmk_delay_max"
    )
    PARSE_RE = re.compile(
		# Match keys with non-empty values, capturing possible suffix
        r'(\w+)(?:-(\w+))?=("[^"]+"|[\w/\d;]+)'
    )

    class SyntaxError(Exception):
        pass

    def __init__(self):
        self.device_list_from_config: list[str] = None
        self.device_meta_dict_runtime: dict[str, int] = None
        self.watchdog_timeout_from_config: int = None
        self.watchdog_device_from_config: str = None
        self.service_manager: ServiceManager = None
        self.cluster_shell: sh.cluster_shell = None
        self.cluster_nodes: list[str] = None
        self.crm_mon_xml_parser: xmlutil.CrmMonXmlParser = None

        command.UI.__init__(self)

    def _load_attributes(self):
        self.device_list_from_config = sbd.SBDUtils.get_sbd_device_from_config()
        self.device_meta_dict_runtime = {}
        if self.device_list_from_config:
            self.device_meta_dict_runtime = sbd.SBDUtils.get_sbd_device_metadata(self.device_list_from_config[0], timeout_only=True)
        try:
            self.watchdog_timeout_from_config = sbd.SBDTimeout.get_sbd_watchdog_timeout()
        except Exception:
            self.watchdog_timeout_from_config = None
        self.watchdog_device_from_config = watchdog.Watchdog.get_watchdog_device_from_sbd_config()

        self.service_manager = ServiceManager()
        self.cluster_shell = sh.cluster_shell()
        self.cluster_nodes = utils.list_cluster_nodes() or [utils.this_node()]
        self.crm_mon_xml_parser = xmlutil.CrmMonXmlParser()

    def requires(self) -> bool:
        '''
        Requirements check when entering sbd sub-level
        '''
        if not utils.package_is_installed("sbd"):
            logger.error('%s', sbd.SBDManager.SBD_NOT_INSTALLED_MSG)
            return False
        return True

    @property
    def configure_usage(self) -> str:
        '''
        Build usage string for sbd configure command,
        including disk-based and diskless sbd cases
        '''
        if sbd.SBDUtils.is_using_disk_based_sbd():
            timeout_types, show_types = self.TIMEOUT_TYPES, self.SHOW_TYPES
        elif sbd.SBDUtils.is_using_diskless_sbd():
            timeout_types, show_types = self.DISKLESS_TIMEOUT_TYPES, self.DISKLESS_SHOW_TYPES
        else:
            timeout_types, show_types = (), self.DISKLESS_SHOW_TYPES

        timeout_usage_str = " ".join([f"[{t}-timeout=<integer>]" for t in timeout_types])
        show_usage = f"crm sbd configure show [{'|'.join(show_types)}]"
        if timeout_usage_str:
            return f"Usage:\n{show_usage}\ncrm sbd configure {timeout_usage_str} [watchdog-device=<device>]\n"
        else:
            return f"Usage:\n{show_usage}\n"

    @staticmethod
    def _show_sysconfig() -> None:
        '''
        Show pure content of /etc/sysconfig/sbd
        '''
        with open(sbd.SBDManager.SYSCONFIG_SBD) as f:
            content_list = [line.strip() for line in f.readlines()
                            if not line.startswith("#")
                            and line.strip()]
        if content_list:
            logger.info("crm sbd configure show sysconfig")
        for line in content_list:
            print(line)

    def _show_disk_metadata(self) -> None:
        '''
        Show sbd disk metadata for each configured device
        '''
        if self.device_list_from_config:
            logger.info("crm sbd configure show disk_metadata")
        for dev in self.device_list_from_config:
            print(self.cluster_shell.get_stdout_or_raise_error(f"sbd -d {dev} dump"))
            print()

    def _show_property(self) -> None:
        '''
        Show sbd-related properties from cluster and systemd
        '''
        out = self.cluster_shell.get_stdout_or_raise_error("crm configure show")

        logger.info("crm sbd configure show property")
        regex = f"({'|'.join(self.PCMK_ATTRS)})=(\\S+)"
        matches = re.findall(regex, out)
        for match in matches:
            print(f"{match[0]}={match[1]}")

        print()
        logger.info('%s', constants.SHOW_SBD_START_TIMEOUT_CMD)
        systemd_start_timeout = sbd.SBDTimeout.get_sbd_systemd_start_timeout()
        print(f"TimeoutStartUSec={systemd_start_timeout}")

    def _configure_show(self, args) -> None:
        if len(args) > 2:
            raise self.SyntaxError("Invalid argument")
        elif len(args) == 2:
            match args[1]:
                case "disk_metadata":
                    self._show_disk_metadata()
                case "sysconfig":
                    SBD._show_sysconfig()
                case "property":
                    self._show_property()
                case _:
                    raise self.SyntaxError(f"Unknown argument: {args[1]}")
        else:
            self._show_disk_metadata()
            if self.device_list_from_config:
                print()
            SBD._show_sysconfig()
            print()
            self._show_property()

    def _parse_args(self, args: tuple[str, ...]) -> dict[str, int|str]:
        '''
        Parse arguments and verify them
        '''
        parameter_dict = {}

        for arg in args:
            match = self.PARSE_RE.match(arg)
            if not match:
                raise self.SyntaxError(f"Invalid argument: {arg}")
            key, suffix, value = match.groups()
            # timeout related parameters
            if key in self.TIMEOUT_TYPES and suffix and suffix == "timeout":
                if not value.isdigit():
                    raise self.SyntaxError(f"Invalid timeout value: {value}")
                parameter_dict[key] = int(value)
            # watchdog device parameter
            elif key == "watchdog" and suffix == "device":
                parameter_dict["watchdog-device"] = value
            else:
                raise self.SyntaxError(f"Unknown argument: {arg}")

        watchdog_device = parameter_dict.get("watchdog-device")
        parameter_dict["watchdog-device"] = watchdog.Watchdog.get_watchdog_device(watchdog_device)

        logger.debug("Parsed arguments: %s", parameter_dict)
        return parameter_dict

    @staticmethod
    def _adjust_timeout_dict(timeout_dict: dict, diskless: bool = False) -> dict:
        watchdog_timeout = timeout_dict.get("watchdog")
        if not watchdog_timeout:
            watchdog_timeout, _ = sbd.SBDTimeout.get_advised_sbd_timeout(diskless)
            logger.info("No watchdog timeout specified, use advised value: %s", watchdog_timeout)
            timeout_dict["watchdog"] = watchdog_timeout

        if diskless:
            return timeout_dict

        msgwait_timeout = timeout_dict.get("msgwait")
        if not msgwait_timeout:
            msgwait_timeout = 2*watchdog_timeout
            logger.info("No msgwait timeout specified, use 2*watchdog timeout: %s", msgwait_timeout)
            timeout_dict["msgwait"] = msgwait_timeout

        if msgwait_timeout < 2*watchdog_timeout:
            logger.warning("It's recommended to set msgwait timeout >= 2*watchdog timeout")

        return timeout_dict

    def _configure_diskbase(self, parameter_dict: dict):
        '''
        Configure disk-based SBD based on input parameters and runtime config
        '''
        update_dict = {}
        watchdog_device = parameter_dict.get("watchdog-device")
        if watchdog_device != self.watchdog_device_from_config:
            update_dict["SBD_WATCHDOG_DEV"] = watchdog_device
        timeout_dict = {k: v for k, v in parameter_dict.items() if k in self.TIMEOUT_TYPES}
        # merge runtime timeout dict with new timeout dict
        timeout_dict = self.device_meta_dict_runtime | timeout_dict
        # adjust watchdog and msgwait timeout
        timeout_dict = self._adjust_timeout_dict(timeout_dict)
        watchdog_timeout = timeout_dict.get("watchdog")
        if watchdog_timeout != self.watchdog_timeout_from_config:
            update_dict["SBD_WATCHDOG_TIMEOUT"] = str(watchdog_timeout)

        sbd_manager = sbd.SBDManager(
            device_list_to_init=self.device_list_from_config,
            timeout_dict=timeout_dict,
            update_dict=update_dict
        )
        sbd_manager.init_and_deploy_sbd()
        
    def _configure_diskless(self, parameter_dict: dict):
        '''
        Configure diskless SBD based on input parameters and runtime config
        '''
        update_dict = {}
        parameter_dict = self._adjust_timeout_dict(parameter_dict, diskless=True)
        watchdog_timeout = parameter_dict.get("watchdog")
        if watchdog_timeout and watchdog_timeout != self.watchdog_timeout_from_config:
            update_dict["SBD_WATCHDOG_TIMEOUT"] = str(watchdog_timeout)
        watchdog_device = parameter_dict.get("watchdog-device")
        if watchdog_device != self.watchdog_device_from_config:
            update_dict["SBD_WATCHDOG_DEV"] = watchdog_device

        sbd_manager = sbd.SBDManager(
            update_dict=update_dict,
            diskless_sbd=True
        )
        sbd_manager.init_and_deploy_sbd()

    def _device_add(self, devices_to_add: typing.List[str]):
        '''
        Implement sbd device add command, add devices to sbd configuration
        '''
        all_device_list = self.device_list_from_config + devices_to_add
        sbd.SBDUtils.verify_sbd_device(all_device_list)

        logger.info("Append devices: %s", ';'.join(devices_to_add))
        update_dict = {"SBD_DEVICE": ";".join(all_device_list)}
        sbd_manager = sbd.SBDManager(
            device_list_to_init=devices_to_add,
            update_dict=update_dict,
            timeout_dict=self.device_meta_dict_runtime
        )
        sbd_manager.init_and_deploy_sbd()

    def _device_remove(self, devices_to_remove: typing.List[str]):
        '''
        Implement sbd device remove command, remove devices from sbd configuration
        '''
        for dev in devices_to_remove:
            if dev not in self.device_list_from_config:
                raise self.SyntaxError(f"Device {dev} is not in config")
        # To keep the order of devices during removal
        left_device_list = [dev for dev in self.device_list_from_config if dev not in devices_to_remove]
        if len(left_device_list) == 0:
            raise self.SyntaxError(f"Not allowed to remove all devices")

        logger.info("Remove devices: %s", ';'.join(devices_to_remove))
        update_dict = {"SBD_DEVICE": ";".join(left_device_list)}
        sbd.SBDManager.update_sbd_configuration(update_dict)
        logger.info('%s', self.RESTART_INFO)

    @command.completers_repeating(sbd_device_completer)
    def do_device(self, context, *args) -> bool:
        '''
        Implement sbd device command
        '''
        if not ServiceManager().service_is_active(constants.PCMK_SERVICE):
            logger.error("%s is not active", constants.PCMK_SERVICE)
            return False
        if not sbd.SBDUtils.is_using_disk_based_sbd():
            logger.error("Only works for disk-based SBD")
            logger.info("Please use 'crm cluster init sbd' to configure disk-based SBD first")
            return False

        try:
            if not args:
                raise self.SyntaxError("No argument")
            if args[0] not in ("add", "remove"):
                raise self.SyntaxError(f"Invalid argument: {args[0]}")
            if len(args) < 2:
                raise self.SyntaxError("No device specified")

            self._load_attributes()
            logger.info("Configured sbd devices: %s", ';'.join(self.device_list_from_config))
            if len(args) == 2 and ";" in args[1]:
                device_list_from_args = args[1].split(";")
            else:
                device_list_from_args = list(args[1:])
            match args[0]:
                case "add":
                    self._device_add(device_list_from_args)
                case "remove":
                    self._device_remove(device_list_from_args)
            return True

        except self.SyntaxError as e:
            logger.error('%s', e)
            logger.info("Usage: crm sbd device <add|remove> <device>...")
            return False

    @command.completers_repeating(sbd_configure_completer)
    def do_configure(self, context, *args) -> bool:
        '''
        Implement sbd configure command
        '''
        self._load_attributes()

        try:
            if not args:
                raise self.SyntaxError("No argument")

            if args[0] == "show":
                self._configure_show(args)
                return True

            if not self.service_manager.service_is_active(constants.PCMK_SERVICE):
                logger.error("%s is not active", constants.PCMK_SERVICE)
                return False

            parameter_dict = self._parse_args(args)
            if sbd.SBDUtils.is_using_disk_based_sbd():
                self._configure_diskbase(parameter_dict)
            elif sbd.SBDUtils.is_using_diskless_sbd():
                self._configure_diskless(parameter_dict)
            return True

        except self.SyntaxError as e:
            logger.error('%s', e)
            print(self.configure_usage)
            return False

    def do_disable(self, context) -> bool:
        '''
        Implement sbd disable command
        '''
        if not ServiceManager().service_is_active(constants.SBD_SERVICE):
            logger.error("%s is not active", constants.SBD_SERVICE)
            return False
        sbd.disable_sbd_from_cluster()
        logger.info('%s', self.RESTART_INFO)
        return True

    def _print_sbd_type(self):
        if not self.service_manager.service_is_active(constants.SBD_SERVICE):
            return
        print(f"# Type of SBD:")
        if self.device_list_from_config:
            print("Disk-based SBD configured")
        else:
            print("Diskless SBD configured")
        print()

    def _print_sbd_status(self):
        padding = 2
        status_len = 8
        max_node_len = max(len(node) for node in self.cluster_nodes) + padding

        print(f"# Status of {constants.SBD_SERVICE}:")
        print(f"{'Node':<{max_node_len}}|{'Active':<{status_len}}|{'Enabled':<{status_len}}|Since")
        for node in self.cluster_nodes:
            is_active = self.service_manager.service_is_active(constants.SBD_SERVICE, node)
            is_active_str = "YES" if is_active else "NO"
            is_enabled = self.service_manager.service_is_enabled(constants.SBD_SERVICE, node)
            is_enabled_str = "YES" if is_enabled else "NO"
            systemd_property = "ActiveEnterTimestamp" if is_active else "ActiveExitTimestamp"
            since_str_prefix = "active since" if is_active else "disactive since"
            systemctl_show_cmd = f"systemctl show {constants.SBD_SERVICE} --property={systemd_property} --value"
            since = self.cluster_shell.get_stdout_or_raise_error(systemctl_show_cmd, node) or "N/A"
            print(f"{node:<{max_node_len}}|{is_active_str:<{status_len}}|{is_enabled_str:<{status_len}}|{since_str_prefix}: {since}")
        print()

    def _print_watchdog_info(self):
        padding = 2
        max_node_len = max(len(node) for node in self.cluster_nodes) + padding

        watchdog_sbd_re = "\[[0-9]+\] (/dev/.*)\nIdentity: Busy: .*sbd.*\nDriver: (.*)"
        device_list, driver_list, kernel_timeout_list = [], [], []
        cluster_nodes = self.cluster_nodes[:]
        for node in cluster_nodes[:]:
            out = self.cluster_shell.get_stdout_or_raise_error("sbd query-watchdog", node)
            res = re.search(watchdog_sbd_re, out)
            if res:
                device, driver = res.groups()
                kernel_timeout = self.cluster_shell.get_stdout_or_raise_error("cat /proc/sys/kernel/watchdog_thresh", node)
                device_list.append(device)
                driver_list.append(driver)
                kernel_timeout_list.append(kernel_timeout)
            else:
                logger.error("Failed to get watchdog info from %s", node)
                cluster_nodes.remove(node)
        if not cluster_nodes:
            return

        print("# Watchdog info:")
        max_dev_len = max(len(dev) for dev in device_list) + padding
        max_driver_len = max(len(driver) for driver in driver_list) + padding
        print(f"{'Node':<{max_node_len}}|{'Device':<{max_dev_len}}|{'Driver':<{max_driver_len}}|Kernel Timeout")
        for i, node in enumerate(cluster_nodes):
            print(f"{node:<{max_node_len}}|{device_list[i]:<{max_dev_len}}|{driver_list[i]:<{max_driver_len}}|{kernel_timeout_list[i]}")
        print()

    def _print_sbd_agent_status(self):
        if self.crm_mon_xml_parser.is_resource_configured(sbd.SBDManager.SBD_RA):
            print("# Status of fence_sbd:")
            sbd_id_list = self.crm_mon_xml_parser.get_resource_id_list_via_type(sbd.SBDManager.SBD_RA)
            for sbd_id in sbd_id_list:
                rc, out, err = self.cluster_shell.get_rc_stdout_stderr_without_input(None, f"crm resource status {sbd_id}")
                if out:
                    print(out)
                if err:
                    print(err)

    def do_status(self, context) -> bool:
        '''
        Implement sbd status command
        '''
        self._load_attributes()
        self._print_sbd_type()
        self._print_sbd_status()
        self._print_watchdog_info()
        self._print_sbd_agent_status()
        return True
