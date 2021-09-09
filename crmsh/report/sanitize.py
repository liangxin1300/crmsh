import os
import re
from crmsh import log, config
from crmsh.report import const, utils, core


logger = log.setup_report_logger(__name__)


def load_sanitize_rule():
    """
    Load config.report.sanitize_rule
    Return a list
    """
    if config.report.sanitize_rule:
        temp_pattern_set = set()
        temp_pattern_set |= set(re.split('\s*\|\s*|\s+', config.report.sanitize_rule.strip('|')))
        return list(temp_pattern_set)
    return []


def parse_sanitize_rule(rule_list):
    """
    Parse sanitize rule set which from config.report.sanitize_rule
    """
    if rule_list:
        core.context.do_sanitize = True
    else:
        rule_list = [const.SENSITIVE_DEFAULT]

    for rule in rule_list:
        if ':' in rule:
            key, value = rule.split(':')
            if value != "raw":
                raise utils.CRMReportError("For sanitize_pattern {}, option should be \"raw\"".format(key))
            core.context.sanitize_rule_dict[key] = value
        else:
            core.context.sanitize_rule_dict[rule] = None
    logger.debug2("core.context.sanitize_rule_dict: %s", core.context.sanitize_rule_dict)


def extract_sensitive_value_list(rule):
    """
    Extract sensitive value from cib.xml
    """
    cib_file = utils.work_path(const.CIB_F)
    if not os.path.exists(cib_file):
        logger.warning("File %s was not collected", const.CIB_F)
        return []
    data = utils.read_from_file(cib_file)
    if not data:
        logger.warning("File %s is empty", cib_file)
        return []

    value_list = re.findall(r'name="({})" value="(.*?)"'.format(rule.strip('?')+'?'), data)
    return [value[1] for value in value_list]


def get_sensitive_key_value_list():
    """
    For each defined sanitize rule, get the sensitive value or key list
    """
    for key, value in core.context.sanitize_rule_dict.items():
        if value == "raw":
            core.context.sanitize_value_raw_list += extract_sensitive_value_list(key)
        else:
            core.context.sanitize_value_cib_list += extract_sensitive_value_list(key)
            core.context.sanitize_key_cib_list.append(key.strip('.*?')+'.*?')


def include_sensitive_data():
    """
    Check whether contain sensitive data
    """
    if core.context.sanitize_value_raw_list or core.context.sanitize_value_cib_list:
        return True
    return False


def sub_sensitive_string(data):
    """
    Do the replace job

    For the raw sanitize_pattern option, replace exactly the value
    For the key:value nvpair sanitize_pattern, replace the value in which line contain the key
    """
    result = data
    if core.context.sanitize_value_raw_list:
        sub_re = r'\b({})\b'.format('|'.join(core.context.sanitize_value_raw_list))
        result = re.sub(sub_re, const.SANITIZE_STR, data)
    if core.context.sanitize_value_cib_list:
        sub_re = '({})({})'.format('|'.join(core.context.sanitize_key_cib_list), '|'.join(core.context.sanitize_value_cib_list))
        result = re.sub(sub_re, '\\1{}'.format(const.SANITIZE_STR), result)
    return result


def sanitize():
    """
    Replace sensitive info with '******' in all report result files
    """
    logger.debug("Check or replace sensitive info from CIB, PE and log files")

    get_sensitive_key_value_list()
    if include_sensitive_data() and not core.context.do_sanitize:
        logger.warning("Some PE/CIB/log files contain possibly sensitive data")
        logger.warning("Using \"-s\" option can replace sensitive data")
        return

    file_list = []
    for (dirpath, dirnames, filenames) in os.walk(core.context.work_dir):
        for _file in filenames:
            file_list.append(os.path.join(dirpath, _file))

    for f in [item for item in file_list if os.path.isfile(item)]:
        data = utils.read_from_file(f)
        if not data:
            continue
        utils.write_to_file(f, sub_sensitive_string(data))
