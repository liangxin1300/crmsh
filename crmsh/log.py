# -*- coding: utf-8 -*-

import os
import sys
import logging
import logging.config
from contextlib import contextmanager

from . import config
from . import options


RED = '\033[31m'
YELLOW = '\033[33m'
GREEN = '\033[32m'
END = '\033[0m'


BOOTSTRAP_LOG_FILE = "/var/log/crmsh/ha-cluster-bootstrap.log"


class ConsoleRedirectHandler(logging.StreamHandler):
    """
    A custom handler for console

    Redirect ERROR message to sys.stderr
    Redirect INFO/WARNING/DEBUG message to sys.stdout
    """
    def emit(self, record):
        # level ERROR numeric value is 40
        if record.levelno < 40:
            stream = sys.stdout
        else:
            stream = sys.stderr
        msg = self.format(record)
        stream.write(msg)
        stream.write(self.terminator)


class ConsoleFormatter(logging.Formatter):
    """
    A custom formatter for console

    Wrap levelname with colors
    Wrap message with line number which is used for regression test
    """
    COLORS = {
        "WARNING": YELLOW,
        "INFO": GREEN,
        "ERROR": RED,
        "OK": GREEN
    }
    FORMAT = "%(levelname)s: %(message)s"

    def __init__(self, lineno=-1):
        self.lineno = lineno
        super().__init__(fmt=self.FORMAT)

    def format(self, record):
        levelname = record.levelname
        # wrap with colors
        if levelname in self.COLORS and not options.regression_tests:
            record.levelname = self.COLORS[levelname] + levelname + END
        # wrap with line number
        if self.lineno > 0:
            msg = record.msg
            record.msg = "{}: {}".format(self.lineno, msg)
            record.levelname = levelname
        return super().format(record)


class FileFormatter(logging.Formatter):
    """
    A custom formatter for file
    """
    FORMAT = "%(asctime)s %(levelname)s: %(message)s"
    DATEFMT = "%b %d %H:%M:%S"

    def __init__(self):
        super().__init__(fmt=self.FORMAT, datefmt=self.DATEFMT)

    def format(self, record):
        # join multi line record into one line
        record.msg = "\\n".join(record.msg.split('\n'))
        return super().format(record)


class DebugFilter(logging.Filter):
    """
    A custom filter for debug message
    """
    def filter(self, record):
        if record.levelname == "DEBUG":
            return config.core.debug
        else:
            return True


LOGGING_CFG = {
    "version": 1,
    "disable_existing_loggers": "False",
    "formatters": {
        "console": {
            "()": ConsoleFormatter
        },
        "file": {
            "()": FileFormatter
        }
    },
    "filters": {
        "console": {
            "()": DebugFilter
        }
    },
    "handlers": {
        'null': {
            'class': 'logging.NullHandler'
        },
        "console": {
            "()": ConsoleRedirectHandler,
            "formatter": "console",
            "filters": ["console"]
        },
        "buffer": {
            "class": "logging.handlers.MemoryHandler",
            "capacity": 1024*100,
            "flushLevel": logging.CRITICAL,
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": BOOTSTRAP_LOG_FILE,
            "formatter": "file"
        }
    },
    "loggers": {
        # The common logger used in most of modules
        # Need log in console in general("console" handler)
        # In some scenarios need log in memory("buffer" handler), periodically flushing them to a target handler
        "crmsh": {
            "handlers": ["null", "console", "buffer"],
            "level": "DEBUG"
        },
        # The logger used in bootstrap
        # Need log both in log file and console
        "bootstrap": {
            "handlers": ["null", "file", "console"],
            "level": "DEBUG"
        }
    }
}


class LoggerConfig(object):
    """
    A class to keep/update some attributes related with logger
    Also has methods related with handler and formatter

    lineno here means the line number of input statements in regression test
    """
    def __init__(self, logger):
        """
        Init function
        """
        self.logger = logger
        if self.logger.name == "crmsh":
            _, self.console_handler, self.buffer_handler = logger.handlers
        if self.logger.name == "bootstrap":
            _, self.file_handler, self.console_handler = logger.handlers
        # used in regression test
        self.lineno = -1
        self.__save_lineno = -1

    def set_ok_level(self):
        """
        Create a custom level name OK for compatibility
        """
        logging.OK = 5
        logging.addLevelName(logging.OK, 'OK')
        self.logger.ok = lambda msg, *args: self.logger._log(logging.OK, msg, args)

    def set_console_formatter(self, lineno):
        """
        Pass line number to ConsoleFormatter
        """
        self.console_handler.setFormatter(ConsoleFormatter(lineno=lineno))

    def reset_lineno(self, to=0):
        """
        Reset line number
        """
        self.lineno = to
        self.set_console_formatter(to)

    def incr_lineno(self):
        """
        Increase line number
        """
        if self.lineno >= 0:
            self.lineno += 1
        self.set_console_formatter(self.lineno)

    @contextmanager
    def only_log_to_file(self):
        """
        Only log to file in bootstrap logger
        """
        try:
            self.logger.removeHandler(self.console_handler)
            yield
        finally:
            self.logger.addHandler(self.console_handler)

    @contextmanager
    def buffer(self):
        """
        Keep log messages in memory and finally show them in console
        """
        try:
            # remove console handler temporarily
            self.logger.removeHandler(self.console_handler)
            # set the target of buffer handler as console
            self.buffer_handler.setTarget(self.console_handler)
            yield
        finally:
            # close the buffer handler(flush to console handler)
            self.buffer_handler.close()
            # add console handler back
            self.logger.addHandler(self.console_handler)
            if not options.batch:
                try:
                    input("Press enter to continue... ")
                except EOFError:
                    pass

    @contextmanager
    def line_number(self):
        """
        Mark the line number in the log record
        """
        try:
            self.__save_lineno = self.lineno
            self.reset_lineno()
            yield
        finally:
            self.reset_lineno(self.__save_lineno)


# Below is a set of wrapped log message for specific scenarios
def no_prog_err(name):
    logger.error("%s not available, check your installation", name)


def unsupported_err(name):
    logger.error("%s is not supported", name)


def missing_obj_err(node):
    logger.error("object {}:{} missing (shouldn't have happened)".format(node.tag, node.get("id")))


def constraint_norefobj_err(constraint_id, obj_id):
    logger.error("constraint {} references a resource {} which doesn't exist".format(constraint_id, obj_id))


def no_object_err(name):
    logger.error("object {} does not exist".format(name))


def invalid_id_err(obj_id):
    logger.error("{}: invalid object id".format(obj_id))


def id_used_err(node_id):
    logger.error("{}: id is already in use".format(node_id))


def syntax_err(s, token='', context='', msg=''):
    err = "syntax"
    if context:
        err += " in {}".format(context)
    if msg:
        err += ": {}".format(msg)
    if isinstance(s, str):
        err += " parsing '{}'".format(s)
    elif token:
        err += " near <{}> parsing '{}'".format(token, ' '.join(s))
    else:
        err += " parsing '{}'".format(' '.join(s))
    logger.error(err)


def bad_usage(cmd, args, msg=None):
    if not msg:
        logger.error("Bad usage: '{} {}'".format(cmd, args))
    else:
        logger.error("Bad usage: {}, command: '{} {}'".format(msg, cmd, args))


def empty_cib_err():
    logger.error("No CIB!")


def cib_parse_err(msg, s):
    logger.error(msg)
    logger.info("offending string: {}".format(s))


def cib_ver_unsupported_err(validator, rel):
    logger.error("Unsupported CIB: validator '{}', release '{}'".format(validator, rel))
    logger.error("To upgrade an old (<1.0) schema, use the upgrade command.")


def update_err(obj_id, cibadm_opt, xml, rc):
    task_table = {"-U": "update", "-D": "delete", "-P": "patch"}
    task = task_table.get(cibadmin_opt, "replace")
    logger.error("could not {} {} (rc={})".format(task, obj_id, rc))
    if rc == 54:
        logger.info("Permission denied.")
    elif task == "patch":
        logger.info("offending xml diff: {}".format(xml))
    else:
        logger.info("offending xml: {}".format(xml))
# Above is a set of wrapped log message for specific scenarios


def setup_directory_for_logfile(logfile):
    """
    Create log file's parent directory
    """
    _dir = os.path.dirname(logfile)
    os.makedirs(_dir, exist_ok=True)


setup_directory_for_logfile(BOOTSTRAP_LOG_FILE)
logging.config.dictConfig(LOGGING_CFG)

logger = logging.getLogger("crmsh")
logger_config = LoggerConfig(logger)
logger_config.set_ok_level()

logger_bootstrap = logging.getLogger("bootstrap")
logger_config_bootstrap = LoggerConfig(logger_bootstrap)
