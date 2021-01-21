# Copyright (C) 2021 Xin Liang <XLiang@suse.com>
# See COPYING for license information.


import sys

from . import command
from . import utils
sys.path.append("/usr/share/crmsh")
from preflight_check import main


class Insight(command.UI):
    """
    """
    name = "insight"

    def __init__(self):
        command.UI.__init__(self)

    def do_preflight_check(self, context, *args):
        sys.argv[1:] = args
        main.ctx.process_name = context.command_name
        try:
            main.run(main.ctx)
        except utils.TerminateSubCommand:
            return False
        return True
