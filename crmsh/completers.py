# Copyright (C) 2013 Kristoffer Gronlund <kgronlund@suse.com>
# See COPYING for license information.

# Helper completers

from prompt_toolkit.completion import Completion, Completer
from . import xmlutil
from . import utils
from . import help as help_module


def choice(lst):
    '''
    Static completion from a list
    '''
    def completer(args):
        return lst
    return completer


null = choice([])
attr_id = choice(["id="])

def call(fn, *fnargs):
    '''
    Call the given function with the given arguments.
    The function has to return a list of completions.
    '''
    def completer(args):
        return fn(*fnargs)
    return completer


def join(*fns):
    '''
    Combine the output of several completers
    into a single completer.
    '''
    def completer(args):
        ret = []
        for fn in fns:
            ret += list(fn(args))
        return ret
    return completer


booleans = choice(['yes', 'no', 'true', 'false', 'on', 'off'])


def resources(args):
    cib_el = xmlutil.resources_xml()
    if cib_el is None:
        return []
    nodes = xmlutil.get_interesting_nodes(cib_el, [])
    res = [x.get("id") for x in nodes if xmlutil.is_resource(x)]
    if args and args[0] in ['promote', 'demote']:
        return list(filter(xmlutil.RscState().is_ms, res))
    if args and args[0] == "started":
        return list(filter(xmlutil.RscState().is_running, res))
    if args and args[0] == "stopped":
        for item in filter(xmlutil.RscState().is_running, res):
            res.remove(item)
    return res


def resources_started(args):
    return resources(["started"])


def resources_stopped(args):
    return resources(["stopped"])


def primitives(args):
    cib_el = xmlutil.resources_xml()
    if cib_el is None:
        return []
    nodes = xmlutil.get_interesting_nodes(cib_el, [])
    return [x.get("id") for x in nodes if xmlutil.is_primitive(x)]


nodes = call(xmlutil.listnodes)

shadows = call(xmlutil.listshadows)

status_option = """full bynode inactive ops timing failcounts
                   verbose quiet xml simple tickets noheaders
                   detail brief""".split()


class CrmshCompleter(Completer):
    def __init__(self, context):
        self.context = context
        self._rl_line = None
        self.style = ""

    def get_required_params(self, line):
        if "primitive" in line and "params" in line:
            import re
            m = re.search(r'ocf:.*:.*', line)
            if m:
                agent=(m.group(0))
                from . import ui_configure
                ra = ui_configure.ra_agent_for_cpt(agent)
                d = ra.params()
                return [x for x in d if d[x]["required"] == '1']
        else:
            return []

    def get_child_short_help(self, item, line):
        child = self.context.current_level().get_child(item)
        if child:
            if child.short_help:
                return child.short_help
            else:
                h = help_module.help_contextual(self.context.level_name(), child.name, None)
                return h.short
        else:
            try:
                h = help_module.help_contextual(line.split()[0], item, None)
                return h.short
            except:
                return

    def get_completions(self, document, complete_event):
        word = document.get_word_before_cursor(WORD=True)
        line = document.current_line_before_cursor
        res = self.get_required_params(line)
        for item in self.context.complete(line):
            if item.startswith(word):
                if item.strip('=') in res:
                    self.style="fg:red"
                else:
                    self.style=""
                yield Completion(
                    item,
                    start_position=-len(word),
                    style=self.style,
                    display_meta=self.get_child_short_help(item, line))
