import astroid
from astroid import nodes
from typing import TYPE_CHECKING, Optional

from pylint.checkers import BaseChecker

if TYPE_CHECKING:
    from pylint.lint import PyLinter


class NoSshInStrChecker(BaseChecker):
    name = "no-ssh-in-str"
    msgs = {
            "W0001": (
                "ssh in str",
                "ssh-in-str",
                "Do not use ssh in str. Use an util function instead.",
            )
    }

    def __init__(self, linter: Optional["PyLinter"] = None) -> None:
            super().__init__(linter)

    def visit_const(self, node: nodes.Const) -> None:
        if isinstance(node.value, str) and 'ssh' in node.value:
            self.add_message("ssh-in-str", node=node)


def register(linter: "PyLinter") -> None:
    """This required method auto registers the checker during initialization.
    :param linter: The linter to register the checker to.
    """
    linter.register_checker(NoSshInStrChecker(linter))
