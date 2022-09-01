import argparse
from typing import Tuple, Type

from knot_resolver_manager.cli.command import Command, CommandArgs, register_command
from knot_resolver_manager.utils.requests import request


@register_command
class StopCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__(namespace)

    def run(self, args: CommandArgs) -> None:
        url = f"{args.socket}/stop"
        response = request("POST", url)
        print(response)

    @staticmethod
    def register_args_subparser(
        parser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        stop = parser.add_parser("stop", help="shutdown everything")
        return stop, StopCommand
