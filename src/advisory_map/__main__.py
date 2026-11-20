import logging
import os
import sys
from collections.abc import Sequence

from advisory_map import cli
from advisory_map.app import App
from advisory_map.config import Settings

# When, level, where in the code, what.
LOG_FORMAT = "%(asctime)s %(levelname)s [%(filename)s:%(funcName)s():L%(lineno)d] %(message)s"


def main(argv: Sequence[str] | None = None) -> None:
    """The app, or with `vex` its verdicts' CLI."""
    args = sys.argv[1:] if argv is None else argv
    if args[:1] == ["vex"]:
        sys.exit(cli.main(args[1:]))
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(), format=LOG_FORMAT)
    App(Settings.from_env()).run()


if __name__ == "__main__":
    main()
