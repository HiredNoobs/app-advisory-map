import logging
import os

from advisory_map.app import App
from advisory_map.config import Settings

# When, level, where in the code, what.
LOG_FORMAT = "%(asctime)s %(levelname)s [%(filename)s:%(funcName)s():L%(lineno)d] %(message)s"


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper(), format=LOG_FORMAT)
    App(Settings.from_env()).run()


if __name__ == "__main__":
    main()
