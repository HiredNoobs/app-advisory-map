import logging

from advisory_map.app import App
from advisory_map.config import Settings


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    App(Settings.from_env()).run()


if __name__ == "__main__":
    main()
