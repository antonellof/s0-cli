"""Config loader that trusts whatever YAML you hand it."""

from pathlib import Path

import yaml


def load_config(path: str | Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.load(f.read())


def main() -> None:
    cfg = load_config("config.yaml")
    print(cfg)


if __name__ == "__main__":
    main()
