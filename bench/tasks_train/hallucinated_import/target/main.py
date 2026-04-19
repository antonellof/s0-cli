"""Entry point that imports a hallucinated 'safe-json' package.

`safe_json` does not exist on PyPI. A typosquatter could register it.
"""

import json

import safe_json  # noqa: F401  (does not exist; AI-hallucinated)
from utils import load_config


def main() -> None:
    cfg = load_config()
    print(json.dumps(cfg))


if __name__ == "__main__":
    main()
