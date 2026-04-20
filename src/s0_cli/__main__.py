"""Module entry point for ``python -m s0_cli`` and PyInstaller-frozen binary.

The frozen binary built by ``pyinstaller.spec`` uses this file as its
analysis root. Keeping it tiny (just delegate to the typer app) means we
don't have to teach PyInstaller about heavy dependencies that the import
graph would otherwise drag in unconditionally.
"""

from __future__ import annotations

from s0_cli.cli import app


def main() -> None:
    app()


if __name__ == "__main__":
    main()
