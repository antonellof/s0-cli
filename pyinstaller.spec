# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for a single-binary build of `s0`.

Run locally:
    uv run pyinstaller pyinstaller.spec --clean --noconfirm

The CI matrix in `.github/workflows/release-binaries.yml` runs the same
command on macOS arm64 / x86_64, Linux x86_64 / arm64, and Windows
x86_64, then renames `dist/s0` -> `s0-<platform>-<arch>` and attaches
the file to the GitHub release.

Why this is non-trivial:

  - `litellm` discovers provider plugins dynamically (one importlib call
    per provider), so PyInstaller's static graph misses everything.
    `collect_all` brings the whole package + data files in.
  - `tiktoken` ships BPE encoding tables outside the import graph —
    must be picked up as data files.
  - `tiktoken_ext` is a namespace package some `tiktoken` versions use
    for pluggable encoding registration; collect its submodules too.
  - `s0_cli.harnesses.<name>` are loaded via `importlib.import_module`
    in `eval/runner.py:load_harness_by_name`. Static analysis only sees
    `s0_cli`; we must `collect_submodules` so every shipped harness
    file is bundled.
  - `s0_cli.prompts/*.txt` are read at runtime via `Path(__file__).parent
    / name` — they're *data*, not modules, so they need `collect_data_files`.

The result is a single executable around 80–120 MB depending on platform.
That's heavy because `litellm` pulls in 100+ provider modules; we keep
all of them so the user can switch `S0_MODEL` between Anthropic / OpenAI
/ Gemini / OpenRouter / Ollama / etc. without re-downloading anything.
"""

from PyInstaller.utils.hooks import (
    collect_all,
    collect_data_files,
    collect_submodules,
)

# Heavy dependencies with dynamic plugin systems.
litellm_data, litellm_binaries, litellm_hidden = collect_all("litellm")
tiktoken_data, tiktoken_binaries, tiktoken_hidden = collect_all("tiktoken")
tiktoken_ext_hidden = collect_submodules("tiktoken_ext")

# Our package: every harness in `s0_cli/harnesses/` is loaded by
# `importlib.import_module` at runtime. Without explicit collection,
# PyInstaller would only ship `s0_cli/__init__.py`.
s0_hidden = collect_submodules("s0_cli")

# Prompt templates live as `.txt` siblings of the Python modules and
# are read with `Path(__file__).parent / name`. PyInstaller needs to
# be told they're data, not code.
s0_data = collect_data_files("s0_cli", includes=["**/*.txt"])

# Some providers `litellm` may import lazily on first use. Listed
# explicitly so the user gets a useful error from the provider itself
# rather than `ModuleNotFoundError: litellm.llms.X`.
extra_hidden = [
    "litellm.llms",
    "litellm.proxy",
    "litellm.integrations",
    "litellm.types",
    # uvloop is optional but litellm probes for it on import
    "uvloop",
]

block_cipher = None

a = Analysis(
    ["src/s0_cli/__main__.py"],
    pathex=["src"],
    binaries=litellm_binaries + tiktoken_binaries,
    datas=litellm_data + tiktoken_data + s0_data,
    hiddenimports=(
        litellm_hidden
        + tiktoken_hidden
        + tiktoken_ext_hidden
        + s0_hidden
        + extra_hidden
    ),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Build/dev tooling we never want in the binary.
        "pyinstaller",
        "pytest",
        "ruff",
        # Tk is dragged in by something occasionally; nothing in s0 needs it.
        "tkinter",
        # We don't ship the MCP server in the standalone binary; users
        # who want MCP run `pip install s0-cli[mcp]` and use the
        # `s0-mcp` console script. Keeping it out shaves ~10 MB.
        "mcp",
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# `--onedir` (a folder of files) instead of `--onefile`.
#
# Why: in onefile mode, every invocation extracts the entire
# bundle (~50 MB) to a temp directory before Python starts. On
# macOS arm64 that's measured at 8–10 s of cold-start latency.
# The actual Python imports take ~250 ms — the wait is purely
# PyInstaller's bootloader. onedir mode skips the extraction
# step and brings cold-start back down to ~0.5 s, matching the
# pip-installed experience.
#
# CI tars the resulting `dist/s0/` folder into a single
# `s0-<platform>-<arch>.tar.gz` (zip on Windows) so users still
# download one file; install is `tar xzf … && mv s0/s0 /usr/local/bin`
# (the binary in `s0/` knows how to find its sibling shared libs).
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="s0",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX trips Windows AV; size win isn't worth the false positives.
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="s0",
)
