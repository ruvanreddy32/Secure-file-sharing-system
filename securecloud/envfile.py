"""
securecloud/envfile.py — Load credentials from a git-ignored ``.env`` file.

Minimal ``KEY=VALUE`` parser (comments with ``#``, optional quotes, optional ``export``).
Variables already present in the real environment always win, so a ``.env`` file never
overrides what the shell sets.  The file must stay out of version control (``.gitignore``
lists ``.env``).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Optional, Union


def parse(text: str) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def read(path: Optional[Union[str, Path]] = None) -> Dict[str, str]:
    """Parse ``.env`` without touching ``os.environ``."""
    p = Path(path) if path else Path.cwd() / ".env"
    return parse(p.read_text(encoding="utf-8-sig")) if p.is_file() else {}


def load(path: Optional[Union[str, Path]] = None) -> Dict[str, str]:
    """Load ``.env`` (default: current directory) into ``os.environ`` without overriding.

    Returns the variables that were newly set.
    """
    if os.environ.get("RINGCRYPTER_NO_DOTENV"):
        return {}                     # set by the unit tests to stay hermetic
    p = Path(path) if path else Path.cwd() / ".env"
    if not p.is_file():
        return {}
    added = {}
    for key, value in parse(p.read_text(encoding="utf-8-sig")).items():
        if key not in os.environ:
            os.environ[key] = value
            added[key] = value
    return added
