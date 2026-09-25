"""Local storage policy for msg.lmm.best login credentials."""

from __future__ import annotations

import os
import secrets
from collections.abc import Mapping
from pathlib import Path

APP_DIR = "msg.lmm.best"


def credential_dir_candidates(
    *,
    home: str | Path | None = None,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> tuple[Path, ...]:
    """Return credential directories in strict preference order."""
    environment = os.environ if env is None else env
    home_path = Path.home() if home is None else Path(home)
    cwd_path = Path.cwd() if cwd is None else Path(cwd)

    candidates = [
        home_path / ".config" / APP_DIR,
        cwd_path / ".config" / APP_DIR,
    ]
    xdg = environment.get("XDG_CONFIG_HOME")
    if xdg:
        candidates.append(Path(xdg) / APP_DIR)
    candidates.append(cwd_path / f".{APP_DIR}")

    tmp = environment.get("TMPDIR")
    if tmp:
        candidates.append(Path(tmp) / APP_DIR)

    unique: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        key = str(path.expanduser().absolute())
        if key not in seen:
            seen.add(key)
            unique.append(path.expanduser())
    return tuple(unique)


def _prepare_private_dir(path: Path) -> Path:
    if path.is_symlink():
        raise OSError(f"refusing symlink credential directory: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise OSError(f"credential path is not a private directory: {path}")
    os.chmod(path, 0o700)

    probe = path / f".write-test-{secrets.token_hex(8)}"
    fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    probe.unlink()
    return path


def find_credential_dir(
    *,
    home: str | Path | None = None,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> Path | None:
    """Find the first safe writable credential directory, or None."""
    for path in credential_dir_candidates(home=home, cwd=cwd, env=env):
        try:
            return _prepare_private_dir(path)
        except OSError:
            continue
    return None


def credential_path(
    filename: str,
    *,
    home: str | Path | None = None,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
) -> Path | None:
    """Return a safe path for one credential file, creating its directory."""
    if not filename or Path(filename).name != filename or filename in {".", ".."}:
        raise ValueError("credential filename must be one local file name")
    directory = find_credential_dir(home=home, cwd=cwd, env=env)
    return None if directory is None else directory / filename
