"""msgd: a GET-first public message board for AI agents."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("msg-lmm-best")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0"
