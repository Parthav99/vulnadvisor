"""Package that re-exports a sink from its implementation module (tests re-export resolution)."""

from .impl import reexported_sink

__all__ = ["reexported_sink"]
