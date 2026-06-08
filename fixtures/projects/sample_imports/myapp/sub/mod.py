"""Module exercising relative imports at different levels."""

from . import other
from .helper import thing
from ..main import load

__all__ = ["load", "other", "thing"]
