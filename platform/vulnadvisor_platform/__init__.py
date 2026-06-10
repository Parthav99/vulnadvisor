"""VulnAdvisor platform backend (M11).

A FastAPI service that wraps the ``vulnadvisor`` engine so teams can store and view findings. It
never replaces the engine: verdicts are identical whether produced by the CLI or served here. The
default mode stores *findings + metadata* only — source never leaves customer infrastructure.
"""

__version__ = "0.1.0"
