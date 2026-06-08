"""Models for a concrete call path from the user's code to a vulnerable symbol."""

from pydantic import BaseModel, ConfigDict


class CallStep(BaseModel):
    """One node on a call path: a first-party function/module, or the final vulnerable call."""

    model_config = ConfigDict(frozen=True)

    qualname: str
    file: str | None = None
    line: int | None = None


class CallPath(BaseModel):
    """An ordered chain of call steps ending at the vulnerable symbol's call site."""

    model_config = ConfigDict(frozen=True)

    steps: tuple[CallStep, ...]

    def render(self) -> str:
        """Render the path as ``a -> b -> vuln (file:line)`` for display."""
        chain = " -> ".join(step.qualname for step in self.steps)
        last = self.steps[-1] if self.steps else None
        if last is not None and last.file and last.line:
            return f"{chain} ({last.file}:{last.line})"
        return chain
