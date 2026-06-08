"""Models for vulnerable symbols extracted from an advisory's fix commit (the data moat)."""

from enum import Enum

from pydantic import BaseModel, ConfigDict


class SymbolKind(str, Enum):
    """The kind of code object a vulnerable symbol refers to."""

    FUNCTION = "function"
    METHOD = "method"
    CLASS = "class"


class ExtractionStatus(str, Enum):
    """Outcome of trying to extract vulnerable symbols for an advisory."""

    EXTRACTED = "extracted"
    NO_FIX_LINK = "no-fix-link"
    FETCH_FAILED = "fetch-failed"
    NO_SYMBOLS = "no-symbols"


class VulnerableSymbol(BaseModel):
    """A candidate vulnerable symbol changed by an advisory's fix.

    Attributes:
        name: The simple symbol name (e.g. ``find_python_name``).
        qualname: Dotted qualified name within the file (e.g. ``FullConstructor.find_python_name``).
        kind: Whether it is a function, method, or class.
        file: The repository-relative file path the symbol lives in, if known.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    qualname: str
    kind: SymbolKind
    file: str | None = None


class SymbolExtraction(BaseModel):
    """The result of extracting vulnerable symbols for one advisory.

    Attributes:
        advisory_id: The advisory the symbols were extracted for.
        symbols: The candidate vulnerable symbols (empty unless ``status`` is ``EXTRACTED``).
        confidence: 0..1 confidence in the extraction (0 when no symbols were produced).
        provenance: The fix-commit URLs the symbols were derived from.
        status: Why the extraction succeeded or degraded.
    """

    model_config = ConfigDict(frozen=True)

    advisory_id: str
    symbols: tuple[VulnerableSymbol, ...] = ()
    confidence: float = 0.0
    provenance: tuple[str, ...] = ()
    status: ExtractionStatus
