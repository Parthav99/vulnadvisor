"""Models describing the import structure of a project's first-party code."""

from enum import Enum

from pydantic import BaseModel, ConfigDict


class ImportKind(str, Enum):
    """Whether an import site is a plain ``import`` or a ``from ... import``."""

    IMPORT = "import"
    FROM = "from"


class DynamicImportKind(str, Enum):
    """A construct that can import or execute code in ways static analysis cannot follow."""

    IMPORTLIB = "importlib"
    DUNDER_IMPORT = "__import__"
    EVAL = "eval"
    EXEC = "exec"


class ImportedName(BaseModel):
    """A single name brought in by an import statement, with its optional alias."""

    model_config = ConfigDict(frozen=True)

    name: str
    asname: str | None = None


class ImportSite(BaseModel):
    """One ``import`` / ``from ... import`` statement and where it appears.

    Attributes:
        file: Project-relative POSIX path of the source file.
        lineno: 1-based line number of the statement.
        col: 0-based column offset.
        kind: Plain ``import`` or ``from`` import.
        module: For ``from`` imports, the module after ``from`` (may be ``None`` for
            ``from . import x``). ``None`` for plain ``import`` (the modules live in ``names``).
        level: Relative-import dot count (0 for absolute imports).
        names: The imported names/aliases. For plain ``import`` these are the dotted module
            paths; for ``from`` imports they are the imported symbols.
    """

    model_config = ConfigDict(frozen=True)

    file: str
    lineno: int
    col: int
    kind: ImportKind
    module: str | None = None
    level: int = 0
    names: tuple[ImportedName, ...] = ()

    @property
    def is_relative(self) -> bool:
        """Whether this is a relative import (first-party, ``level > 0``)."""
        return self.level > 0

    def imported_roots(self) -> tuple[str, ...]:
        """Return the top-level absolute module names this site references.

        Relative imports return ``()`` (they are first-party, not a distribution root).
        """
        if self.kind is ImportKind.IMPORT:
            roots = (name.name.split(".")[0] for name in self.names if name.name)
            return tuple(dict.fromkeys(roots))
        if self.is_relative or not self.module:
            return ()
        return (self.module.split(".")[0],)


class DynamicImportSite(BaseModel):
    """A location where dynamic import/execution may hide a real usage."""

    model_config = ConfigDict(frozen=True)

    file: str
    lineno: int
    col: int
    kind: DynamicImportKind
    detail: str


class ImportParseError(BaseModel):
    """A file that could not be parsed (recorded, not raised — a gap to stay cautious about)."""

    model_config = ConfigDict(frozen=True)

    file: str
    message: str


class ImportGraph(BaseModel):
    """The collected import structure of a project.

    Attributes:
        import_sites: Every import statement found, ordered by (file, line, col).
        dynamic_sites: Dynamic import/exec constructs and their locations.
        first_party_modules: Top-level module names that belong to the project itself.
        parse_errors: Files that failed to parse (their imports could be missed).
    """

    model_config = ConfigDict(frozen=True)

    import_sites: tuple[ImportSite, ...] = ()
    dynamic_sites: tuple[DynamicImportSite, ...] = ()
    first_party_modules: tuple[str, ...] = ()
    parse_errors: tuple[ImportParseError, ...] = ()

    def import_roots(self) -> dict[str, tuple[ImportSite, ...]]:
        """Map every absolute import root to the sites that import it."""
        out: dict[str, list[ImportSite]] = {}
        for site in self.import_sites:
            for root in site.imported_roots():
                out.setdefault(root, []).append(site)
        return {root: tuple(sites) for root, sites in out.items()}

    def external_import_roots(self) -> dict[str, tuple[ImportSite, ...]]:
        """Like :meth:`import_roots` but excluding the project's own first-party modules."""
        first_party = set(self.first_party_modules)
        return {
            root: sites for root, sites in self.import_roots().items() if root not in first_party
        }
