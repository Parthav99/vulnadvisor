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
    """A location where dynamic import/execution may hide a real usage.

    ``target_root`` and ``first_party_relative`` record what static analysis can *prove* about the
    import target — purely a function of the call's syntax, so they are safe to cache. A site that
    provably targets only the project's own first-party modules (a relative loader, a
    ``__name__``/``__package__``-prefixed module, or a constant first-party prefix) cannot pull in a
    third-party distribution, so it must not escalate unused third-party packages to
    ``DYNAMIC_UNKNOWN``. ``eval``/``exec`` and opaque targets stay unprovable (conservative).

    Attributes:
        target_root: The provable absolute top-level module the import targets (the constant
            leading segment, e.g. ``"redash"`` for ``import_module("redash." + x)``), or ``None``
            when the target cannot be pinned down statically.
        first_party_relative: ``True`` when the site provably targets the current/first-party
            package (a leading-dot relative import, or a ``__name__``/``__package__`` prefix).
        runtime: ``False`` for build-time-only files (``setup.py``, a Sphinx ``conf.py``, anything
            under ``docs/``) whose ``eval``/``exec`` never runs in the deployed application, so it
            cannot make a dependency vulnerability reachable. Such sites do not force caution.
    """

    model_config = ConfigDict(frozen=True)

    file: str
    lineno: int
    col: int
    kind: DynamicImportKind
    detail: str
    target_root: str | None = None
    first_party_relative: bool = False
    runtime: bool = True

    def is_provably_first_party(self, first_party_modules: frozenset[str]) -> bool:
        """Whether this site can only reach the project's own first-party modules.

        ``eval``/``exec`` run arbitrary code and are never provable. A relative/own-package target
        is always first-party; a constant absolute target is first-party only if its root is one of
        the project's own modules. Anything unproven returns ``False`` (stay conservative).
        """
        if self.kind in (DynamicImportKind.EVAL, DynamicImportKind.EXEC):
            return False
        if self.first_party_relative:
            return True
        return self.target_root is not None and self.target_root in first_party_modules


class ImportParseError(BaseModel):
    """A file that could not be parsed (recorded, not raised — a gap to stay cautious about)."""

    model_config = ConfigDict(frozen=True)

    file: str
    message: str


class FileAnalysis(BaseModel):
    """The cacheable result of statically analyzing a single source file.

    This is the unit of incremental caching: keyed on the file's content hash, an unchanged file
    is never re-parsed. It carries exactly what :func:`build_import_graph` needs to assemble the
    whole-project graph — the file's import sites, dynamic constructs, and any parse error.
    """

    model_config = ConfigDict(frozen=True)

    imports: tuple[ImportSite, ...] = ()
    dynamic_sites: tuple[DynamicImportSite, ...] = ()
    parse_error: ImportParseError | None = None


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
    analyzed_file_count: int = 0

    def unproven_dynamic_sites(self) -> tuple[DynamicImportSite, ...]:
        """Dynamic sites that genuinely force caution: runtime, and not provably first-party-only.

        A site is excluded here when it cannot hide third-party runtime usage — either because it
        provably targets only the project's own modules, or because it lives in build-time-only code
        (``setup.py``/``docs``) that never runs in the deployed app. Everything else (``eval``/
        ``exec`` and opaque/third-party imports in runtime code) remains, exactly as conservative as
        before for any project that has such a site.
        """
        first_party = frozenset(self.first_party_modules)
        return tuple(
            site
            for site in self.dynamic_sites
            if site.runtime and not site.is_provably_first_party(first_party)
        )

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
