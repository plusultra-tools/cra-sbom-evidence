"""CRA clause registry loader.

Loads the verbatim CRA clause data from ``data/cra_clauses.yaml`` and exposes
it as typed objects.

The ``data/clauses.lock`` file is the canonical source-of-truth for the
SHA-256 digest of each bundled clause text. ``verify_integrity()`` compares
the YAML-derived hash against the locked hash (NOT against itself) so that
a maintainer-side transcription error in the YAML is caught at runtime —
which is what ``cra-sbom verify-citations`` reports.

Source: Regulation (EU) 2024/2847 (Cyber Resilience Act), OJEU 2024-11-20.
Canonical URL: https://eur-lex.europa.eu/eli/reg/2024/2847/oj
"""
from __future__ import annotations

import hashlib
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, model_validator

try:
    import yaml
except ImportError as exc:
    raise ImportError("PyYAML is required: pip install pyyaml") from exc


# Valid excerpt_type values. The lock file records the declared excerpt type
# alongside the hash so verification can also detect classification drift.
_VALID_EXCERPT_TYPES = frozenset({"verbatim", "verbatim_truncated", "summary"})


class CraClause(BaseModel):
    """A single CRA clause with verbatim text and evidence metadata."""

    key: str
    title: str
    text: str
    evidence_fields: list[str] = Field(default_factory=list)
    source_url: str = "https://eur-lex.europa.eu/eli/reg/2024/2847/oj"
    excerpt_type: str = "verbatim"   # "verbatim" | "verbatim_truncated" | "summary"
    sha256: str = ""

    @model_validator(mode="after")
    def compute_sha256(self) -> "CraClause":
        """Compute SHA-256 of the text field if not already set."""
        if not self.sha256:
            self.sha256 = hashlib.sha256(self.text.encode("utf-8")).hexdigest()
        if self.excerpt_type not in _VALID_EXCERPT_TYPES:
            raise ValueError(
                f"Invalid excerpt_type {self.excerpt_type!r} for clause {self.key!r}. "
                f"Valid values: {sorted(_VALID_EXCERPT_TYPES)}"
            )
        return self


class CraRegistry(BaseModel):
    """Full registry of CRA clauses with regulation metadata."""

    source_canonical_url: str
    regulation_id: str
    short_title: str
    date_article_14_applies: str
    date_full_application: str
    clauses: dict[str, CraClause]


def _load_yaml_data() -> dict[str, Any]:
    """Load the YAML data file bundled with the package."""
    # Try importlib.resources first (installed package)
    try:
        ref = resources.files("cra_sbom_evidence.data").joinpath("cra_clauses.yaml")
        with resources.as_file(ref) as yaml_path:
            with open(yaml_path, encoding="utf-8") as fh:
                loaded: dict[str, Any] = yaml.safe_load(fh)
                return loaded
    except (AttributeError, TypeError, FileNotFoundError):
        pass
    # Fallback: relative to this file (development mode)
    fallback = Path(__file__).parent / "data" / "cra_clauses.yaml"
    if fallback.exists():
        with fallback.open(encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh)
            return loaded
    raise FileNotFoundError("cra_clauses.yaml not found in package data or adjacent directory")


def _load_lock_data() -> dict[str, tuple[str, str]]:
    """Load the canonical lock file. Returns mapping key -> (sha256, excerpt_type).

    Falls back to an empty dict if the lock file is missing — in that case
    ``verify_integrity()`` returns a ``"missing_lock"`` marker for every key.
    """
    # Try installed-package location first
    try:
        ref = resources.files("cra_sbom_evidence.data").joinpath("clauses.lock")
        with resources.as_file(ref) as lock_path:
            return _parse_lock_file(lock_path)
    except (AttributeError, TypeError, FileNotFoundError):
        pass
    fallback = Path(__file__).parent / "data" / "clauses.lock"
    if fallback.exists():
        return _parse_lock_file(fallback)
    return {}


def _parse_lock_file(lock_path: Path) -> dict[str, tuple[str, str]]:
    """Parse the line-oriented lock file."""
    result: dict[str, tuple[str, str]] = {}
    with lock_path.open(encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            sha, key, excerpt_type = parts[0], parts[1], parts[2]
            result[key] = (sha, excerpt_type)
    return result


@lru_cache(maxsize=1)
def load_registry() -> CraRegistry:
    """Load and parse the CRA clause registry (cached after first call).

    Returns:
        A ``CraRegistry`` with all clauses and their SHA-256 digests.
    """
    data = _load_yaml_data()
    raw_clauses: dict[str, Any] = data.pop("clauses", {})
    clauses: dict[str, CraClause] = {}
    for key, clause_data in raw_clauses.items():
        if not isinstance(clause_data, dict):
            continue
        clause_data["key"] = key
        clauses[key] = CraClause.model_validate(clause_data)

    # Build registry with remaining top-level fields
    registry_data = {**data, "clauses": clauses}
    # Drop unknown top-level keys (e.g., date_of_entry_into_force) — model is strict
    known = {
        "source_canonical_url",
        "regulation_id",
        "short_title",
        "date_article_14_applies",
        "date_full_application",
        "clauses",
    }
    registry_data = {k: v for k, v in registry_data.items() if k in known}
    return CraRegistry.model_validate(registry_data)


def get_clause(key: str) -> CraClause:
    """Fetch a single clause by key.

    Args:
        key: Clause key, e.g. ``"art_14_1"`` or ``"annex_i_part_ii"``.

    Returns:
        The corresponding ``CraClause``.

    Raises:
        KeyError: If the key does not exist in the registry.
    """
    registry = load_registry()
    if key not in registry.clauses:
        raise KeyError(f"Unknown CRA clause key: {key!r}. "
                       f"Available keys: {list(registry.clauses.keys())}")
    return registry.clauses[key]


def verify_integrity() -> dict[str, dict[str, str]]:
    """Recompute SHA-256 of each clause text and compare against the lock file.

    Returns:
        Mapping of clause key -> dict with keys:
            - ``status``: "ok" | "drift" | "missing_in_lock" | "missing_in_yaml" | "type_drift"
            - ``yaml_sha256``: computed digest from YAML text (or empty if missing)
            - ``lock_sha256``: digest from clauses.lock (or empty if missing)
            - ``yaml_excerpt_type``: excerpt_type from YAML
            - ``lock_excerpt_type``: excerpt_type from lock
    """
    registry = load_registry()
    lock_data = _load_lock_data()
    results: dict[str, dict[str, str]] = {}

    yaml_keys = set(registry.clauses.keys())
    lock_keys = set(lock_data.keys())

    for key in sorted(yaml_keys | lock_keys):
        if key not in yaml_keys:
            results[key] = {
                "status": "missing_in_yaml",
                "yaml_sha256": "",
                "lock_sha256": lock_data[key][0],
                "yaml_excerpt_type": "",
                "lock_excerpt_type": lock_data[key][1],
            }
            continue
        clause = registry.clauses[key]
        computed = hashlib.sha256(clause.text.encode("utf-8")).hexdigest()
        if key not in lock_keys:
            results[key] = {
                "status": "missing_in_lock",
                "yaml_sha256": computed,
                "lock_sha256": "",
                "yaml_excerpt_type": clause.excerpt_type,
                "lock_excerpt_type": "",
            }
            continue
        lock_sha, lock_type = lock_data[key]
        if computed != lock_sha:
            status = "drift"
        elif clause.excerpt_type != lock_type:
            status = "type_drift"
        else:
            status = "ok"
        results[key] = {
            "status": status,
            "yaml_sha256": computed,
            "lock_sha256": lock_sha,
            "yaml_excerpt_type": clause.excerpt_type,
            "lock_excerpt_type": lock_type,
        }
    return results
