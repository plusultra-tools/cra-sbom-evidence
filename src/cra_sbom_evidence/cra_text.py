"""CRA clause registry loader.

Loads the verbatim CRA clause data from ``data/cra_clauses.yaml`` and exposes
it as typed objects. The ``sha256`` field on each clause is computed at load
time from the ``text`` field; tests assert identity to detect drift.

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


class CraClause(BaseModel):
    """A single CRA clause with verbatim text and evidence metadata."""

    key: str
    title: str
    text: str
    evidence_fields: list[str] = Field(default_factory=list)
    source_url: str = "https://eur-lex.europa.eu/eli/reg/2024/2847/oj"
    excerpt_type: str = "verbatim"   # "verbatim" | "paraphrase" | "summary"
    sha256: str = ""

    @model_validator(mode="after")
    def compute_sha256(self) -> "CraClause":
        """Compute SHA-256 of the text field if not already set."""
        if not self.sha256:
            self.sha256 = hashlib.sha256(self.text.encode("utf-8")).hexdigest()
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


def verify_integrity() -> dict[str, bool]:
    """Recompute SHA-256 of each clause text and compare to the stored digest.

    Returns:
        Mapping of clause key → True (pass) / False (drift detected).
    """
    registry = load_registry()
    results: dict[str, bool] = {}
    for key, clause in registry.clauses.items():
        computed = hashlib.sha256(clause.text.encode("utf-8")).hexdigest()
        results[key] = computed == clause.sha256
    return results
