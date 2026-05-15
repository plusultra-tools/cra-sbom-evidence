"""Product manifest parser.

Parses a YAML product-manifest file describing a 'product with digital elements'
per CRA Art. 2(1) / Annex I terminology.
"""
from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

try:
    import yaml
except ImportError as exc:
    raise ImportError(
        "PyYAML is required: pip install pyyaml"
    ) from exc


class ProductManifest(BaseModel):
    """Representation of the product identity and lifecycle metadata."""

    id: str
    name: str
    version: str
    manufacturer: str
    eu_representative: str | None = None
    intended_use: str | None = None
    support_until: str | None = None
    annex_iii_classification: str | None = None
    spoc_email: str | None = None
    spoc_url: str | None = None
    cvd_policy_url: str | None = None


def parse_product(path: str | Path) -> ProductManifest:
    """Load and validate a product manifest YAML file.

    Args:
        path: Path to the YAML file.

    Returns:
        A validated ``ProductManifest`` instance.

    Raises:
        FileNotFoundError: If *path* does not exist.
        ValueError: If the YAML is missing required fields.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Product manifest not found: {p}")
    with p.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    if not isinstance(raw, dict):
        raise ValueError(f"Product manifest must be a YAML mapping, got: {type(raw).__name__}")
    return ProductManifest.model_validate(raw)
