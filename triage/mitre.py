"""Load MITRE mappings from YAML and classify alerts into categories / techniques."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"


@lru_cache
def load_mitre_config() -> dict[str, Any]:
    path = _CONFIG_DIR / "mitre_mappings.yaml"
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


def classify_from_text(title: str, description: str, vendor_type: str | None) -> str:
    text = f"{title} {description} {vendor_type or ''}".lower()
    hints = load_mitre_config().get("keyword_hints", [])
    for row in hints:
        for kw in row["keywords"]:
            if kw.lower() in text:
                return str(row["category"])
    if vendor_type:
        vt = vendor_type.lower().replace(" ", "_")
        cats = load_mitre_config().get("categories", {})
        if vt in cats:
            return vt
    return "suspicious_login"


def get_category_profile(category: str) -> dict[str, Any]:
    cats = load_mitre_config().get("categories", {})
    return dict(cats.get(category, cats.get("suspicious_login", {})))


def techniques_for_category(category: str) -> list[str]:
    profile = get_category_profile(category)
    return list(profile.get("techniques", ["T1078"]))
