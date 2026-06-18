"""Index templates and ILM policies — aligned with STINGAR stingar-* conventions."""

from __future__ import annotations

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
ES_ASSETS_DIR = PROJECT_ROOT / "es"

ENRICHED_INDEX_PREFIX = "stingar"
SUMMARIES_INDEX = "intel-summaries"

ENRICHED_TEMPLATE_NAME = "stingar-enriched"
SUMMARIES_TEMPLATE_NAME = "intel-summaries"
ENRICHED_ILM_POLICY_NAME = "stingar-policy"


def _load_json(relative_path: str) -> dict:
    path = ES_ASSETS_DIR / relative_path
    return json.loads(path.read_text(encoding="utf-8"))


def enriched_index_template() -> dict:
    return _load_json("templates/stingar-enriched.json")


def summaries_index_template() -> dict:
    return _load_json("templates/intel-summaries.json")


def enriched_ilm_policy() -> dict:
    return _load_json("ilm/stingar-enriched-policy.json")
