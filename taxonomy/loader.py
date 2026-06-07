"""GÖKTÜRK — Taksonomi yükleyici."""
import json
from pathlib import Path

_TAX_PATH = Path(__file__).parent / "r155_annex5.json"


def load_taxonomy() -> dict:
    with open(_TAX_PATH, encoding="utf-8") as f:
        return json.load(f)


def get_vector(vector_id: str) -> dict:
    tax = load_taxonomy()
    for cat in tax["categories"]:
        for v in cat["vectors"]:
            if v["id"] == vector_id:
                return {**v, "category_id": cat["id"], "category_label": cat["label"]}
    return {}


def get_category(category_id: int) -> dict:
    tax = load_taxonomy()
    for cat in tax["categories"]:
        if cat["id"] == category_id:
            return cat
    return {}
