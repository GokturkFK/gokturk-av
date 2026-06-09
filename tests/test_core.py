"""Temel sanity testleri — çekirdek modüllerin import edilebilirliğini doğrular."""

from core.finding_store import FindingStore
from taxonomy.loader import load_taxonomy, get_vector, get_category
from plugins.base_plugin import Finding


def test_taxonomy_loads():
    tax = load_taxonomy()
    assert "categories" in tax
    assert len(tax["categories"]) == 7


def test_taxonomy_has_vectors():
    tax = load_taxonomy()
    total = sum(len(cat["vectors"]) for cat in tax["categories"])
    assert total > 0


def test_get_vector_returns_dict():
    result = get_vector("R155-2.5")
    assert isinstance(result, dict)


def test_get_category_returns_dict():
    result = get_category(1)
    assert isinstance(result, dict)


def test_finding_store_init(tmp_path):
    db = FindingStore(db_path=str(tmp_path / "test.db"))
    assert db is not None


def test_finding_dataclass():
    f = Finding(
        component_id="test_comp",
        test_module_id="test_mod",
        r155_vector_id="R155-2.5",
        r155_category=2,
        status="vulnerable",
        title="Test bulgusu",
        description="Açıklama",
        attack_feasibility="medium",
    )
    assert f.status == "vulnerable"
    assert f.r155_category == 2
