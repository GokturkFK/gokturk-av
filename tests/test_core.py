"""
GÖKTÜRK — Çekirdek Test Suite (Faz 2-4)
Tüm katmanları kapsar: taksonomi, Finding şeması, FindingStore,
mock adaptör, yedi test modülü, orchestrator ve rapor üretici.

Donanımsızdır; her şey MockAdapter üzerinden deterministik koşar.
"""

import pytest

from taxonomy.loader import load_taxonomy, get_vector, get_category
from plugins.base_plugin import Finding, BasePlugin
from core.finding_store import FindingStore
from core.orchestrator import Orchestrator
from adapters.mock_adapter import MockAdapter

from plugins.modules.can_replay_plugin import CANReplayPlugin
from plugins.modules.can_fuzz_plugin import CANFuzzPlugin
from plugins.modules.ros2_topic_enum_plugin import ROS2TopicEnumPlugin
from plugins.modules.gps_spoof_plugin import GPSSpoofPlugin
from plugins.modules.obd2_enum_plugin import OBD2EnumPlugin
from plugins.modules.ros2_topic_injection_plugin import ROS2TopicInjectionPlugin
from plugins.modules.lidar_spoof_plugin import LidarSpoofPlugin
from plugins.modules.v2x_spoof_plugin import V2XSpoofPlugin
from core.report_generator import generate_compliance_report
from docx import Document
from io import BytesIO


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def profile():
    return {
        "id": "shuttle-test",
        "name": "Test Shuttle",
        "components": [
            {"id": "gateway_ecu", "attack_surfaces": ["in-vehicle-network"],
             "r155_vectors": ["R155-2.2", "R155-2.5"]},
            {"id": "hpc", "attack_surfaces": ["ros2-dds"], "r155_vectors": ["R155-5.6"]},
            {"id": "gnss", "attack_surfaces": ["sensor-spoofing"], "r155_vectors": ["R155-2.8"]},
            {"id": "obd2_port", "attack_surfaces": ["diagnostic"], "r155_vectors": ["R155-5.5"]},
        ],
    }


def _mock(mode="vulnerable"):
    a = MockAdapter({"mode": mode})
    a.connect()
    return a


# ── Taksonomi ────────────────────────────────────────────────────────────────

def test_taxonomy_loads():
    tax = load_taxonomy()
    assert "categories" in tax
    assert len(tax["categories"]) == 7


def test_taxonomy_total_vectors_is_69():
    tax = load_taxonomy()
    total = sum(len(cat["vectors"]) for cat in tax["categories"])
    assert total == 69
    assert tax["total_vectors"] == 69


def test_taxonomy_vector_ids_unique():
    tax = load_taxonomy()
    ids = [v["id"] for cat in tax["categories"] for v in cat["vectors"]]
    assert len(ids) == len(set(ids))


def test_get_vector_returns_category_context():
    v = get_vector("R155-2.5")
    assert v["id"] == "R155-2.5"
    assert v["category_id"] == 2
    assert "category_label" in v


def test_get_vector_unknown_returns_empty():
    assert get_vector("R155-9.9") == {}


def test_get_category_returns_dict():
    cat = get_category(5)
    assert cat["id"] == 5
    assert len(cat["vectors"]) > 0


def test_get_category_unknown_returns_empty():
    assert get_category(99) == {}


# ── Finding şeması ───────────────────────────────────────────────────────────

def test_finding_defaults():
    f = Finding(component_id="c", test_module_id="m", status="vulnerable", title="t")
    assert f.impact_safety == "none"
    assert f.attack_feasibility == "unknown"
    assert f.id and f.created_at


def test_finding_is_vulnerable():
    f = Finding(component_id="c", test_module_id="m", status="vulnerable", title="t")
    assert f.is_vulnerable() is True


def test_finding_is_critical_safety():
    f = Finding(component_id="c", test_module_id="m", status="vulnerable",
                title="t", impact_safety="high")
    assert f.is_critical_safety() is True


def test_finding_not_critical_when_clean():
    f = Finding(component_id="c", test_module_id="m", status="not_vulnerable",
                title="t", impact_safety="high")
    assert f.is_critical_safety() is False


def test_finding_highest_impact():
    f = Finding(component_id="c", test_module_id="m", status="vulnerable", title="t",
                impact_safety="medium", impact_operational="critical")
    assert f.highest_impact() == "critical"


def test_finding_to_dict_roundtrip():
    f = Finding(component_id="c", test_module_id="m", status="vulnerable", title="t")
    d = f.to_dict()
    assert d["component_id"] == "c"
    assert d["status"] == "vulnerable"


# ── FindingStore ─────────────────────────────────────────────────────────────

def test_store_init(tmp_path):
    db = FindingStore(db_path=str(tmp_path / "t.db"))
    assert db is not None


def test_store_profile_roundtrip(tmp_path):
    db = FindingStore(db_path=str(tmp_path / "t.db"))
    db.save_profile("p1", "Prof 1", "id: p1")
    assert db.get_profile("p1")["name"] == "Prof 1"
    assert any(p["id"] == "p1" for p in db.get_profiles())


def test_store_session_lifecycle(tmp_path):
    db = FindingStore(db_path=str(tmp_path / "t.db"))
    db.save_profile("p1", "Prof 1", "x")
    sid = db.create_session("p1", "not")
    db.close_session(sid)
    sessions = db.get_sessions("p1")
    assert sessions[0]["status"] == "completed"


def test_store_add_and_get_finding(tmp_path):
    db = FindingStore(db_path=str(tmp_path / "t.db"))
    db.save_profile("p1", "Prof 1", "x")
    sid = db.create_session("p1")
    db.add_finding(sid, "p1", "comp", "mod", "vulnerable", "T",
                   r155_vector_id="R155-2.5", r155_category=2)
    findings = db.get_findings(vehicle_profile_id="p1")
    assert len(findings) == 1
    assert findings[0]["r155_vector_id"] == "R155-2.5"
    assert findings[0]["evidence_paths"] == []


def test_store_filter_by_status(tmp_path):
    db = FindingStore(db_path=str(tmp_path / "t.db"))
    db.save_profile("p1", "Prof 1", "x")
    sid = db.create_session("p1")
    db.add_finding(sid, "p1", "c", "m", "vulnerable", "A")
    db.add_finding(sid, "p1", "c", "m", "not_vulnerable", "B")
    assert len(db.get_findings(status="vulnerable")) == 1


def test_store_compliance_coverage(tmp_path):
    db = FindingStore(db_path=str(tmp_path / "t.db"))
    db.save_profile("p1", "Prof 1", "x")
    sid = db.create_session("p1")
    db.add_finding(sid, "p1", "c", "m", "vulnerable", "A", r155_vector_id="R155-2.5")
    db.add_finding(sid, "p1", "c", "m", "not_vulnerable", "B", r155_vector_id="R155-5.6")
    cov = db.get_compliance_coverage("p1")
    assert cov["total"] == 2
    assert cov["vulnerable"] == 1
    assert cov["vectors_tested"] == 2


def test_store_module_registry(tmp_path):
    db = FindingStore(db_path=str(tmp_path / "t.db"))
    db.register_module({"id": "can-replay", "name": "Replay",
                        "surface": "in-vehicle-network", "technique": "replay"})
    mods = db.get_modules()
    assert any(m["id"] == "can-replay" for m in mods)


# ── MockAdapter ──────────────────────────────────────────────────────────────

def test_mock_invalid_mode_raises():
    with pytest.raises(ValueError):
        MockAdapter({"mode": "banana"})


def test_mock_connect_and_impersonate():
    a = MockAdapter({"mode": "secure", "as_type": "socketcan"})
    assert a.connect() is True
    assert a.is_connected() is True
    assert a.adapter_type == "socketcan"


def test_mock_modes_behaviour():
    assert _mock("vulnerable").receive_frames() != []
    assert _mock("empty").receive_frames() == []
    assert _mock("vulnerable").send_frame({"arb_id": 1}) is True
    assert _mock("secure").send_frame({"arb_id": 1}) is False
    assert _mock("secure").list_topics() and _mock("empty").list_topics() == []


def test_mock_v2x_injection_behaviour():
    # imzasız mesaj: sadece vulnerable kabul; imzalı: her modda kabul
    assert _mock("vulnerable").inject_v2x_message(signed=False) is True
    assert _mock("secure").inject_v2x_message(signed=False) is False
    assert _mock("empty").inject_v2x_message(signed=False) is False
    assert _mock("secure").inject_v2x_message(signed=True) is True


# ── Plugin katmanı ───────────────────────────────────────────────────────────

def test_can_replay_matrix():
    assert CANReplayPlugin(_mock("vulnerable")).run({"id": "c"}).status == "vulnerable"
    assert CANReplayPlugin(_mock("secure")).run({"id": "c"}).status == "not_vulnerable"
    assert CANReplayPlugin(_mock("empty")).run({"id": "c"}).status == "inconclusive"


def test_can_fuzz_matrix():
    assert CANFuzzPlugin(_mock("vulnerable")).run({"id": "c"}).status == "vulnerable"
    assert CANFuzzPlugin(_mock("secure")).run({"id": "c"}).status == "not_vulnerable"
    assert CANFuzzPlugin(_mock("empty")).run({"id": "c"}).status == "inconclusive"


def test_ros2_enum_matrix():
    assert ROS2TopicEnumPlugin(_mock("vulnerable")).run({"id": "c"}).status == "vulnerable"
    assert ROS2TopicEnumPlugin(_mock("secure")).run({"id": "c"}).status == "not_vulnerable"
    assert ROS2TopicEnumPlugin(_mock("empty")).run({"id": "c"}).status == "inconclusive"


def test_gps_spoof_matrix():
    assert GPSSpoofPlugin(_mock("vulnerable")).run({"id": "c"}).status == "vulnerable"
    assert GPSSpoofPlugin(_mock("secure")).run({"id": "c"}).status == "not_vulnerable"


def test_obd2_enum_matrix():
    assert OBD2EnumPlugin(_mock("vulnerable")).run({"id": "c"}).status == "vulnerable"
    assert OBD2EnumPlugin(_mock("secure")).run({"id": "c"}).status == "not_vulnerable"
    assert OBD2EnumPlugin(_mock("empty")).run({"id": "c"}).status == "inconclusive"


def test_vulnerable_findings_carry_taxonomy():
    f = OBD2EnumPlugin(_mock("vulnerable")).run({"id": "c"})
    assert f.r155_vector_id == "R155-5.5"
    assert f.r155_category == 5
    assert f.is_vulnerable()


def test_plugin_never_raises_on_bad_component():
    # component_config eksik olsa da plugin exception fırlatmamalı
    f = CANReplayPlugin(_mock("vulnerable")).run({})
    assert isinstance(f, Finding)


def test_ros2_injection_matrix():
    assert ROS2TopicInjectionPlugin(_mock("vulnerable")).run({"id": "c"}).status == "vulnerable"
    assert ROS2TopicInjectionPlugin(_mock("secure")).run({"id": "c"}).status == "not_vulnerable"
    assert ROS2TopicInjectionPlugin(_mock("empty")).run({"id": "c"}).status == "inconclusive"


def test_ros2_injection_critical_safety_when_vulnerable():
    f = ROS2TopicInjectionPlugin(_mock("vulnerable")).run({"id": "c"})
    assert f.r155_vector_id == "R155-5.7"
    assert f.impact_safety == "critical"
    assert f.is_critical_safety()


def test_lidar_spoof_matrix():
    assert LidarSpoofPlugin(_mock("vulnerable")).run({"id": "lidar_front"}).status == "vulnerable"
    assert LidarSpoofPlugin(_mock("secure")).run({"id": "lidar_front"}).status == "not_vulnerable"


def test_lidar_spoof_empty_mode_rejected():
    # empty modda inject_lidar_spoof her iki senaryoda da False döner → not_vulnerable
    f = LidarSpoofPlugin(_mock("empty")).run({"id": "lidar_front"})
    assert f.status == "not_vulnerable"


def test_lidar_spoof_remove_scenario_is_critical():
    f = LidarSpoofPlugin(_mock("vulnerable")).run({"id": "lidar_front"})
    assert f.impact_safety == "critical"
    assert f.is_critical_safety()


def test_v2x_spoof_matrix():
    assert V2XSpoofPlugin(_mock("vulnerable")).run({"id": "v2x_unit"}).status == "vulnerable"
    assert V2XSpoofPlugin(_mock("secure")).run({"id": "v2x_unit"}).status == "not_vulnerable"
    assert V2XSpoofPlugin(_mock("empty")).run({"id": "v2x_unit"}).status == "not_vulnerable"


def test_v2x_spoof_carries_taxonomy_when_vulnerable():
    f = V2XSpoofPlugin(_mock("vulnerable")).run({"id": "v2x_unit"})
    assert f.r155_vector_id == "R155-2.7"
    assert f.r155_category == 2
    assert f.impact_safety == "high"
    assert f.is_vulnerable()


def test_v2x_spoof_inconclusive_when_adapter_unsupported():
    # Ham base adapter inject_v2x_message'i desteklemez -> NotImplementedError -> inconclusive
    from adapters.base_adapter import BaseAdapter

    class _BareAdapter(BaseAdapter):
        adapter_type = "bare"

        def connect(self):
            self._connected = True
            return True

        def disconnect(self):
            self._connected = False

        def is_connected(self):
            return self._connected

    bare = _BareAdapter({})
    bare.connect()
    f = V2XSpoofPlugin(bare).run({"id": "v2x_unit"})
    assert f.status == "inconclusive"


def test_base_plugin_is_abstract():
    with pytest.raises(TypeError):
        BasePlugin(_mock())  # abstract run() → örneklenemez


# ── Orchestrator ─────────────────────────────────────────────────────────────

def test_orchestrator_discovers_all_plugins():
    orch = Orchestrator(_mock(), FindingStore(db_path=":memory:"), strict_adapter=False)
    classes = orch.discover_plugin_classes()
    ids = {c.module_id for c in classes}
    assert {"can-replay", "can-fuzz", "ros2-topic-enum", "ros2-topic-injection",
            "gps-spoof", "obd2-enum", "lidar-spoof", "v2x-spoof"} <= ids


def test_orchestrator_run_persists_findings(tmp_path, profile):
    db = FindingStore(db_path=str(tmp_path / "run.db"))
    orch = Orchestrator(_mock("vulnerable"), db, strict_adapter=False)
    findings = orch.run_all(profile)
    assert len(findings) >= 7
    assert all(isinstance(f, Finding) for f in findings)
    stored = db.get_findings(vehicle_profile_id="shuttle-test")
    assert len(stored) == len(findings)


def test_orchestrator_vulnerable_profile_flags_risks(tmp_path, profile):
    db = FindingStore(db_path=str(tmp_path / "run.db"))
    orch = Orchestrator(_mock("vulnerable"), db, strict_adapter=False)
    orch.run_all(profile)
    cov = db.get_compliance_coverage("shuttle-test")
    assert cov["vulnerable"] >= 7


def test_orchestrator_secure_profile_no_vulns(tmp_path, profile):
    db = FindingStore(db_path=str(tmp_path / "run.db"))
    orch = Orchestrator(_mock("secure"), db, strict_adapter=False)
    orch.run_all(profile)
    cov = db.get_compliance_coverage("shuttle-test")
    assert cov["vulnerable"] == 0


def test_orchestrator_strict_adapter_skips_mismatch(tmp_path, profile):
    # strict + saf 'mock' tipi → hiçbir plugin'in applicable_adapters'ı 'mock' değil
    db = FindingStore(db_path=str(tmp_path / "run.db"))
    orch = Orchestrator(_mock("vulnerable"), db, strict_adapter=True)
    findings = orch.run_all(profile)
    assert all(f.status == "inconclusive" for f in findings)


# ── Rapor Üretici ─────────────────────────────────────────────────────────────

def _sample_finding(**overrides):
    base = {
        "component_id": "gateway_ecu",
        "test_module_id": "can-replay",
        "r155_vector_id": "R155-2.5",
        "r155_category": 2,
        "status": "vulnerable",
        "title": "CAN Replay: Kimlik doğrulama YOK",
        "description": "Açıklama metni.",
        "impact_safety": "high",
        "impact_financial": "none",
        "impact_operational": "medium",
        "impact_privacy": "none",
        "attack_feasibility": "medium",
        "remediation": "SecOC uygula.",
    }
    base.update(overrides)
    return base


def test_report_generates_valid_docx_bytes():
    profile = {"id": "p1", "name": "Test Shuttle", "architecture": "zonal"}
    findings = [_sample_finding()]
    coverage = {"total": 1, "vulnerable": 1, "not_vulnerable": 0, "vectors_tested": 1}

    docx_bytes = generate_compliance_report(profile, findings, coverage)
    assert isinstance(docx_bytes, bytes)
    assert len(docx_bytes) > 1000  # boş/bozuk dosya değil

    # python-docx ile tekrar açılabiliyor mu (dosya bütünlüğü kontrolü)
    doc = Document(BytesIO(docx_bytes))
    assert len(doc.paragraphs) > 0


def test_report_contains_key_sections():
    profile = {"id": "p1", "name": "Test Shuttle", "architecture": "zonal"}
    findings = [_sample_finding()]
    coverage = {"total": 1, "vulnerable": 1, "not_vulnerable": 0, "vectors_tested": 1}

    docx_bytes = generate_compliance_report(profile, findings, coverage)
    doc = Document(BytesIO(docx_bytes))
    full_text = "\n".join(p.text for p in doc.paragraphs)

    assert "Yönetici Özeti" in full_text
    assert "Metodoloji" in full_text
    assert "Annex 5 Kapsam" in full_text
    assert "Test Shuttle" in full_text


def test_report_handles_empty_findings():
    profile = {"id": "p1", "name": "Bos Profil"}
    coverage = {"total": 0, "vulnerable": 0, "not_vulnerable": 0, "vectors_tested": 0}

    docx_bytes = generate_compliance_report(profile, [], coverage)
    doc = Document(BytesIO(docx_bytes))
    full_text = "\n".join(p.text for p in doc.paragraphs)
    assert "henüz kaydedilmiş bulgu bulunmamaktadır" in full_text


def test_report_deduplicates_repeated_findings_across_components():
    # Aynı bulgu (aynı vektör+başlık+açıklama) dört farklı bileşende tekrarlanıyor;
    # rapor bunu TEK blok olarak, bileşenleri gruplayarak göstermeli.
    findings = [
        _sample_finding(
            component_id=comp, r155_vector_id="R155-2.9",
            title="LiDAR Spoof: 2/2 senaryo başarılı",
            description="Ortak açıklama metni.", impact_safety="critical",
        )
        for comp in ["lidar_front", "lidar_rear", "camera_front", "radar_front"]
    ]
    profile = {"id": "p1", "name": "Test Shuttle"}
    coverage = {"total": 4, "vulnerable": 4, "not_vulnerable": 0, "vectors_tested": 1}

    docx_bytes = generate_compliance_report(profile, findings, coverage)
    doc = Document(BytesIO(docx_bytes))
    full_text = "\n".join(p.text for p in doc.paragraphs)

    # Açıklama metni yalnızca BİR kez geçmeli (dört kez değil)
    assert full_text.count("Ortak açıklama metni.") == 1
    assert "lidar_front, lidar_rear, camera_front, radar_front" in full_text


def test_report_end_to_end_with_real_orchestrator(tmp_path, profile):
    db = FindingStore(db_path=str(tmp_path / "report.db"))
    orch = Orchestrator(_mock("vulnerable"), db, strict_adapter=False)
    orch.run_all(profile)

    findings = db.get_findings(vehicle_profile_id="shuttle-test")
    coverage = db.get_compliance_coverage("shuttle-test")
    profile_dict = {"id": "shuttle-test", "name": "Test Shuttle"}

    docx_bytes = generate_compliance_report(profile_dict, findings, coverage)
    doc = Document(BytesIO(docx_bytes))
    assert len(doc.tables) >= 3  # özet + bulgu + kapsam tablosu
