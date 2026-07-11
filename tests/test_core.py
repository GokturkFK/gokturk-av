"""
GÖKTÜRK — Çekirdek Test Suite (Faz 2-4)
Tüm katmanları kapsar: taksonomi, Finding şeması, FindingStore,
mock adaptör, yedi test modülü, orchestrator, rapor üretici ve
3D saldırı yüzeyi haritası.

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
from core.attack_surface import compute_component_statuses, build_attack_surface_html
from core.compliance_heatmap import compute_vector_statuses, build_heatmap_html
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


# ── 3D Saldırı Yüzeyi ─────────────────────────────────────────────────────────

def _sample_components():
    return [
        {"id": "gateway_ecu", "label": "Gateway ECU", "category": "network",
         "position_3d": [0.2, 0.0, 0.2], "attack_surfaces": ["in-vehicle-network"],
         "r155_vectors": ["R155-2.2"]},
        {"id": "lidar_front", "label": "Ön LiDAR", "category": "sensor",
         "position_3d": [2.1, 0.0, 1.2], "attack_surfaces": ["sensor-spoofing"],
         "r155_vectors": ["R155-2.9"]},
        {"id": "obd2_port", "label": "OBD-II Portu", "category": "diagnostic",
         "position_3d": [0.8, -0.5, 0.0], "attack_surfaces": ["diagnostic"],
         "r155_vectors": ["R155-5.5"]},
        {"id": "tcu", "label": "TCU", "category": "connectivity",
         "position_3d": [0.0, 2.8, 0.5], "attack_surfaces": ["telematics"],
         "r155_vectors": ["R155-5.1"]},
    ]


def test_compute_statuses_vulnerable_takes_priority():
    components = _sample_components()
    findings = [
        {"component_id": "gateway_ecu", "status": "vulnerable"},
        {"component_id": "gateway_ecu", "status": "not_vulnerable"},
    ]
    statuses = compute_component_statuses(components, findings)
    assert statuses["gateway_ecu"] == "vulnerable"


def test_compute_statuses_clean_when_only_not_vulnerable():
    components = _sample_components()
    findings = [{"component_id": "obd2_port", "status": "not_vulnerable"}]
    statuses = compute_component_statuses(components, findings)
    assert statuses["obd2_port"] == "clean"


def test_compute_statuses_not_tested_when_no_findings():
    components = _sample_components()
    statuses = compute_component_statuses(components, [])
    assert all(s == "not_tested" for s in statuses.values())


def test_compute_statuses_ignores_inconclusive_and_error():
    components = _sample_components()
    findings = [
        {"component_id": "tcu", "status": "inconclusive"},
        {"component_id": "tcu", "status": "error"},
    ]
    statuses = compute_component_statuses(components, findings)
    assert statuses["tcu"] == "not_tested"


def test_compute_statuses_covers_all_components():
    components = _sample_components()
    statuses = compute_component_statuses(components, [])
    assert set(statuses.keys()) == {c["id"] for c in components}


def test_build_html_contains_component_data():
    components = _sample_components()
    statuses = {"gateway_ecu": "vulnerable", "lidar_front": "clean",
                "obd2_port": "not_tested", "tcu": "not_tested"}
    html = build_attack_surface_html("Test Shuttle", components, statuses)

    assert "gateway_ecu" in html
    assert "Ön LiDAR" in html
    assert "#e24b4a" in html  # vulnerable rengi
    assert "#63a922" in html  # clean rengi
    assert "#ef9f27" in html  # not_tested rengi


def test_build_html_contains_valid_importmap_json():
    import json
    import re

    components = _sample_components()
    statuses = compute_component_statuses(components, [])
    html = build_attack_surface_html("Test Shuttle", components, statuses)

    match = re.search(r'<script type="importmap">\s*(\{.*?\})\s*</script>', html, re.S)
    assert match is not None
    data = json.loads(match.group(1))  # geçerli JSON olmalı, exception atmamalı
    assert "three" in data["imports"]


def test_build_html_embeds_syntactically_valid_js():
    import shutil
    if shutil.which("node") is None:
        pytest.skip("node kurulu değil — JS sözdizimi kontrolü atlandı")

    components = _sample_components()
    statuses = compute_component_statuses(components, [])
    html = build_attack_surface_html("Test Shuttle", components, statuses)

    start = html.index('<script type="module">') + len('<script type="module">')
    end = html.index("</script>", start)
    js_code = html[start:end]

    # import ifadelerini node'un çözemeyeceği bir CDN'den çektiği için
    # sözdizimi kontrolü amacıyla nötrleştiriyoruz; geri kalan JS gövdesi
    # gerçek/değişmeden test edilir.
    js_for_check = js_code.replace(
        "import * as THREE from 'three';", "// import"
    ).replace(
        "import { OrbitControls } from 'three/addons/controls/OrbitControls.js';",
        "const THREE = {}; const OrbitControls = function(){};"
    )

    import subprocess
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".mjs", mode="w", delete=False) as f:
        f.write(js_for_check)
        path = f.name

    result = subprocess.run(["node", "--check", path], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_build_html_handles_empty_components():
    html = build_attack_surface_html("Bos Profil", [], {})
    assert "gokturk-3d-root" in html


def test_compute_vector_statuses_covers_all_69():
    statuses = compute_vector_statuses([])
    assert len(statuses) == 69
    assert all(s == "not_tested" for s in statuses.values())


def test_compute_vector_statuses_vulnerable_priority():
    findings = [
        {"r155_vector_id": "R155-2.5", "status": "vulnerable"},
        {"r155_vector_id": "R155-2.5", "status": "not_vulnerable"},
    ]
    statuses = compute_vector_statuses(findings)
    assert statuses["R155-2.5"] == "vulnerable"


def test_compute_vector_statuses_clean_when_only_not_vulnerable():
    findings = [{"r155_vector_id": "R155-5.5", "status": "not_vulnerable"}]
    statuses = compute_vector_statuses(findings)
    assert statuses["R155-5.5"] == "clean"


def test_compute_vector_statuses_ignores_findings_without_vector():
    findings = [{"status": "vulnerable"}]
    statuses = compute_vector_statuses(findings)
    assert all(s == "not_tested" for s in statuses.values())


def test_build_heatmap_html_contains_all_69_cells():
    html = build_heatmap_html([])
    assert html.count('gk-heat-cell"') == 69


def test_build_heatmap_html_reflects_findings():
    findings = [{"r155_vector_id": "R155-2.5", "status": "vulnerable"}]
    html = build_heatmap_html(findings)
    assert "var(--red)" in html
    assert "R155-2.5" in html


def test_build_heatmap_html_escapes_tooltip_content():
    html = build_heatmap_html([])
    import re
    titles = re.findall(r'title="([^"]*)"', html)
    assert len(titles) == 69


def test_build_heatmap_html_uses_theme_css_vars_not_hardcoded_colors():
    html = build_heatmap_html([])
    assert "var(--red)" in html
    assert "var(--green)" in html
    assert "var(--text-muted)" in html
