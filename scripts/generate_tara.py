"""
GÖKTÜRK — ISO/SAE 21434 TARA Belge Üreticisi
autonomous_shuttle_v1.yaml profilinden ve mevcut test modüllerinin ürettiği
bulgulardan bir Tehdit Analizi ve Risk Değerlendirmesi (TARA) belgesi türetir.

ISO 21434 TARA zinciri:
  Varlık → Zarar Senaryosu → Tehdit Senaryosu → Etki (Impact) →
  Saldırı Fizibilitesi → Risk Değeri → Risk Ele Alma Kararı

Kullanım:
    python scripts/generate_tara.py > docs/tara.md

Belge, gerçek profil + plugin verisinden üretildiği için kod/veri değiştikçe
yeniden üretilerek güncel tutulmalıdır (statik elle düzenleme YERİNE).
"""

import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# Proje kökünü import yoluna ekle (script scripts/ altından da çalışsın)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml  # noqa: E402

from adapters.mock_adapter import MockAdapter  # noqa: E402
from core.finding_store import FindingStore  # noqa: E402
from core.orchestrator import Orchestrator  # noqa: E402
from taxonomy.loader import load_taxonomy  # noqa: E402

PROFILE_PATH = "profiles/autonomous_shuttle_v1.yaml"

# ── ISO 21434 etki/fizibilite → sayısal seviye eşlemeleri ─────────────────────
_IMPACT_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_FEAS_RANK = {"unknown": 2, "low": 1, "medium": 2, "high": 3}


# Risk matrisi: max_impact (0-4) × feasibility (1-3) → risk seviyesi
# ISO 21434 Tablo benzeri; sadeleştirilmiş 4 seviyeli çıktı.
def _risk_level(max_impact_rank: int, feas_rank: int) -> str:
    score = max_impact_rank * feas_rank
    if score >= 9:
        return "Kritik"
    if score >= 6:
        return "Yüksek"
    if score >= 3:
        return "Orta"
    if score >= 1:
        return "Düşük"
    return "İhmal Edilebilir"


_RISK_TREATMENT = {
    "Kritik": "Azaltma (zorunlu) — üretim öncesi giderilmeli",
    "Yüksek": "Azaltma — sonraki sürüm hedefiyle giderilmeli",
    "Orta": "Azaltma / Kabul — risk sahibi kararı",
    "Düşük": "İzleme — kabul edilebilir, dokümante et",
    "İhmal Edilebilir": "Kabul",
}

_CATEGORY_TR = {
    "network": "Ağ",
    "compute": "Hesaplama",
    "sensor": "Algı/Sensör",
    "diagnostic": "Teşhis",
    "connectivity": "Bağlanabilirlik",
    "physical": "Fiziksel",
    "ev-charging": "EV Şarj",
}


def _load_profile():
    raw = open(PROFILE_PATH, encoding="utf-8").read()
    prof = yaml.safe_load(raw)
    prof["_yaml"] = raw
    return prof, raw


def _run_findings(prof, raw):
    db = FindingStore(db_path=tempfile.mktemp(suffix=".db"))
    db.save_profile(prof["id"], prof["name"], raw)
    adapter = MockAdapter({"mode": "vulnerable"})
    adapter.connect()
    orch = Orchestrator(adapter, db, strict_adapter=False)
    findings = orch.run_all(prof)
    adapter.disconnect()
    return findings


def _max_impact_rank(f) -> int:
    return max(
        _IMPACT_RANK.get(getattr(f, "impact_safety", "none") or "none", 0),
        _IMPACT_RANK.get(getattr(f, "impact_operational", "none") or "none", 0),
        _IMPACT_RANK.get(getattr(f, "impact_financial", "none") or "none", 0),
        _IMPACT_RANK.get(getattr(f, "impact_privacy", "none") or "none", 0),
    )


def _impact_summary(f) -> str:
    parts = []
    for label, attr in [("G", "impact_safety"), ("O", "impact_operational"),
                        ("F", "impact_financial"), ("M", "impact_privacy")]:
        val = getattr(f, attr, "none") or "none"
        if val != "none":
            parts.append(f"{label}:{val}")
    return ", ".join(parts) if parts else "—"


def generate() -> str:
    prof, raw = _load_profile()
    findings = _run_findings(prof, raw)
    tax = load_taxonomy()

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    components = prof["components"]

    # Yalnızca vulnerable bulgular risk tablosuna girer
    vuln = [f for f in findings if f.status == "vulnerable"]

    # Risk hesapla + sırala
    rows = []
    for f in vuln:
        mi = _max_impact_rank(f)
        fr = _FEAS_RANK.get(getattr(f, "attack_feasibility", "unknown") or "unknown", 2)
        risk = _risk_level(mi, fr)
        # ISO 21434 güvenlik tabanı: safety etkisi 'critical'/'high' olan bir tehdit,
        # saldırı fizibilitesi düşük olsa bile en az 'Yüksek' risk taşır (güvenlik
        # gözden geçirmesinde kritik etkinin gizlenmemesi için).
        safety_rank = _IMPACT_RANK.get(getattr(f, "impact_safety", "none") or "none", 0)
        if safety_rank >= 3 and risk in ("Orta", "Düşük", "İhmal Edilebilir"):
            risk = "Yüksek"
        rows.append({
            "component": f.component_id,
            "vector": f.r155_vector_id or "—",
            "threat": f.title,
            "impact": _impact_summary(f),
            "feas": getattr(f, "attack_feasibility", "unknown") or "unknown",
            "cvss": getattr(f, "cvss_score", None),
            "risk": risk,
            "treatment": _RISK_TREATMENT[risk],
        })

    risk_order = {"Kritik": 4, "Yüksek": 3, "Orta": 2, "Düşük": 1, "İhmal Edilebilir": 0}
    rows.sort(key=lambda r: (risk_order[r["risk"]], r["cvss"] or 0), reverse=True)

    out = []
    _w = out.append

    # ── Başlık ──
    _w("# Tehdit Analizi ve Risk Değerlendirmesi (TARA)")
    _w("")
    _w(f"**Öğe (Item):** {prof['name']}  ")
    _w(f"**Profil Kimliği:** `{prof['id']}`  ")
    _w(f"**Mimari:** {prof.get('architecture', '—')}  ")
    _w("**Metodoloji:** ISO/SAE 21434:2021 — Clause 15 (TARA)  ")
    _w("**Düzenleyici Çerçeve:** UN Regulation No. 155 (CSMS), Annex 5  ")
    _w(f"**Üretim Tarihi:** {now}  ")
    _w("**Üretim Yöntemi:** `scripts/generate_tara.py` — profil ve test "
       "modüllerinden otomatik türetilmiştir.")
    _w("")
    _w("> Bu belge otomatik üretilir. Profil (`" + PROFILE_PATH + "`) veya test "
       "modülleri değiştiğinde script yeniden çalıştırılarak güncellenmelidir.")
    _w("")

    # ── 1. Kapsam ──
    _w("## 1. Kapsam ve Öğe Tanımı")
    _w("")
    _w(f"Değerlendirilen öğe, **{prof['name']}** ({prof.get('architecture','—')} "
       "mimari) aracıdır. Aşağıdaki bileşen sınırları (item boundary) tanımlanmıştır:")
    _w("")
    _w("| # | Bileşen | Kategori | Ağlar | Saldırı Yüzeyleri |")
    _w("|---|---------|----------|-------|-------------------|")
    for i, c in enumerate(components, 1):
        cat = _CATEGORY_TR.get(c["category"], c["category"])
        nets = ", ".join(c.get("networks", [])) or "—"
        surfaces = ", ".join(c.get("attack_surfaces", [])) or "—"
        _w(f"| {i} | {c['label']} (`{c['id']}`) | {cat} | {nets} | {surfaces} |")
    _w("")

    # ── 2. Varlık Kataloğu ──
    _w("## 2. Varlık Kataloğu ve Siber Güvenlik Özellikleri")
    _w("")
    _w("Her bileşen bir veya daha fazla **varlık** (asset) barındırır. Korunması "
       "gereken siber güvenlik özellikleri (CIA): Gizlilik (C), Bütünlük (I), "
       "Erişilebilirlik (A).")
    _w("")
    _w("| Varlık (Bileşen) | İlgili R155 Vektörleri | Öncelikli Özellik |")
    _w("|------------------|------------------------|-------------------|")
    for c in components:
        vecs = ", ".join(c.get("r155_vectors", [])) or "—"
        prop = {
            "sensor": "Bütünlük (I)",
            "connectivity": "Gizlilik + Bütünlük (C/I)",
            "network": "Bütünlük + Erişilebilirlik (I/A)",
            "compute": "Bütünlük + Erişilebilirlik (I/A)",
            "diagnostic": "Bütünlük (I)",
        }.get(c["category"], "Bütünlük (I)")
        _w(f"| {c['label']} | {vecs} | {prop} |")
    _w("")

    # ── 3. Risk Değerlendirme Tablosu ──
    _w("## 3. Tehdit Senaryoları ve Risk Değerlendirmesi")
    _w("")
    _w("Aşağıdaki tablo, mock (vulnerable) adaptörle çalıştırılan test "
       "modüllerinin tespit ettiği tehdit senaryolarını ISO 21434 risk "
       "değerlendirmesiyle birlikte listeler. **Etki kısaltmaları:** "
       "G=Güvenlik(Safety), O=Operasyonel, F=Finansal, M=Mahremiyet(Privacy). "
       "**Risk = f(maks. etki, saldırı fizibilitesi)**; güvenlik-kritik etkiler "
       "için taban 'Yüksek' uygulanır.")
    _w("")
    _w("| Risk | Bileşen | R155 | Tehdit Senaryosu | Etki | Fizibilite | CVSS | Ele Alma |")
    _w("|------|---------|------|------------------|------|-----------|------|----------|")
    for r in rows:
        cvss = f"{r['cvss']:.1f}" if r["cvss"] is not None else "—"
        threat = r["threat"].replace("|", "\\|")
        _w(f"| **{r['risk']}** | `{r['component']}` | {r['vector']} | {threat} | "
           f"{r['impact']} | {r['feas']} | {cvss} | {r['treatment']} |")
    _w("")

    # ── 4. Risk Özeti ──
    _w("## 4. Risk Dağılımı Özeti")
    _w("")
    counts = {}
    for r in rows:
        counts[r["risk"]] = counts.get(r["risk"], 0) + 1
    _w("| Risk Seviyesi | Tehdit Sayısı | Varsayılan Ele Alma |")
    _w("|---------------|---------------|---------------------|")
    for level in ["Kritik", "Yüksek", "Orta", "Düşük", "İhmal Edilebilir"]:
        if counts.get(level):
            _w(f"| {level} | {counts[level]} | {_RISK_TREATMENT[level]} |")
    _w(f"| **Toplam** | **{len(rows)}** | — |")
    _w("")

    # ── 5. Kapsam Notu ──
    tested_vectors = sorted({f.r155_vector_id for f in findings if f.r155_vector_id})
    total_vectors = tax["total_vectors"]
    _w("## 5. Kapsam ve Kısıtlar")
    _w("")
    _w(f"- Bu TARA, mevcut **{len({f.test_module_id for f in findings})} test "
       f"modülünün** kapsadığı **{len(tested_vectors)} / {total_vectors}** "
       "R155 Annex 5 vektörünü yansıtır.")
    _w("- Kapsanan vektörler: " + ", ".join(f"`{v}`" for v in tested_vectors))
    _w("- Bulgular **mock (vulnerable) adaptörle** üretilmiştir; gerçek araç/"
       "tezgâh testi (vcan0, ICSim, CARLA) sonuçları farklılık gösterebilir.")
    _w("- Profildeki bazı bileşenler henüz plugin'i olmayan vektörler taşır "
       "(ör. `R155-6.7` adversarial ML) — bunlar bilinçli kapsam boşluğudur ve "
       "gelecek geliştirme önceliklerini işaret eder.")
    _w("")
    _w("---")
    _w("*ISO/SAE 21434:2021 ve UN R155 Annex 5 referans alınarak GÖKTÜRK-AV "
       "tarafından otomatik üretilmiştir.*")

    return "\n".join(out)


if __name__ == "__main__":
    print(generate())
