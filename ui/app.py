"""
GÖKTÜRK — Streamlit UI
Otonom Araç Siber Test Platformu — Ana Pano
"""

import streamlit as st
import sys
import os
import yaml
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.finding_store import FindingStore
from core.orchestrator import Orchestrator
from adapters.mock_adapter import MockAdapter
from adapters.socketcan_adapter import SocketCANAdapter

# ── Sayfa yapılandırması ──────────────────────────────────────────────────────
st.set_page_config(
    page_title="GÖKTÜRK",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&display=swap');

html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
[data-testid="stSidebar"] {
    background-color: #0D0D0D;
    border-right: 1px solid #1A1A1A;
}
[data-testid="stSidebar"] * { color: #E8E6E0 !important; }
.main { background-color: #111111; }

.vuln-badge   { background:#2A1010; color:#E24B4A; border:1px solid #E24B4A;
                padding:2px 8px; border-radius:4px; font-size:12px; }
.clean-badge  { background:#0F1E0A; color:#639922; border:1px solid #639922;
                padding:2px 8px; border-radius:4px; font-size:12px; }
.unknown-badge{ background:#1E1608; color:#EF9F27; border:1px solid #EF9F27;
                padding:2px 8px; border-radius:4px; font-size:12px; }
.metric-card  { background:#161616; border:1px solid #222; border-radius:8px;
                padding:1.2rem; margin-bottom:0.5rem; }
h1,h2,h3 { letter-spacing:-0.03em; color:#F0EDE8; }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ── Session state ─────────────────────────────────────────────────────────────
for key, default in [
    ("authenticated", False),
    ("selected_profile", None),
    ("selected_session", None),
]:
    if key not in st.session_state:
        st.session_state[key] = default

# ── Login ─────────────────────────────────────────────────────────────────────
def login_screen():
    st.markdown("<br><br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("## 🛡️ GÖKTÜRK")
        st.markdown("*Otonom Araç Siber Test Platformu*")
        st.divider()
        pwd = st.text_input("Erişim Anahtarı", type="password",
                            placeholder="••••••••••••")
        if st.button("Giriş", use_container_width=True, type="primary"):
            if pwd == os.getenv("GOKTÜRK_PASSWORD", "goktürk2026"):
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error("Hatalı erişim anahtarı.")

if not st.session_state.authenticated:
    login_screen()
    st.stop()

# ── Veritabanı ────────────────────────────────────────────────────────────────
db = FindingStore()

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ GÖKTÜRK")
    st.caption("Otonom Araç Siber Test")
    st.divider()

    pages = {
        "🚌 Araç Seçimi":     "vehicle",
        "🗺️  Saldırı Yüzeyi": "surface",
        "⚡ Test Çalıştır":   "run",
        "📋 Bulgular":        "findings",
        "📊 Uyumluluk":       "compliance",
        "📄 Raporlama":       "report",
    }
    page = st.radio("", list(pages.keys()), label_visibility="collapsed")
    page_id = pages[page]

    st.divider()
    if st.session_state.selected_profile:
        st.caption(f"Araç: {st.session_state.selected_profile}")
    if st.button("⬅ Çıkış", use_container_width=True):
        st.session_state.authenticated = False
        st.rerun()

# ── Araç Seçimi ───────────────────────────────────────────────────────────────
if page_id == "vehicle":
    st.markdown("## 🚌 Araç Seçimi")
    col1, col2 = st.columns([3, 1])
    with col2:
        uploaded = st.file_uploader("Profil yükle (.yaml)", type=["yaml", "yml"])
        if uploaded:
            try:
                content = uploaded.read().decode("utf-8")
                profile = yaml.safe_load(content)
                db.save_profile(profile["id"], profile["name"], content)
                st.success(f"Profil yüklendi: {profile['name']}")
                st.rerun()
            except Exception as e:
                st.error(f"Profil hatası: {e}")

    profiles = db.get_profiles()
    if not profiles:
        st.info("Henüz araç profili yok. Sağdan profil yükle veya 'profiles/shuttle_example.yaml' ile başla.")
    else:
        for p in profiles:
            c1, c2 = st.columns([4, 1])
            c1.markdown(f"**{p['name']}** `{p['id']}`")
            if c2.button("Seç", key=f"sel_{p['id']}"):
                st.session_state.selected_profile = p["id"]
                st.success(f"{p['name']} seçildi.")

# ── Saldırı Yüzeyi ────────────────────────────────────────────────────────────
elif page_id == "surface":
    st.markdown("## 🗺️ Saldırı Yüzeyi Haritası")
    if not st.session_state.selected_profile:
        st.warning("Önce Araç Seçimi sayfasından bir araç seç.")
    else:
        prof = db.get_profile(st.session_state.selected_profile)
        if prof:
            data = yaml.safe_load(prof["profile_yaml"])
            st.markdown(f"### {data['name']}")
            st.caption(f"Mimari: {data.get('architecture', '??')} | Profil: v{data.get('profile_version', '?')}")
            st.info("3B animasyonlu harita — Faz 4. Şu an bileşen tablosu:")
            components = data.get("components", [])
            for comp in components:
                status = comp.get("test_status", "not_tested")
                badge = {
                    "not_tested": "unknown-badge",
                    "clean": "clean-badge",
                    "vulnerable": "vuln-badge",
                }.get(status, "unknown-badge")
                label = {"not_tested": "Test Edilmedi",
                         "clean": "Temiz", "vulnerable": "Zafiyetli"}.get(status, status)
                with st.expander(f"{comp['label']}  — {comp['category']}"):
                    st.markdown(f"<span class='{badge}'>{label}</span>", unsafe_allow_html=True)
                    st.write("**Saldırı yüzeyleri:**", ", ".join(comp.get("attack_surfaces", [])))
                    st.write("**R155 vektörleri:**", ", ".join(comp.get("r155_vectors", [])))

# ── Test Çalıştır ─────────────────────────────────────────────────────────────
elif page_id == "run":
    st.markdown("## ⚡ Test Çalıştır")
    if not st.session_state.selected_profile:
        st.warning("Önce Araç Seçimi sayfasından bir araç seç.")
    else:
        prof_row = db.get_profile(st.session_state.selected_profile)
        if not prof_row:
            st.error("Seçili profil bulunamadı.")
        else:
            profile_yaml_text = prof_row["profile_yaml"]
            profile_dict = yaml.safe_load(profile_yaml_text)
            # Orchestrator her koşuda profili yeniden kaydeder; ham YAML'ı
            # koru ki finding_store'daki profile_yaml alanı boşa düşmesin.
            profile_dict["_yaml"] = profile_yaml_text

            st.markdown(f"**Hedef:** {profile_dict.get('name', profile_dict.get('id'))}")
            st.caption(f"{len(profile_dict.get('components', []))} bileşen tanımlı")

            adapter_choice = st.radio(
                "Adaptör",
                ["Mock (Demo — donanımsız)", "SocketCAN (gerçek / vcan0)"],
                horizontal=True,
            )

            if adapter_choice.startswith("Mock"):
                mode = st.selectbox(
                    "Mock modu",
                    ["vulnerable", "secure", "empty"],
                    format_func=lambda m: {
                        "vulnerable": "Zafiyetli (demo)",
                        "secure": "Güvenli (demo)",
                        "empty": "Sessiz / erişilemez (demo)",
                    }[m],
                )
                st.caption(
                    "Demo modunda adaptör tipi kontrolü gevşetilir; tüm plugin'ler "
                    "bileşenlere karşı çalıştırılır (gerçek donanım gerekmez)."
                )
                strict = False

                def _make_adapter(mode=mode):
                    return MockAdapter({"mode": mode})
            else:
                iface = st.text_input("CAN arayüzü", value="vcan0")
                st.caption(
                    "Gerçek modda yalnızca SocketCAN uyumlu plugin'ler çalışır "
                    "(CAN replay/fuzz, OBD-II). vcan0/ICSim'in ayakta olması gerekir."
                )
                strict = True

                def _make_adapter(iface=iface):
                    return SocketCANAdapter({"interface": iface})

            notes = st.text_input("Oturum notu (opsiyonel)", value="")

            if st.button("▶ Testleri Çalıştır", type="primary"):
                adapter = None
                try:
                    adapter = _make_adapter()
                    adapter.connect()
                except Exception as e:
                    st.error(f"Adaptör bağlantı hatası: {e}")
                else:
                    orch = Orchestrator(adapter, db, strict_adapter=strict)
                    with st.spinner("Test modülleri çalıştırılıyor..."):
                        findings = orch.run_all(profile_dict, session_notes=notes)
                    adapter.disconnect()

                    vuln = sum(1 for f in findings if f.is_vulnerable())
                    st.success(f"{len(findings)} test tamamlandı — {vuln} zafiyetli bulgu.")

                    for f in findings:
                        color = {"vulnerable": "🔴", "not_vulnerable": "🟢",
                                 "inconclusive": "🟡", "error": "⚫"}.get(f.status, "⚪")
                        with st.expander(f"{color} {f.title}"):
                            st.write(f.description)
                            c1, c2, c3 = st.columns(3)
                            c1.write(f"**R155:** {f.r155_vector_id or '—'}")
                            c2.write(f"**Bileşen:** {f.component_id}")
                            c3.write(f"**Fizibilite:** {f.attack_feasibility}")
                            if f.remediation:
                                st.info(f.remediation)

                    st.caption("Sonuçlar 'Bulgular' ve 'Uyumluluk' sayfalarına kaydedildi.")

# ── Bulgular ─────────────────────────────────────────────────────────────────
elif page_id == "findings":
    st.markdown("## 📋 Bulgular")
    findings = db.get_findings(vehicle_profile_id=st.session_state.selected_profile)
    if not findings:
        st.info("Henüz bulgu yok. Test çalıştırdıktan sonra bulgular burada görünür.")
    else:
        cols = st.columns(3)
        vuln = sum(1 for f in findings if f["status"] == "vulnerable")
        cols[0].metric("Toplam", len(findings))
        cols[1].metric("Zafiyetli", vuln)
        cols[2].metric("Temiz", len(findings) - vuln)
        st.divider()
        for f in findings:
            color = {"vulnerable": "🔴", "not_vulnerable": "🟢",
                     "inconclusive": "🟡", "error": "⚫"}.get(f["status"], "⚪")
            with st.expander(f"{color} {f['title']}"):
                st.write(f["description"])
                c1, c2, c3 = st.columns(3)
                c1.write(f"**R155:** {f.get('r155_vector_id', '—')}")
                c2.write(f"**Bileşen:** {f['component_id']}")
                c3.write(f"**Fizibilite:** {f.get('attack_feasibility', '—')}")
                if f.get("remediation"):
                    st.info(f["remediation"])

# ── Uyumluluk ─────────────────────────────────────────────────────────────────
elif page_id == "compliance":
    st.markdown("## 📊 UN R155 Uyumluluk Paneli")
    coverage = db.get_compliance_coverage(st.session_state.selected_profile)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Toplam Bulgu", coverage["total"])
    c2.metric("Zafiyetli", coverage["vulnerable"])
    c3.metric("Temiz", coverage["not_vulnerable"])
    c4.metric("Test Edilen Vektörler", f"{coverage['vectors_tested']} / 69")
    st.divider()
    st.markdown("**Annex 5 Vektör Kapsam Durumu**")
    st.info("Detaylı ısı haritası Faz 4'te gelecek. Şu an ham veri:")
    st.json(coverage["by_vector"])

# ── Raporlama ─────────────────────────────────────────────────────────────────
elif page_id == "report":
    st.markdown("## 📄 Rapor Oluştur")
    st.info(
        "ISO 21434 / UN R155 uyumlu rapor üretimi Faz 4'te devreye girecek. "
        "Çıktı: otomatik doldurulmuş docx rapor."
    )
    if st.button("Ham Veriyi JSON Olarak İndir"):
        findings = db.get_findings(vehicle_profile_id=st.session_state.selected_profile)
        st.download_button(
            "⬇ findings.json",
            data=json.dumps(findings, ensure_ascii=False, indent=2),
            file_name="goktürk_findings.json",
            mime="application/json",
        )
