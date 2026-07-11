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
from core.report_generator import generate_compliance_report
from core.attack_surface import compute_component_statuses, build_attack_surface_html
from core.compliance_heatmap import build_heatmap_html
from adapters.mock_adapter import MockAdapter
from adapters.socketcan_adapter import SocketCANAdapter

st.set_page_config(
    page_title="GÖKTÜRK",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Session state ─────────────────────────────────────────────────────────────
for key, default in [
    ("authenticated", False),
    ("selected_profile", None),
    ("selected_session", None),
    ("theme", "dark"),
]:
    if key not in st.session_state:
        st.session_state[key] = default

# ── Tema CSS değişkenleri ─────────────────────────────────────────────────────
DARK_VARS = """
    --bg:           #080B0F;
    --bg-card:      #0D1117;
    --bg-card2:     #0A0D12;
    --border:       #1A2A3A;
    --border-glow:  #1A3A5C;
    --sidebar-bg:   #0A0D12;
    --accent:       #00C8FF;
    --accent2:      #0062FF;
    --text-prim:    #C8DDEF;
    --text-sec:     #7A9ABB;
    --text-muted:   #3A6A8A;
    --text-head:    #E8F4FF;
    --logo-glow:    rgba(0,200,255,0.7);
    --scan-opacity: 0.02;
    --green:        #39FF8F;
    --red:          #FF4D4D;
    --yellow:       #FFB830;
    --green-bg:     #091A09;
    --red-bg:       #1A0A0A;
    --yellow-bg:    #1A150A;
    --green-bord:   #39FF8F44;
    --red-bord:     #FF4D4D44;
    --yellow-bord:  #FFB83044;
    --info-bg:      #0A1520;
    --info-bord:    #1A3A5C;
    --info-text:    #7AA0BB;
    --code-bg:      #060A0E;
    --btn-from:     #0050B3;
    --btn-to:       #0080D0;
    --input-bg:     #0D1117;
    --input-bord:   #1A3A5C;
"""

LIGHT_VARS = """
    --bg:           #F0F4F8;
    --bg-card:      #FFFFFF;
    --bg-card2:     #F8FAFC;
    --border:       #D1DDE9;
    --border-glow:  #93C5E8;
    --sidebar-bg:   #1A2332;
    --accent:       #0062FF;
    --accent2:      #004BD6;
    --text-prim:    #2C4A6A;
    --text-sec:     #4A6A8A;
    --text-muted:   #8AABCC;
    --text-head:    #1A2332;
    --logo-glow:    rgba(0,98,255,0.5);
    --scan-opacity: 0;
    --green:        #18A84A;
    --red:          #E02020;
    --yellow:       #D97B00;
    --green-bg:     #EDFDF3;
    --red-bg:       #FEF0F0;
    --yellow-bg:    #FFF8E6;
    --green-bord:   #18A84A44;
    --red-bord:     #E0202044;
    --yellow-bord:  #D97B0044;
    --info-bg:      #EBF4FF;
    --info-bord:    #93C5E8;
    --info-text:    #2C5F8A;
    --code-bg:      #F5F7FA;
    --btn-from:     #0062FF;
    --btn-to:       #0080D0;
    --input-bg:     #FFFFFF;
    --input-bord:   #93C5E8;
"""

def get_css(theme: str) -> str:
    vars_block = DARK_VARS if theme == "dark" else LIGHT_VARS
    return f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Inter:wght@300;400;500;600;700&display=swap');

:root {{ {vars_block} }}

html, body, [class*="css"] {{
    font-family: 'Inter', sans-serif;
    background-color: var(--bg) !important;
}}

#MainMenu, footer, header {{ visibility: hidden; }}
.block-container {{ padding-top: 1.5rem !important; }}

[data-testid="stSidebar"] {{
    background: var(--sidebar-bg) !important;
    border-right: 1px solid var(--border-glow) !important;
}}
[data-testid="stSidebar"] * {{ color: #C8DDEF !important; }}

.main, .stApp {{ background-color: var(--bg) !important; }}

.gk-logo {{
    font-family: 'Share Tech Mono', monospace;
    font-size: 20px;
    color: var(--accent);
    text-shadow: 0 0 12px var(--logo-glow);
    letter-spacing: 3px;
    margin-bottom: 2px;
}}
.gk-subtitle {{
    font-size: 10px;
    color: #4A7A9B;
    letter-spacing: 1.5px;
    text-transform: uppercase;
}}
.gk-divider {{
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--accent)44, transparent);
    margin: 12px 0;
}}

.gk-page-title {{
    font-family: 'Share Tech Mono', monospace;
    font-size: 24px;
    color: var(--text-head);
    letter-spacing: 2px;
    border-left: 3px solid var(--accent);
    padding-left: 14px;
    margin-bottom: 6px;
}}
.gk-page-cap {{
    font-size: 12px;
    color: var(--text-muted);
    letter-spacing: 1px;
    margin-bottom: 20px;
    padding-left: 17px;
}}

.gk-metrics-row {{ display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }}
.gk-metric {{
    flex: 1;
    min-width: 100px;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 20px;
    position: relative;
    overflow: hidden;
    transition: border-color 0.3s;
}}
.gk-metric:hover {{ border-color: var(--accent)44; }}
.gk-metric::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, var(--m-color, var(--accent)), transparent);
}}
.gk-metric-val {{
    font-family: 'Share Tech Mono', monospace;
    font-size: 34px;
    color: var(--m-color, var(--accent));
    line-height: 1;
}}
.gk-metric-label {{
    font-size: 10px;
    color: var(--text-muted);
    letter-spacing: 1px;
    text-transform: uppercase;
    margin-top: 4px;
}}

.badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-family: 'Share Tech Mono', monospace;
    letter-spacing: 1px;
    font-weight: 600;
    white-space: nowrap;
}}
.badge-vuln   {{ background: var(--red-bg);    color: var(--red);    border: 1px solid var(--red-bord); }}
.badge-clean  {{ background: var(--green-bg);  color: var(--green);  border: 1px solid var(--green-bord); }}
.badge-unk    {{ background: var(--yellow-bg); color: var(--yellow); border: 1px solid var(--yellow-bord); }}

.gk-finding {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 10px;
    border-left: 3px solid var(--f-color, var(--border));
    transition: background 0.2s;
}}
.gk-finding:hover {{ background: var(--bg-card2); }}
.gk-finding-title {{ font-size: 14px; font-weight: 600; color: var(--text-head); }}
.gk-finding-meta {{
    font-size: 11px;
    color: var(--text-muted);
    margin-top: 4px;
    font-family: 'Share Tech Mono', monospace;
}}
.gk-finding-desc {{ font-size: 12px; color: var(--text-sec); margin-top: 8px; line-height: 1.5; }}
.gk-remediation {{
    background: var(--green-bg);
    border: 1px solid var(--green-bord);
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 12px;
    color: var(--green);
    margin-top: 8px;
}}

.gk-progress-row {{ margin-bottom: 14px; }}
.gk-progress-label {{
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    color: var(--text-sec);
    margin-bottom: 5px;
    display: flex;
    justify-content: space-between;
}}
.gk-progress-track {{
    height: 6px;
    background: var(--border);
    border-radius: 3px;
    overflow: hidden;
}}
.gk-progress-fill {{
    height: 100%;
    border-radius: 3px;
    transition: width 0.6s ease;
}}

.gk-comp {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 16px;
    margin-bottom: 8px;
    transition: border-color 0.2s;
}}
.gk-comp:hover {{ border-color: var(--accent)44; }}
.gk-comp-name {{ font-size: 13px; font-weight: 600; color: var(--text-head); }}
.gk-comp-cat {{ font-size: 10px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 2px; }}
.gk-tag {{
    display: inline-block;
    background: var(--bg-card2);
    border: 1px solid var(--border);
    color: var(--text-sec);
    padding: 1px 7px;
    border-radius: 3px;
    font-size: 10px;
    margin: 2px 2px 0 0;
    font-family: 'Share Tech Mono', monospace;
}}

.gk-login-box {{
    background: var(--bg-card);
    border: 1px solid var(--border-glow);
    border-radius: 16px;
    padding: 48px 40px;
    width: 100%;
    max-width: 380px;
    box-shadow: 0 0 60px color-mix(in srgb, var(--accent) 10%, transparent);
    text-align: center;
    margin: 0 auto;
}}
.gk-logo-big {{
    font-family: 'Share Tech Mono', monospace;
    font-size: 38px;
    color: var(--accent);
    text-shadow: 0 0 30px var(--logo-glow);
    letter-spacing: 6px;
    margin-bottom: 4px;
    animation: pulse 3s ease-in-out infinite;
}}
@keyframes pulse {{
    0%,100% {{ text-shadow: 0 0 30px var(--logo-glow); }}
    50%      {{ text-shadow: 0 0 60px var(--logo-glow), 0 0 100px var(--logo-glow); }}
}}
.gk-logo-sub {{
    font-size: 11px;
    color: var(--text-muted);
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 32px;
}}

.stApp::after {{
    content: '';
    position: fixed;
    top: 0; left: 0; width: 100%; height: 100%;
    background: repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,var(--scan-opacity)) 2px,rgba(0,0,0,var(--scan-opacity)) 4px);
    pointer-events: none;
    z-index: 9999;
}}

.stAlert {{
    background: var(--info-bg) !important;
    border: 1px solid var(--info-bord) !important;
    color: var(--info-text) !important;
    border-radius: 8px !important;
}}
.stCodeBlock {{
    background: var(--code-bg) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
}}
.stButton > button {{
    background: linear-gradient(135deg, var(--btn-from), var(--btn-to)) !important;
    border: none !important;
    color: white !important;
    font-family: 'Share Tech Mono', monospace !important;
    letter-spacing: 1px !important;
    border-radius: 8px !important;
    transition: box-shadow 0.2s !important;
}}
.stButton > button:hover {{
    box-shadow: 0 0 20px color-mix(in srgb, var(--accent) 40%, transparent) !important;
}}
[data-testid="stFileUploader"] {{
    background: var(--bg-card);
    border: 1px dashed var(--border-glow);
    border-radius: 8px;
}}
input, .stTextInput input, .stSelectbox select {{
    background: var(--input-bg) !important;
    border: 1px solid var(--input-bord) !important;
    color: var(--text-head) !important;
    border-radius: 8px !important;
}}
</style>
"""

st.markdown(get_css(st.session_state.theme), unsafe_allow_html=True)

# ── Login ─────────────────────────────────────────────────────────────────────
def login_screen():
    st.markdown("<br><br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        st.markdown("""
        <div class="gk-login-box">
            <div class="gk-logo-big">GÖKTÜRK</div>
            <div class="gk-logo-sub">Otonom Araç Siber Test Platformu</div>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        pwd = st.text_input("", type="password", placeholder="Erişim Anahtarı",
                            label_visibility="collapsed")
        if st.button("▶  SİSTEME GİR", use_container_width=True, type="primary"):
            if pwd == os.getenv("GOKTÜRK_PASSWORD", "goktürk2026"):
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error("⛔  Hatalı erişim anahtarı.")
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<p style="text-align:center;font-size:10px;color:var(--text-muted);letter-spacing:2px;">UN R155 · ISO 21434 UYUMLU</p>', unsafe_allow_html=True)

if not st.session_state.authenticated:
    login_screen()
    st.stop()

# ── Veritabanı ────────────────────────────────────────────────────────────────
db = FindingStore()

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div class="gk-logo">⬡ GÖKTÜRK</div>', unsafe_allow_html=True)
    st.markdown('<div class="gk-subtitle">Siber Test Platformu v0.1</div>', unsafe_allow_html=True)
    st.markdown('<div class="gk-divider"></div>', unsafe_allow_html=True)

    pages = {
        "🚌  Araç Seçimi":     "vehicle",
        "🗺️  Saldırı Yüzeyi": "surface",
        "⚡  Test Çalıştır":   "run",
        "📋  Bulgular":        "findings",
        "📊  Uyumluluk":       "compliance",
        "📄  Raporlama":       "report",
    }
    page = st.radio("NAV", list(pages.keys()), label_visibility="collapsed")
    page_id = pages[page]

    st.markdown('<div class="gk-divider"></div>', unsafe_allow_html=True)

    is_dark = st.session_state.theme == "dark"
    if st.button("☀️  Açık Tema" if is_dark else "🌙  Koyu Tema", use_container_width=True):
        st.session_state.theme = "light" if is_dark else "dark"
        st.rerun()

    st.markdown('<div class="gk-divider"></div>', unsafe_allow_html=True)

    if st.session_state.selected_profile:
        st.markdown('<div style="font-size:10px;color:#3A6A8A;letter-spacing:1px;">AKTİF ARAÇ</div>', unsafe_allow_html=True)
        st.markdown(f'<div style="font-size:12px;color:#00C8FF;font-family:monospace;">{st.session_state.selected_profile}</div>', unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)

    if st.button("⬅  Çıkış", use_container_width=True):
        st.session_state.authenticated = False
        st.rerun()

# ── Yardımcılar ───────────────────────────────────────────────────────────────
def page_header(icon, title, caption=""):
    st.markdown(f'<div class="gk-page-title">{icon} {title}</div>', unsafe_allow_html=True)
    if caption:
        st.markdown(f'<div class="gk-page-cap">{caption}</div>', unsafe_allow_html=True)

def metric_card(value, label, color):
    return (
        f'<div class="gk-metric" style="--m-color:{color}">'
        f'<div class="gk-metric-val">{value}</div>'
        f'<div class="gk-metric-label">{label}</div>'
        f'</div>'
    )

# ── Araç Seçimi ───────────────────────────────────────────────────────────────
if page_id == "vehicle":
    page_header("🚌", "ARAÇ SEÇİMİ", "Test edilecek otonom araç profilini seç veya yükle")

    col_list, col_upload = st.columns([3, 1])
    with col_upload:
        st.markdown("**Profil Yükle**")
        uploaded = st.file_uploader("", type=["yaml", "yml"], label_visibility="collapsed")
        if uploaded:
            try:
                content = uploaded.read().decode("utf-8")
                profile = yaml.safe_load(content)
                db.save_profile(profile["id"], profile["name"], content)
                st.success(f"✅ Yüklendi: {profile['name']}")
                st.rerun()
            except Exception as e:
                st.error(f"❌ Hata: {e}")

    with col_list:
        profiles = db.get_profiles()
        if not profiles:
            st.markdown("""
            <div style="background:var(--bg-card);border:1px dashed var(--border-glow);border-radius:10px;padding:40px;text-align:center;color:var(--text-muted);">
                <div style="font-size:32px;margin-bottom:8px;">🚗</div>
                <div style="font-family:monospace;letter-spacing:1px;">Araç profili bulunamadı</div>
                <div style="font-size:11px;margin-top:6px;">Sağdan .yaml profil yükle veya<br><code>profiles/shuttle_example.yaml</code> ile başla</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            for p in profiles:
                c1, c2 = st.columns([4, 1])
                c1.markdown(f"""
                <div class="gk-comp">
                    <div class="gk-comp-name">🚌 {p['name']}</div>
                    <div class="gk-comp-cat" style="margin-top:4px;font-family:monospace;">{p['id']}</div>
                </div>
                """, unsafe_allow_html=True)
                if c2.button("SEÇ", key=f"sel_{p['id']}", use_container_width=True):
                    st.session_state.selected_profile = p["id"]
                    st.success(f"✅ {p['name']} aktif edildi.")

# ── Saldırı Yüzeyi ────────────────────────────────────────────────────────────
elif page_id == "surface":
    page_header("🗺️", "SALDIRI YÜZEYİ", "Araç bileşenleri ve tehdit vektörleri")

    if not st.session_state.selected_profile:
        st.warning("⚠️  Önce Araç Seçimi sayfasından bir araç seç.")
    else:
        prof = db.get_profile(st.session_state.selected_profile)
        if prof:
            data = yaml.safe_load(prof["profile_yaml"])
            components = data.get("components", [])
            findings = db.get_findings(vehicle_profile_id=st.session_state.selected_profile)
            statuses = compute_component_statuses(components, findings)

            vuln_count    = sum(1 for s in statuses.values() if s == "vulnerable")
            clean_count   = sum(1 for s in statuses.values() if s == "clean")
            untested_count = sum(1 for s in statuses.values() if s == "not_tested")

            st.markdown(
                '<div class="gk-metrics-row">'
                + metric_card(data["name"],      "Araç",              "var(--text-prim)")
                + metric_card(data.get("architecture","—"), "Mimari",  "var(--text-prim)")
                + metric_card(vuln_count,         "Zafiyetli",         "var(--red)")
                + metric_card(clean_count,        "Temiz",             "var(--green)")
                + metric_card(untested_count,     "Test Edilmedi",     "var(--yellow)")
                + '</div>',
                unsafe_allow_html=True
            )

            # 3B / interaktif saldırı yüzeyi haritası
            html = build_attack_surface_html(data.get("name", ""), components, statuses)
            st.components.v1.html(html, height=520, scrolling=False)
            st.caption("Sahneyi fare ile döndür/yakınlaştır; bir bileşene tıklayınca altındaki panelde detayları görürsün.")

            st.markdown('<div class="gk-divider"></div>', unsafe_allow_html=True)
            st.markdown("**Bileşen Tablosu**")

            status_map = {
                "not_tested": ("badge-unk",  "TEST EDİLMEDİ"),
                "clean":      ("badge-clean","TEMİZ"),
                "vulnerable": ("badge-vuln", "ZAFİYETLİ"),
            }
            for comp in components:
                status = statuses.get(comp.get("id"), "not_tested")
                badge_cls, badge_text = status_map.get(status, ("badge-unk", status.upper()))
                surfaces = " ".join([f'<span class="gk-tag">{s}</span>' for s in comp.get("attack_surfaces", [])])
                vectors  = " ".join([f'<span class="gk-tag">{v}</span>' for v in comp.get("r155_vectors", [])])
                st.markdown(f"""
                <div class="gk-comp">
                    <div style="display:flex;justify-content:space-between;align-items:flex-start;">
                        <div>
                            <div class="gk-comp-name">{comp['label']}</div>
                            <div class="gk-comp-cat">{comp['category']}</div>
                        </div>
                        <span class="badge {badge_cls}">{badge_text}</span>
                    </div>
                    <div style="margin-top:10px;">
                        <div style="font-size:10px;color:var(--text-muted);letter-spacing:1px;margin-bottom:4px;">SALDIRI YÜZEYLERİ</div>
                        {surfaces if surfaces else '<span class="gk-tag">—</span>'}
                    </div>
                    <div style="margin-top:8px;">
                        <div style="font-size:10px;color:var(--text-muted);letter-spacing:1px;margin-bottom:4px;">R155 VEKTÖRLERİ</div>
                        {vectors if vectors else '<span class="gk-tag">—</span>'}
                    </div>
                </div>
                """, unsafe_allow_html=True)

# ── Test Çalıştır ─────────────────────────────────────────────────────────────
elif page_id == "run":
    page_header("⚡", "TEST ÇALIŞTIR", "Güvenlik modüllerini seç ve çalıştır")

    if not st.session_state.selected_profile:
        st.warning("⚠️  Önce Araç Seçimi sayfasından bir araç seç.")
    else:
        prof_row = db.get_profile(st.session_state.selected_profile)
        if not prof_row:
            st.error("Seçili profil bulunamadı.")
        else:
            profile_yaml_text = prof_row["profile_yaml"]
            profile_dict = yaml.safe_load(profile_yaml_text)
            profile_dict["_yaml"] = profile_yaml_text

            st.markdown(f"""
            <div class="gk-comp" style="margin-bottom:16px;">
                <div class="gk-comp-name">🎯 {profile_dict.get('name', profile_dict.get('id'))}</div>
                <div class="gk-comp-cat">{len(profile_dict.get('components', []))} bileşen tanımlı</div>
            </div>
            """, unsafe_allow_html=True)

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
                        "secure":     "Güvenli (demo)",
                        "empty":      "Sessiz / erişilemez (demo)",
                    }[m],
                )
                st.caption("Demo modunda adaptör tipi kontrolü gevşetilir; tüm plugin'ler bileşenlere karşı çalıştırılır.")
                strict = False

                def _make_adapter(mode=mode):
                    return MockAdapter({"mode": mode})
            else:
                iface = st.text_input("CAN arayüzü", value="vcan0")
                st.caption("Gerçek modda yalnızca SocketCAN uyumlu plugin'ler çalışır. vcan0/ICSim'in ayakta olması gerekir.")
                strict = True

                def _make_adapter(iface=iface):
                    return SocketCANAdapter({"interface": iface})

            notes = st.text_input("Oturum notu (opsiyonel)", value="")

            if st.button("▶  Testleri Çalıştır", type="primary"):
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
                    st.success(f"✅ {len(findings)} test tamamlandı — {vuln} zafiyetli bulgu.")

                    color_map = {
                        "vulnerable":     ("var(--red)",   "🔴", "badge-vuln",  "ZAFİYETLİ"),
                        "not_vulnerable": ("var(--green)", "🟢", "badge-clean", "TEMİZ"),
                        "inconclusive":   ("var(--yellow)","🟡", "badge-unk",   "BELİRSİZ"),
                        "error":          ("#888888",      "⚫", "badge-unk",   "HATA"),
                    }
                    for f in findings:
                        fc, icon, badge_cls, badge_text = color_map.get(f.status, ("#555","⚪","badge-unk",f.status.upper()))
                        rem = f'<div class="gk-remediation">💡 {f.remediation}</div>' if f.remediation else ""
                        st.markdown(f"""
                        <div class="gk-finding" style="--f-color:{fc}">
                            <div style="display:flex;justify-content:space-between;align-items:flex-start;">
                                <div class="gk-finding-title">{icon} {f.title}</div>
                                <span class="badge {badge_cls}">{badge_text}</span>
                            </div>
                            <div class="gk-finding-meta">
                                R155: {f.r155_vector_id or '—'} &nbsp;|&nbsp;
                                Bileşen: {f.component_id} &nbsp;|&nbsp;
                                Fizibilite: {f.attack_feasibility}
                            </div>
                            <div class="gk-finding-desc">{f.description}</div>
                            {rem}
                        </div>
                        """, unsafe_allow_html=True)

                    st.caption("Sonuçlar 'Bulgular' ve 'Uyumluluk' sayfalarına kaydedildi.")

# ── Bulgular ─────────────────────────────────────────────────────────────────
elif page_id == "findings":
    page_header("📋", "BULGULAR", "Tespit edilen güvenlik açıkları")

    findings = db.get_findings(vehicle_profile_id=st.session_state.selected_profile)

    if not findings:
        st.markdown("""
        <div style="background:var(--bg-card);border:1px dashed var(--border-glow);border-radius:10px;padding:40px;text-align:center;color:var(--text-muted);">
            <div style="font-size:32px;margin-bottom:8px;">🔍</div>
            <div style="font-family:monospace;letter-spacing:1px;">Henüz bulgu yok</div>
            <div style="font-size:11px;margin-top:6px;">Test çalıştırdıktan sonra bulgular burada görünür</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        vuln  = sum(1 for f in findings if f["status"] == "vulnerable")
        clean = sum(1 for f in findings if f["status"] == "not_vulnerable")
        incon = len(findings) - vuln - clean

        st.markdown(
            '<div class="gk-metrics-row">'
            + metric_card(len(findings), "Toplam Bulgu", "var(--text-prim)")
            + metric_card(vuln,          "Zafiyetli",    "var(--red)")
            + metric_card(clean,         "Temiz",        "var(--green)")
            + metric_card(incon,         "Belirsiz",     "var(--yellow)")
            + '</div>',
            unsafe_allow_html=True
        )

        color_map = {
            "vulnerable":     ("var(--red)",   "🔴", "badge-vuln",  "ZAFİYETLİ"),
            "not_vulnerable": ("var(--green)", "🟢", "badge-clean", "TEMİZ"),
            "inconclusive":   ("var(--yellow)","🟡", "badge-unk",   "BELİRSİZ"),
            "error":          ("#888888",      "⚫", "badge-unk",   "HATA"),
        }
        for f in findings:
            fc, icon, badge_cls, badge_text = color_map.get(f["status"], ("#555","⚪","badge-unk",f["status"].upper()))
            rem = f'<div class="gk-remediation">💡 {f["remediation"]}</div>' if f.get("remediation") else ""
            st.markdown(f"""
            <div class="gk-finding" style="--f-color:{fc}">
                <div style="display:flex;justify-content:space-between;align-items:flex-start;">
                    <div class="gk-finding-title">{icon} {f['title']}</div>
                    <span class="badge {badge_cls}">{badge_text}</span>
                </div>
                <div class="gk-finding-meta">
                    R155: {f.get('r155_vector_id','—')} &nbsp;|&nbsp;
                    Bileşen: {f['component_id']} &nbsp;|&nbsp;
                    Fizibilite: {f.get('attack_feasibility','—')}
                </div>
                <div class="gk-finding-desc">{f['description']}</div>
                {rem}
            </div>
            """, unsafe_allow_html=True)

# ── Uyumluluk ─────────────────────────────────────────────────────────────────
elif page_id == "compliance":
    page_header("📊", "UYUMLULUK", "UN R155 Annex 5 — Vektör kapsam durumu")

    coverage  = db.get_compliance_coverage(st.session_state.selected_profile)
    total     = coverage["total"]
    vuln      = coverage["vulnerable"]
    clean     = coverage["not_vulnerable"]
    tested    = coverage["vectors_tested"]
    score_pct = int((tested / 69) * 100) if tested else 0
    vuln_pct  = int((vuln / total) * 100) if total else 0

    st.markdown(
        '<div class="gk-metrics-row">'
        + metric_card(f"{score_pct}%", "Kapsam Skoru",  "var(--accent)")
        + metric_card(total,           "Toplam Bulgu",   "var(--text-prim)")
        + metric_card(vuln,            "Zafiyetli",      "var(--red)")
        + metric_card(clean,           "Temiz",          "var(--green)")
        + metric_card(f"{tested}<span style='font-size:14px;opacity:0.5'>/69</span>",
                      "Test Edilen Vektörler", "var(--accent)")
        + '</div>',
        unsafe_allow_html=True
    )

    st.markdown("<br>", unsafe_allow_html=True)
    for label, pct, c1, c2 in [
        ("Kapsam",        score_pct,                       "var(--accent)", "var(--accent2)"),
        ("Zafiyet Oranı", vuln_pct,                        "var(--red)",    "#C00000"),
        ("Başarı Oranı",  (100 - vuln_pct) if total else 0,"var(--green)",  "#008830"),
    ]:
        st.markdown(f"""
        <div class="gk-progress-row">
            <div class="gk-progress-label"><span>{label}</span><span>{pct}%</span></div>
            <div class="gk-progress-track">
                <div class="gk-progress-fill" style="width:{pct}%;background:linear-gradient(90deg,{c1},{c2});"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    if coverage["by_vector"]:
        st.markdown("<br>", unsafe_allow_html=True)
        with st.expander("📂 Vektör Bazlı Ham Veri"):
            st.json(coverage["by_vector"])

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<div class="gk-page-title" style="font-size:16px;">🗺️ Annex 5 Isı Haritası (69 Vektör)</div>',
                unsafe_allow_html=True)
    findings_all = db.get_findings(vehicle_profile_id=st.session_state.selected_profile)
    st.markdown(build_heatmap_html(findings_all), unsafe_allow_html=True)

# ── Raporlama ─────────────────────────────────────────────────────────────────
elif page_id == "report":
    page_header("📄", "RAPORLAMA", "ISO 21434 / UN R155 uyumlu rapor oluştur")

    if not st.session_state.selected_profile:
        st.warning("⚠️  Önce Araç Seçimi sayfasından bir araç seç.")
    else:
        prof_row = db.get_profile(st.session_state.selected_profile)
        findings = db.get_findings(vehicle_profile_id=st.session_state.selected_profile)
        coverage = db.get_compliance_coverage(st.session_state.selected_profile)

        if not findings:
            st.markdown("""
            <div style="background:var(--bg-card);border:1px dashed var(--border-glow);border-radius:10px;padding:40px;text-align:center;color:var(--text-muted);">
                <div style="font-size:32px;margin-bottom:8px;">📄</div>
                <div style="font-family:monospace;letter-spacing:1px;">Henüz bulgu yok</div>
                <div style="font-size:11px;margin-top:6px;">Önce 'Test Çalıştır' sayfasından bir test oturumu başlat</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div class="gk-comp" style="margin-bottom:16px;">
                <div class="gk-comp-name">📊 Rapor Kapsamı</div>
                <div class="gk-comp-cat" style="margin-top:4px;">
                    {len(findings)} bulgu · {coverage['vectors_tested']}/69 R155 vektörü
                </div>
            </div>
            """, unsafe_allow_html=True)

            c1, c2 = st.columns(2)
            with c1:
                if st.button("📄  Word Raporu Oluştur (.docx)", type="primary", use_container_width=True):
                    profile_dict = yaml.safe_load(prof_row["profile_yaml"]) if prof_row else {
                        "id": st.session_state.selected_profile,
                        "name": st.session_state.selected_profile,
                    }
                    with st.spinner("ISO 21434 / UN R155 raporu oluşturuluyor..."):
                        docx_bytes = generate_compliance_report(profile_dict, findings, coverage)
                    st.session_state["_report_docx"] = docx_bytes
                    st.success("✅ Rapor hazır — aşağıdan indirebilirsin.")

            if st.session_state.get("_report_docx"):
                st.download_button(
                    "⬇  goktürk_uyumluluk_raporu.docx",
                    data=st.session_state["_report_docx"],
                    file_name="goktürk_uyumluluk_raporu.docx",
                    mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    use_container_width=True,
                )

            with c2:
                st.download_button(
                    "⬇  Ham Veriyi JSON Olarak İndir",
                    data=json.dumps(findings, ensure_ascii=False, indent=2),
                    file_name="goktürk_findings.json",
                    mime="application/json",
                    use_container_width=True,
                )
