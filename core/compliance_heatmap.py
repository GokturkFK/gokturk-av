"""
GÖKTÜRK — UN R155 Annex 5 Uyumluluk Isı Haritası
69 vektörün tamamı için test durumunu (vulnerable/clean/not_tested) hesaplar
ve tema-uyumlu (CSS değişkenli) bir HTML ızgara üretir.

Renkler doğrudan uygulamanın global tema CSS değişkenlerini (var(--red),
var(--green), var(--text-muted) vb.) kullanır — bu sayede koyu/açık tema
geçişinde otomatik uyum sağlar, ayrı bir tema mantığı gerekmez.
"""

import html as html_escape
from typing import Any, Dict, List

from taxonomy.loader import load_taxonomy

STATUS_VAR = {
    "vulnerable": "var(--red)",
    "clean": "var(--green)",
    "not_tested": "var(--text-muted)",
}
STATUS_BG_VAR = {
    "vulnerable": "var(--red-bg)",
    "clean": "var(--green-bg)",
    "not_tested": "var(--bg-card2)",
}
STATUS_LABEL_TR = {
    "vulnerable": "Zafiyetli",
    "clean": "Temiz",
    "not_tested": "Test Edilmedi",
}


def compute_vector_statuses(findings: List[Dict[str, Any]]) -> Dict[str, str]:
    """Taksonomideki 69 vektörün HER BİRİ için test durumunu hesaplar.

    Kural: vektöre ait EN AZ BİR 'vulnerable' bulgu varsa -> 'vulnerable'.
    Zafiyetli yok ama en az bir 'not_vulnerable' bulgu varsa -> 'clean'.
    Hiç ilgili bulgu yoksa (veya yalnızca inconclusive/error) -> 'not_tested'.

    Dönüş, taksonomideki TÜM 69 vektörü içerir (bulgusu olmayanlar dahil,
    'not_tested' olarak) — ısı haritasının hiç eksik hücre bırakmaması için.
    """
    by_vector: Dict[str, List[str]] = {}
    for f in findings:
        vid = f.get("r155_vector_id")
        if not vid:
            continue
        by_vector.setdefault(vid, []).append(f.get("status", ""))

    tax = load_taxonomy()
    statuses: Dict[str, str] = {}
    for cat in tax["categories"]:
        for v in cat["vectors"]:
            vid = v["id"]
            v_statuses = by_vector.get(vid, [])
            if any(s == "vulnerable" for s in v_statuses):
                statuses[vid] = "vulnerable"
            elif any(s == "not_vulnerable" for s in v_statuses):
                statuses[vid] = "clean"
            else:
                statuses[vid] = "not_tested"
    return statuses


def build_heatmap_html(findings: List[Dict[str, Any]]) -> str:
    """7 kategori × N vektör ızgarası üretir; her hücre renk kodlu ve
    hover'da (native title attribute) vektör açıklamasını gösterir.
    """
    tax = load_taxonomy()
    statuses = compute_vector_statuses(findings)

    rows = []
    for cat in tax["categories"]:
        cells = []
        for v in cat["vectors"]:
            vid = v["id"]
            status = statuses.get(vid, "not_tested")
            color = STATUS_VAR[status]
            bg = STATUS_BG_VAR[status]
            label = STATUS_LABEL_TR[status]
            short = vid.split("-", 1)[1] if "-" in vid else vid
            tooltip = html_escape.escape(f"{vid}: {v['desc']} — {label}")
            cells.append(
                f'<div class="gk-heat-cell" '
                f'style="background:{bg};border-color:{color};color:{color};" '
                f'title="{tooltip}">{short}</div>'
            )
        cells_html = "".join(cells)
        cat_label = html_escape.escape(f'{cat["code"]} — {cat["label"]}')
        rows.append(
            f'<div class="gk-heat-row">'
            f'<div class="gk-heat-cat-label">{cat_label}</div>'
            f'<div class="gk-heat-cells">{cells_html}</div>'
            f'</div>'
        )

    style = """
<style>
.gk-heat-row { display:flex; align-items:center; gap:14px; margin-bottom:10px; }
.gk-heat-cat-label {
    width:270px; flex-shrink:0; font-size:12px; color:var(--text-sec);
    font-weight:500; line-height:1.3;
}
.gk-heat-cells { display:flex; gap:6px; flex-wrap:wrap; }
.gk-heat-cell {
    width:38px; height:28px; border-radius:5px; border:1px solid;
    display:flex; align-items:center; justify-content:center;
    font-size:11px; font-weight:600; cursor:default;
    font-family:'Share Tech Mono', monospace;
    transition: transform 0.12s ease;
}
.gk-heat-cell:hover { transform: scale(1.18); z-index: 2; position: relative; }

.gk-heat-legend { display:flex; gap:18px; margin-bottom:16px; font-size:12px; color:var(--text-sec); }
.gk-heat-legend-item { display:flex; align-items:center; gap:6px; }
.gk-heat-legend-dot { width:10px; height:10px; border-radius:50%; }
</style>
"""

    legend = (
        '<div class="gk-heat-legend">'
        f'<div class="gk-heat-legend-item">'
        f'<span class="gk-heat-legend-dot" style="background:{STATUS_VAR["vulnerable"]}"></span>Zafiyetli</div>'
        f'<div class="gk-heat-legend-item">'
        f'<span class="gk-heat-legend-dot" style="background:{STATUS_VAR["clean"]}"></span>Temiz</div>'
        f'<div class="gk-heat-legend-item">'
        f'<span class="gk-heat-legend-dot" style="background:{STATUS_VAR["not_tested"]}"></span>Test Edilmedi</div>'
        '</div>'
    )

    return style + legend + "".join(rows)
