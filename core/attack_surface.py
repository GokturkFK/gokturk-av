"""
GÖKTÜRK — 3D Saldırı Yüzeyi Haritası
Bileşen test durumunu (gerçek Finding verisinden) hesaplar ve tıklanabilir,
döndürülebilir, renk kodlu bir three.js sahnesi (gömülü HTML/JS) üretir.

Tasarım notu: JS tarafındaki tıklama, sahne içindeki bilgi paneline anında
yansır (saf istemci-taraflı etkileşim). Streamlit'e geri veri göndermek
için çift yönlü bir custom component (npm build zinciri) gerekir; bu,
mevcut mimariye orantısız karmaşıklık katacağından bilinçli olarak kapsam
dışı bırakıldı.

Otobüs gövdesi gerçekçi, sabit shuttle oranlarındadır (7x2.4x2.2). Gövde
zeminden FLOOR_Y kadar kaldırıldığı için bileşen işaretlerine de aynı ofset
uygulanır. Profesyonel tutarlılık için HER bileşen aynı görsel dile sahiptir:
renkli küre + zemine inen ince dikey sap + zemindeki taban noktası ("pin"
görünümü) — böylece hiçbiri havada asılı ya da yarım bağlı durmaz.
"""

import json
from typing import Any, Dict, List

STATUS_COLOR = {
    "vulnerable": "#e24b4a",
    "clean": "#63a922",
    "not_tested": "#ef9f27",
}
STATUS_LABEL_TR = {
    "vulnerable": "Zafiyetli",
    "clean": "Temiz",
    "not_tested": "Test Edilmedi",
}


def compute_component_statuses(
    components: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
) -> Dict[str, str]:
    """Her bileşen için en güncel durumu (vulnerable/clean/not_tested) hesaplar.

    Kural: bileşene ait EN AZ BİR 'vulnerable' bulgu varsa -> 'vulnerable'.
    Zafiyetli yok ama en az bir 'not_vulnerable' bulgu varsa -> 'clean'.
    Hiç ilgili bulgu yoksa (veya yalnızca inconclusive/error) -> 'not_tested'.
    """
    by_component: Dict[str, List[str]] = {}
    for f in findings:
        cid = f.get("component_id")
        if not cid:
            continue
        by_component.setdefault(cid, []).append(f.get("status", ""))

    statuses: Dict[str, str] = {}
    for comp in components:
        cid = comp.get("id", "")
        comp_statuses = by_component.get(cid, [])
        if any(s == "vulnerable" for s in comp_statuses):
            statuses[cid] = "vulnerable"
        elif any(s == "not_vulnerable" for s in comp_statuses):
            statuses[cid] = "clean"
        else:
            statuses[cid] = "not_tested"
    return statuses


def build_attack_surface_html(
    vehicle_name: str,
    components: List[Dict[str, Any]],
    statuses: Dict[str, str],
    height: int = 520,
) -> str:
    """Tıklanabilir, döndürülebilir 3D saldırı yüzeyi sahnesi için HTML üretir.

    Streamlit'te `st.components.v1.html(html, height=height)` ile gömülür.
    """
    scene_components = []
    for comp in components:
        pos = comp.get("position_3d", [0, 0, 0])
        cid = comp.get("id", "")
        status = statuses.get(cid, "not_tested")
        scene_components.append({
            "id": cid,
            "label": comp.get("label", cid),
            "category": comp.get("category", "—"),
            "position": pos,
            "color": STATUS_COLOR[status],
            "statusLabel": STATUS_LABEL_TR[status],
            "surfaces": ", ".join(comp.get("attack_surfaces", [])) or "—",
            "vectors": ", ".join(comp.get("r155_vectors", [])) or "—",
        })

    data_json = json.dumps(scene_components, ensure_ascii=False)
    vehicle_name_json = json.dumps(vehicle_name, ensure_ascii=False)

    return f"""
<div id="gokturk-3d-root" style="width:100%; height:{height}px; position:relative;
     background:#111111; border-radius:8px; overflow:hidden; font-family:'Inter',sans-serif;">
  <canvas id="gokturk-canvas" style="display:block; width:100%; height:100%;"></canvas>

  <div id="gokturk-legend" style="position:absolute; top:12px; left:12px; z-index:10;
       background:rgba(15,15,15,0.85); border:1px solid #222; border-radius:6px;
       padding:8px 12px; color:#E8E6E0; font-size:12px; line-height:1.8;">
    <div><span style="color:#e24b4a;">●</span> Zafiyetli</div>
    <div><span style="color:#63a922;">●</span> Temiz</div>
    <div><span style="color:#ef9f27;">●</span> Test Edilmedi</div>
  </div>

  <div id="gokturk-detail" style="position:absolute; bottom:12px; left:12px; right:12px;
       z-index:10; background:rgba(15,15,15,0.92); border:1px solid #222; border-radius:6px;
       padding:10px 14px; color:#E8E6E0; font-size:13px; min-height:20px;">
    <em style="color:#888;">Bir bileşene tıkla — detaylar burada görünür.</em>
  </div>
</div>

<script type="importmap">
{{
  "imports": {{
    "three": "https://cdn.jsdelivr.net/npm/three@0.160.0/build/three.module.js",
    "three/addons/": "https://cdn.jsdelivr.net/npm/three@0.160.0/examples/jsm/"
  }}
}}
</script>
<script type="module">
import * as THREE from 'three';
import {{ OrbitControls }} from 'three/addons/controls/OrbitControls.js';

const components = {data_json};
const vehicleName = {vehicle_name_json};

const root = document.getElementById('gokturk-3d-root');
const canvas = document.getElementById('gokturk-canvas');
const detailBox = document.getElementById('gokturk-detail');

const scene = new THREE.Scene();
scene.background = new THREE.Color(0x111111);

const renderer = new THREE.WebGLRenderer({{ canvas: canvas, antialias: true }});
renderer.setSize(root.clientWidth, root.clientHeight);
renderer.setPixelRatio(window.devicePixelRatio || 1);

// ── Gerçekçi, sabit otobüs oranları ───────────────────────────────────────
const BUS_LENGTH = 7.0;   // X ekseni
const BUS_HEIGHT = 2.4;   // Y ekseni (kabin yüksekliği)
const BUS_WIDTH = 2.2;    // Z ekseni
const FLOOR_Y = 0.5;      // gövde tabanının zeminden yüksekliği
const bodyCenterY = FLOOR_Y + BUS_HEIGHT / 2;

const camera = new THREE.PerspectiveCamera(50, root.clientWidth / root.clientHeight, 0.1, 200);
camera.position.set(7.5, 4.5, 8.5);

const controls = new OrbitControls(camera, renderer.domElement);
controls.enableDamping = true;
controls.target.set(0, bodyCenterY * 0.6, 0);

// Aydınlatma
scene.add(new THREE.AmbientLight(0xffffff, 0.6));
const dirLight = new THREE.DirectionalLight(0xffffff, 0.8);
dirLight.position.set(5, 8, 5);
scene.add(dirLight);

// Basit araç gövdesi (yarı saydam, bileşenleri gizlemesin)
const busGeo = new THREE.BoxGeometry(BUS_LENGTH, BUS_HEIGHT, BUS_WIDTH);
const busMat = new THREE.MeshStandardMaterial({{
  color: 0x2a3a4a, transparent: true, opacity: 0.3, roughness: 0.6,
}});
const busBody = new THREE.Mesh(busGeo, busMat);
busBody.position.set(0, bodyCenterY, 0);
scene.add(busBody);

// Tekerlekler (normal boyutta, sabit)
const wheelGeo = new THREE.CylinderGeometry(0.35, 0.35, 0.25, 16);
const wheelMat = new THREE.MeshStandardMaterial({{ color: 0x1a1a1a }});
const wheelX = BUS_LENGTH / 2 - 0.9;
const wheelZ = BUS_WIDTH / 2 + 0.05;
[[wheelX, wheelZ], [wheelX, -wheelZ], [-wheelX, wheelZ], [-wheelX, -wheelZ]].forEach(p => {{
  const wheel = new THREE.Mesh(wheelGeo, wheelMat);
  wheel.rotation.z = Math.PI / 2;
  wheel.position.set(p[0], 0.35, p[1]);
  scene.add(wheel);
}});

// Zemin (referans ızgarası)
const grid = new THREE.GridHelper(16, 16, 0x333333, 0x222222);
grid.position.y = 0;
scene.add(grid);

// Bileşen işaretleri + zemine dikey sap (stem) + taban noktası
// Profesyonel tutarlılık için HER bileşen aynı görsel dile sahiptir:
// zeminden yükselen ince bir dikey çizgi (stem) ve zemindeki küçük bir
// taban noktası (base dot). Böylece 12 bileşenin hepsi "zemine dikili pin"
// gibi görünür — hiçbiri havada asılı ya da yarım bağlı durmaz.
// position_3d, gövde FLOOR_Y kadar kaldırıldığı için aynı ofsetle kaydırılır.
const markerGeo = new THREE.SphereGeometry(0.16, 24, 24);
const baseGeo = new THREE.CircleGeometry(0.09, 16);
const markers = [];

components.forEach(comp => {{
  const mx = comp.position[0];
  const my = comp.position[1] + FLOOR_Y;
  const mz = comp.position[2];

  // Küresel işaret (durum rengiyle)
  const mat = new THREE.MeshStandardMaterial({{
    color: comp.color, emissive: comp.color, emissiveIntensity: 0.4,
  }});
  const marker = new THREE.Mesh(markerGeo, mat);
  marker.position.set(mx, my, mz);
  marker.userData = comp;
  scene.add(marker);
  markers.push(marker);

  // Zemine (y=0) inen dikey sap — işaretle aynı renk, yarı saydam
  const stemMat = new THREE.LineBasicMaterial({{
    color: comp.color, transparent: true, opacity: 0.45,
  }});
  const stemGeo = new THREE.BufferGeometry().setFromPoints([
    new THREE.Vector3(mx, my, mz),
    new THREE.Vector3(mx, 0.01, mz),
  ]);
  scene.add(new THREE.Line(stemGeo, stemMat));

  // Zemindeki taban noktası (yere yatık küçük disk)
  const baseMat = new THREE.MeshBasicMaterial({{
    color: comp.color, transparent: true, opacity: 0.6, side: THREE.DoubleSide,
  }});
  const base = new THREE.Mesh(baseGeo, baseMat);
  base.rotation.x = -Math.PI / 2;
  base.position.set(mx, 0.02, mz);
  scene.add(base);
}});

// Tıklama ile bileşen seçimi
const raycaster = new THREE.Raycaster();
const pointer = new THREE.Vector2();

function showDetail(comp) {{
  detailBox.innerHTML =
    '<strong>' + comp.label + '</strong> — ' + comp.category + '<br>' +
    '<span style="color:' + comp.color + ';">● ' + comp.statusLabel + '</span><br>' +
    '<strong>Saldırı yüzeyleri:</strong> ' + comp.surfaces + '<br>' +
    '<strong>R155 vektörleri:</strong> ' + comp.vectors;
}}

renderer.domElement.addEventListener('click', (event) => {{
  const rect = renderer.domElement.getBoundingClientRect();
  pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
  pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
  raycaster.setFromCamera(pointer, camera);
  const hits = raycaster.intersectObjects(markers);
  if (hits.length > 0) {{
    showDetail(hits[0].object.userData);
  }}
}});

window.addEventListener('resize', () => {{
  camera.aspect = root.clientWidth / root.clientHeight;
  camera.updateProjectionMatrix();
  renderer.setSize(root.clientWidth, root.clientHeight);
}});

function animate() {{
  requestAnimationFrame(animate);
  controls.update();
  renderer.render(scene, camera);
}}
animate();
</script>
"""
