"""
GÖKTÜRK — Arka Uç / Filo Yönetim Sunucusu Güvenlik Modülü (R155 Kategori 1)
Taktik: aracın bağlandığı backend (filo yönetim/telematik) sunucusuna iki
senaryo uygular:

  - weak_auth → R155-1.1 (yetkisiz uzaktan sunucu erişimi)
  - dos       → R155-1.5 (araç servisleri arka uç sunucusuna DoS)

Saha araştırmasında vurgulandığı gibi backend, filo homojenliği nedeniyle
özellikle kritik bir yüzeydir: tek bir backend zaafı TÜM FİLOYU aynı anda
etkileyebilir (R155-1.4 tedarik zinciri senaryosuyla da ilişkili).

Birincil vektör: R155-1.1 (yetkisiz erişim — genelde daha kritik, çünkü
DoS'tan farklı olarak veri/kontrol sızıntısına yol açabilir).
"""

from ..base_plugin import BasePlugin, Finding

_SCENARIOS = [
    ("weak_auth", "R155-1.1", "Yetkisiz uzaktan sunucu erişimi"),
    ("dos", "R155-1.5", "Araç servisleri arka uç sunucusuna DoS"),
]


class BackendServerPlugin(BasePlugin):
    module_id = "backend-server"
    name = "Arka Uç Sunucu Güvenliği"
    surface = "backend"
    technique = "server-access"
    r155_vector_id = "R155-1.1"   # birincil
    r155_category = 1
    avcat_id = "BACKEND-SERVER-ACCESS"
    applicable_adapters = ["telematics", "cloud", "simulation"]
    severity_hint = "high"
    description = (
        "Araç filo yönetim/telematik backend sunucusuna zayıf kimlik "
        "doğrulama (R155-1.1) ve servis engelleme (R155-1.5) senaryolarıyla "
        "erişim/dayanıklılık testi yapar."
    )

    def run(self, component_config: dict) -> Finding:
        comp_id = component_config.get("id", "unknown")

        try:
            results = {}
            for scenario, vector, label in _SCENARIOS:
                results[scenario] = {
                    "vector": vector,
                    "label": label,
                    "outcome": self.adapter.backend_server_probe(comp_id, scenario),
                }
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="Backend Sunucu: Adaptör desteklemiyor",
                description=(
                    "Bu test için backend/filo yönetim API'sini modelleyen bir "
                    "adaptör gerekli. Gerçek backend testi yalnızca yetkili "
                    "ortamda ve sahibinin izniyle yapılır."
                ),
            )
        except Exception as e:
            return self.make_error_finding(comp_id, e)

        vulnerable_scenarios = [
            (s, results[s]) for s, _, _ in _SCENARIOS
            if results[s]["outcome"].get("accepted")
        ]

        lines = []
        for scenario, vector, label in _SCENARIOS:
            outcome = results[scenario]["outcome"]
            mark = "⚠ ZAFİYETLİ" if outcome.get("accepted") else "✓ korumalı"
            lines.append(f"  [{vector}] {label}: {mark} — {outcome.get('detail', '')}")
        report = "\n".join(lines)

        if not vulnerable_scenarios:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                status="not_vulnerable",
                title="Backend Sunucu: Erişim/dayanıklılık korumaları aktif",
                description=(
                    "İki backend saldırı senaryosunun tamamı ilgili koruma "
                    f"mekanizması tarafından engellendi:\n\n{report}"
                ),
                attack_feasibility="high",
            )

        priority = {"weak_auth": 2, "dos": 1}
        top_scenario = max(vulnerable_scenarios, key=lambda x: priority.get(x[0], 0))
        top_vector = top_scenario[1]["vector"]
        top_label = top_scenario[1]["label"]

        only_dos = all(s == "dos" for s, _ in vulnerable_scenarios)
        safety = "medium" if only_dos else "high"
        privacy = "high" if not only_dos else "none"
        cvss = 6.5 if only_dos else 8.6

        return Finding(
            component_id=comp_id,
            test_module_id=self.module_id,
            r155_vector_id=top_vector,
            r155_category=self.r155_category,
            avcat_id=self.avcat_id,
            status="vulnerable",
            title=(
                f"Backend Sunucu: {len(vulnerable_scenarios)}/2 senaryo başarılı "
                f"(birincil: {top_vector} {top_label})"
            ),
            description=(
                f"'{comp_id}' üzerinden erişilen backend sunucusunda "
                f"{len(vulnerable_scenarios)} saldırı senaryosu başarılı oldu:\n\n"
                f"{report}\n\n"
                "Filo homojenliği nedeniyle backend zaafları özellikle kritiktir: "
                "tek bir sunucu güvenlik açığı, o backend'e bağlı TÜM araçları "
                "aynı anda etkileyebilir (uzaktan komut, konum verisi, filo "
                "yönetim kontrolü dahil)."
            ),
            impact_safety=safety,
            impact_operational="high",
            impact_financial="medium",
            impact_privacy=privacy,
            attack_feasibility="medium",
            remediation=(
                "1. Çok faktörlü kimlik doğrulama (MFA) ve güçlü parola politikası "
                "zorunlu kıl; varsayılan kimlik bilgilerini asla üretimde bırakma. "
                "2. API/yönetim paneli için hız sınırlama (rate limiting) ve "
                "anomali tespiti uygula. "
                "3. En az yetki (least privilege) ilkesiyle personel erişimini "
                "sınırla (R155-1.2 ile ilişkili). "
                "4. Backend'i DDoS koruması olan bir CDN/WAF arkasına al. "
                "5. Düzenli sızma testi ve tedarik zinciri (üçüncü taraf "
                "bileşen) denetimi yap (R155-1.4)."
            ),
            cvss_score=cvss,
        )
