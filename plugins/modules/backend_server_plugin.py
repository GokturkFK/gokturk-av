"""
GÖKTÜRK — Arka Uç / Filo Yönetim Sunucusu Güvenlik Modülü (R155 Kategori 1)
Taktik: aracın bağlandığı backend (filo yönetim/telematik) sunucusuna iki
senaryo uygular:

  - weak_auth → R155-1.1 (yetkisiz uzaktan sunucu erişimi)
  - dos       → R155-1.5 (araç servisleri arka uç sunucusuna DoS)

Saha araştırmasında vurgulandığı gibi backend, filo homojenliği nedeniyle
özellikle kritik bir yüzeydir: tek bir backend zaafı TÜM FİLOYU aynı anda
etkileyebilir (R155-1.4 tedarik zinciri senaryosuyla da ilişkili).

Her zafiyetli senaryo, KENDİ R155 vektörüyle AYRI bir Finding olarak
raporlanır (List[Finding]) — böylece her iki vektör de kapsam sayımına
doğru şekilde yansır.
"""

from ..base_plugin import BasePlugin, Finding

_SCENARIOS = {
    "weak_auth": {
        "vector": "R155-1.1",
        "label": "Yetkisiz uzaktan sunucu erişimi",
        "impact_safety": "high",
        "impact_privacy": "high",
        "cvss": 8.6,
        "remediation": (
            "1. Çok faktörlü kimlik doğrulama (MFA) ve güçlü parola politikası "
            "zorunlu kıl; varsayılan kimlik bilgilerini asla üretimde bırakma. "
            "2. En az yetki (least privilege) ilkesiyle personel erişimini sınırla."
        ),
    },
    "dos": {
        "vector": "R155-1.5",
        "label": "Araç servisleri arka uç sunucusuna DoS",
        "impact_safety": "medium",
        "impact_privacy": "none",
        "cvss": 6.5,
        "remediation": (
            "1. API/yönetim paneli için hız sınırlama (rate limiting) ve anomali "
            "tespiti uygula. "
            "2. Backend'i DDoS koruması olan bir CDN/WAF arkasına al."
        ),
    },
}

_COMMON_REMEDIATION = (
    " 3. Düzenli sızma testi ve tedarik zinciri (üçüncü taraf bileşen) "
    "denetimi yap (R155-1.4)."
)


class BackendServerPlugin(BasePlugin):
    module_id = "backend-server"
    name = "Arka Uç Sunucu Güvenliği"
    surface = "backend"
    technique = "server-access"
    r155_vector_id = "R155-1.1"   # birincil (koruma aktifse tek özet Finding için)
    r155_category = 1
    avcat_id = "BACKEND-SERVER-ACCESS"
    applicable_adapters = ["telematics", "cloud", "simulation"]
    severity_hint = "high"
    description = (
        "Araç filo yönetim/telematik backend sunucusuna zayıf kimlik "
        "doğrulama (R155-1.1) ve servis engelleme (R155-1.5) senaryolarıyla "
        "erişim/dayanıklılık testi yapar."
    )

    def run(self, component_config: dict):
        comp_id = component_config.get("id", "unknown")

        try:
            outcomes = {
                scenario: self.adapter.backend_server_probe(comp_id, scenario)
                for scenario in _SCENARIOS
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

        vulnerable = {s: o for s, o in outcomes.items() if o.get("accepted")}

        if not vulnerable:
            lines = [
                f"  [{meta['vector']}] {meta['label']}: ✓ korumalı — {outcomes[s].get('detail', '')}"
                for s, meta in _SCENARIOS.items()
            ]
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                status="not_vulnerable",
                title="Backend Sunucu: Erişim/dayanıklılık korumaları aktif",
                description=(
                    "İki backend saldırı senaryosunun tamamı ilgili koruma "
                    "mekanizması tarafından engellendi:\n\n" + "\n".join(lines)
                ),
                attack_feasibility="high",
            )

        findings = []
        for scenario, outcome in vulnerable.items():
            meta = _SCENARIOS[scenario]
            findings.append(Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=meta["vector"],
                r155_category=self.r155_category,
                avcat_id=self.avcat_id,
                status="vulnerable",
                title=f"Backend Sunucu: {meta['label']} başarılı",
                description=(
                    f"'{comp_id}' üzerinden erişilen backend sunucusunda "
                    f"'{meta['label'].lower()}' senaryosu başarılı oldu: "
                    f"{outcome.get('detail', '')}\n\n"
                    "Filo homojenliği nedeniyle backend zaafları özellikle "
                    "kritiktir: tek bir sunucu güvenlik açığı, o backend'e "
                    "bağlı TÜM araçları aynı anda etkileyebilir."
                ),
                impact_safety=meta["impact_safety"],
                impact_operational="high",
                impact_financial="medium",
                impact_privacy=meta["impact_privacy"],
                attack_feasibility="medium",
                remediation=meta["remediation"] + _COMMON_REMEDIATION,
                cvss_score=meta["cvss"],
            ))
        return findings
