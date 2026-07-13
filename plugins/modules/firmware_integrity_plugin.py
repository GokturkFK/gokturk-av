"""
GÖKTÜRK — Firmware / Yazılım Bütünlüğü Test Modülü (R155 Kategori 6)
Taktik: ECU'nun çalışan firmware/yazılımına iki senaryo uygular:

  - malicious_replace      → R155-6.1 (firmware değiştirme / zararlı kod)
  - integrity_check_bypass → R155-6.4 (yazılım bütünlüğü ihlali)

Bu iki vektör, profildeki `hpc_compute` bileşeninde başından beri
DEKLARE EDİLMİŞ ama hiçbir plugin tarafından test EDİLMEMİŞ durumdaydı
(bkz. docs/coverage_roadmap.md) — bu modül o dürüst boşluğu kapatır.

Her zafiyetli senaryo, KENDİ R155 vektörüyle AYRI bir Finding olarak
raporlanır (List[Finding]) — böylece her iki vektör de kapsam sayımına
doğru şekilde yansır.
"""

from ..base_plugin import BasePlugin, Finding

_SCENARIOS = {
    "malicious_replace": {
        "vector": "R155-6.1",
        "label": "Firmware değiştirme / zararlı kod",
        "impact_safety": "critical",
        "cvss": 8.4,
        "remediation": (
            "1. Donanım kök-güvenli (hardware root-of-trust) secure boot "
            "zinciri kur; her önyükleme aşaması bir öncekini imza ile doğrulasın. "
            "2. Firmware imzalama anahtarlarını HSM'de sakla, asla yazılımda gömme."
        ),
    },
    "integrity_check_bypass": {
        "vector": "R155-6.4",
        "label": "Yazılım bütünlüğü ihlali",
        "impact_safety": "high",
        "cvss": 7.2,
        "remediation": (
            "1. Çalışma anında periyodik bütünlük doğrulaması (runtime "
            "attestation) uygula. "
            "2. Bütünlük ihlali tespit edildiğinde güvenli duruma (fail-safe) "
            "geçiş mekanizması tanımla."
        ),
    },
}


class FirmwareIntegrityPlugin(BasePlugin):
    module_id = "firmware-integrity"
    name = "Firmware / Yazılım Bütünlüğü"
    surface = "firmware"
    technique = "integrity-bypass"
    r155_vector_id = "R155-6.1"   # birincil (koruma aktifse tek özet Finding için)
    r155_category = 6
    avcat_id = "FIRMWARE-INTEGRITY"
    applicable_adapters = ["socketcan", "carla"]
    severity_hint = "critical"
    description = (
        "ECU firmware'ine kötü niyetli değiştirme (R155-6.1) ve çalışma anı "
        "bütünlük doğrulaması atlatma (R155-6.4) senaryolarını uygular; "
        "secure boot zincirinin ve runtime attestation'ın etkinliğini test eder."
    )

    def run(self, component_config: dict):
        comp_id = component_config.get("id", "unknown")

        try:
            outcomes = {
                scenario: self.adapter.firmware_integrity_probe(comp_id, scenario)
                for scenario in _SCENARIOS
            }
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="Firmware Bütünlüğü: Adaptör desteklemiyor",
                description=(
                    "Bu test için firmware/secure boot doğrulamasını modelleyen "
                    "bir adaptör gerekli. Gerçek testte fiziksel/yetkili bir "
                    "tezgâh ortamı gerekir."
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
                title="Firmware Bütünlüğü: Doğrulama korumaları aktif",
                description=(
                    "İki firmware bütünlük senaryosunun tamamı ilgili koruma "
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
                title=f"Firmware Bütünlüğü: {meta['label']} başarılı",
                description=(
                    f"'{comp_id}' üzerinde '{meta['label'].lower()}' senaryosu "
                    f"başarılı oldu: {outcome.get('detail', '')}\n\n"
                    "Firmware bütünlüğünün doğrulanmaması, saldırganın ECU "
                    "üzerinde kalıcı ve tespit edilmesi zor bir kontrol "
                    "kazanmasına olanak tanır."
                ),
                impact_safety=meta["impact_safety"],
                impact_operational="high",
                attack_feasibility="medium",
                remediation=meta["remediation"],
                cvss_score=meta["cvss"],
            ))
        return findings
