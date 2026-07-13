"""
GÖKTÜRK — Firmware / Yazılım Bütünlüğü Test Modülü (R155 Kategori 6)
Taktik: ECU'nun çalışan firmware/yazılımına iki senaryo uygular:

  - malicious_replace      → R155-6.1 (firmware değiştirme / zararlı kod)
  - integrity_check_bypass → R155-6.4 (yazılım bütünlüğü ihlali)

Bu iki vektör, profildeki `hpc_compute` bileşeninde başından beri
DEKLARE EDİLMİŞ ama hiçbir plugin tarafından test EDİLMEMİŞ durumdaydı
(bkz. docs/coverage_roadmap.md) — bu modül o dürüst boşluğu kapatır.

R155-6.1, firmware'in TAMAMEN kötü niyetli bir imajla değiştirilmesini;
R155-6.4 ise daha geniş kapsamlı olarak çalışma anındaki bütünlük
doğrulamasının (checksum/imza/attestation) atlatılmasını kapsar.

Birincil vektör: R155-6.1 (tam değiştirme — genelde daha kritik, çünkü
saldırganın firmware üzerinde tam kontrol sağlamasına yol açar).
"""

from ..base_plugin import BasePlugin, Finding

_SCENARIOS = [
    ("malicious_replace", "R155-6.1", "Firmware değiştirme / zararlı kod"),
    ("integrity_check_bypass", "R155-6.4", "Yazılım bütünlüğü ihlali"),
]


class FirmwareIntegrityPlugin(BasePlugin):
    module_id = "firmware-integrity"
    name = "Firmware / Yazılım Bütünlüğü"
    surface = "firmware"
    technique = "integrity-bypass"
    r155_vector_id = "R155-6.1"   # birincil
    r155_category = 6
    avcat_id = "FIRMWARE-INTEGRITY"
    applicable_adapters = ["socketcan", "carla"]
    severity_hint = "critical"
    description = (
        "ECU firmware'ine kötü niyetli değiştirme (R155-6.1) ve çalışma anı "
        "bütünlük doğrulaması atlatma (R155-6.4) senaryolarını uygular; "
        "secure boot zincirinin ve runtime attestation'ın etkinliğini test eder."
    )

    def run(self, component_config: dict) -> Finding:
        comp_id = component_config.get("id", "unknown")

        try:
            results = {}
            for scenario, vector, label in _SCENARIOS:
                results[scenario] = {
                    "vector": vector,
                    "label": label,
                    "outcome": self.adapter.firmware_integrity_probe(comp_id, scenario),
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
                title="Firmware Bütünlüğü: Doğrulama korumaları aktif",
                description=(
                    "İki firmware bütünlük senaryosunun tamamı ilgili koruma "
                    f"mekanizması tarafından engellendi:\n\n{report}"
                ),
                attack_feasibility="high",
            )

        priority = {"malicious_replace": 2, "integrity_check_bypass": 1}
        top_scenario = max(vulnerable_scenarios, key=lambda x: priority.get(x[0], 0))
        top_vector = top_scenario[1]["vector"]
        top_label = top_scenario[1]["label"]

        return Finding(
            component_id=comp_id,
            test_module_id=self.module_id,
            r155_vector_id=top_vector,
            r155_category=self.r155_category,
            avcat_id=self.avcat_id,
            status="vulnerable",
            title=(
                f"Firmware Bütünlüğü: {len(vulnerable_scenarios)}/2 senaryo başarılı "
                f"(birincil: {top_vector} {top_label})"
            ),
            description=(
                f"'{comp_id}' üzerinde firmware/yazılım bütünlüğü testinde "
                f"{len(vulnerable_scenarios)} saldırı senaryosu başarılı oldu:\n\n"
                f"{report}\n\n"
                "Firmware bütünlüğünün doğrulanmaması, saldırganın ECU üzerinde "
                "kalıcı ve tespit edilmesi zor bir kontrol kazanmasına olanak "
                "tanır — kötü niyetli kod, sistem yeniden başlatılsa bile "
                "kalıcı olabilir ve tüm alt sistemleri (algı, kontrol, "
                "iletişim) etkileyebilir."
            ),
            impact_safety="critical",
            impact_operational="high",
            attack_feasibility="medium",
            remediation=(
                "1. Donanım kök-güvenli (hardware root-of-trust) secure boot "
                "zinciri kur; her önyükleme aşaması bir öncekini imza ile doğrulasın. "
                "2. Çalışma anında periyodik bütünlük doğrulaması (runtime "
                "attestation) uygula. "
                "3. Firmware imzalama anahtarlarını HSM'de sakla, asla yazılımda "
                "gömme. "
                "4. Bütünlük ihlali tespit edildiğinde güvenli duruma (fail-safe) "
                "geçiş mekanizması tanımla."
            ),
            cvss_score=8.4,
        )
