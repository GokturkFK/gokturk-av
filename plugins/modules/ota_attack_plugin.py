"""
GÖKTÜRK — OTA / Firmware Güncelleme Saldırı Modülü (UN R156 / R155 Kat.3)
Taktik: OTA güncelleme kanalına üç saldırı senaryosu uygular ve her birini
ilgili R155 vektörüne çapalar:

  - rollback      → R155-3.6 (eski sürüme geri döndürme / downgrade)
  - bad_signature → R155-3.4 (imza doğrulama atlatma)
  - plaintext     → R155-3.5 (OTA kanal gizliliği ihlali)

Saha araştırmasında UN R156 (SUMS) ve OTA kanalı kritik bir saldırı yüzeyi
olarak tanımlanmıştı; bu modül o boşluğu kapatır.

Birincil vektör: R155-3.4 (imza atlatma — en kritik senaryo). Bulgu açıklaması
üç senaryonun tamamının sonucunu içerir.
"""

from ..base_plugin import BasePlugin, Finding

# Senaryo → (R155 vektörü, insan-okur etiket)
_SCENARIOS = [
    ("bad_signature", "R155-3.4", "İmza doğrulama atlatma"),
    ("plaintext", "R155-3.5", "OTA kanal gizliliği (şifreleme)"),
    ("rollback", "R155-3.6", "Downgrade / rollback koruması"),
]


class OTAAttackPlugin(BasePlugin):
    module_id = "ota-attack"
    name = "OTA / Firmware Güncelleme Saldırısı"
    surface = "ota"
    technique = "update-manipulation"
    r155_vector_id = "R155-3.4"   # birincil (imza atlatma)
    r155_category = 3
    avcat_id = "OTA-UPDATE-ATTACK"
    applicable_adapters = ["socketcan", "carla", "eth"]
    severity_hint = "high"
    description = (
        "OTA güncelleme kanalına rollback (R155-3.6), imza atlatma (R155-3.4) ve "
        "şifrelenmemiş kanal (R155-3.5) senaryolarını uygulayarak UN R156/R155 "
        "Kategori 3 güncelleme güvenliğini test eder."
    )

    def run(self, component_config: dict) -> Finding:
        comp_id = component_config.get("id", "unknown")

        try:
            results = {}
            for scenario, vector, label in _SCENARIOS:
                results[scenario] = {
                    "vector": vector,
                    "label": label,
                    "outcome": self.adapter.ota_update_probe(comp_id, scenario),
                }
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="OTA Saldırı: Adaptör desteklemiyor",
                description=(
                    "Bu test için OTA kanalını modelleyen bir adaptör gerekli "
                    "(SocketCAN/CARLA/Ethernet). Gerçek OTA testi yalnızca yetkili "
                    "ortamda yapılır."
                ),
            )
        except Exception as e:
            return self.make_error_finding(comp_id, e)

        # Hangi senaryolar başarılı oldu (zafiyet)?
        vulnerable_scenarios = [
            (s, results[s]) for s, _, _ in _SCENARIOS
            if results[s]["outcome"].get("accepted")
        ]

        # Rapor satırları (her senaryo için)
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
                title="OTA Saldırı: Güncelleme korumaları aktif",
                description=(
                    "Üç OTA saldırı senaryosunun tamamı ilgili koruma mekanizması "
                    f"tarafından engellendi:\n\n{report}"
                ),
                attack_feasibility="high",
            )

        # En az bir senaryo başarılı → birincil vektörü belirle.
        # İmza atlatma > rollback > plaintext önceliğiyle en kritik olanı seç.
        priority = {"bad_signature": 3, "rollback": 2, "plaintext": 1}
        top_scenario = max(vulnerable_scenarios, key=lambda x: priority.get(x[0], 0))
        top_vector = top_scenario[1]["vector"]
        top_label = top_scenario[1]["label"]

        # plaintext yalnız başına orta, imza/rollback yüksek safety etkisi
        only_plaintext = all(s == "plaintext" for s, _ in vulnerable_scenarios)
        safety = "medium" if only_plaintext else "high"
        cvss = 5.9 if only_plaintext else 8.1

        return Finding(
            component_id=comp_id,
            test_module_id=self.module_id,
            r155_vector_id=top_vector,
            r155_category=self.r155_category,
            avcat_id=self.avcat_id,
            status="vulnerable",
            title=(
                f"OTA Saldırı: {len(vulnerable_scenarios)}/3 senaryo başarılı "
                f"(birincil: {top_vector} {top_label})"
            ),
            description=(
                f"'{comp_id}' güncelleme kanalında {len(vulnerable_scenarios)} "
                "saldırı senaryosu başarılı oldu:\n\n"
                f"{report}\n\n"
                "İmza doğrulama veya downgrade korumasının atlatılabilmesi, "
                "saldırganın araca zararlı/eski firmware yüklemesine olanak tanır "
                "— bu, tüm filoyu etkileyebilecek doğrudan bir safety ve bütünlük "
                "riskidir."
            ),
            impact_safety=safety,
            impact_operational="high",
            impact_financial="medium",
            attack_feasibility="medium",
            remediation=(
                "1. Tüm OTA paketlerinde asimetrik imza doğrulamasını zorunlu kıl "
                "(ör. Uptane çerçevesi). "
                "2. Monoton artan sürüm sayacı ile downgrade/rollback'i engelle. "
                "3. OTA kanalını uçtan uca TLS ile şifrele ve sunucu kimliğini doğrula. "
                "4. Güncelleme meta verisini (manifest) ayrıca imzala ve doğrula. "
                "5. UN R156 SUMS gereksinimlerine uygun güncelleme yönetim süreci kur."
            ),
            cvss_score=cvss,
        )
