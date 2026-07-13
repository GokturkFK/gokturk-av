"""
GÖKTÜRK — OTA / Firmware Güncelleme Saldırı Modülü (UN R156 / R155 Kat.3)
Taktik: OTA güncelleme kanalına üç saldırı senaryosu uygular ve her birini
ilgili R155 vektörüne çapalar:

  - bad_signature → R155-3.4 (imza doğrulama atlatma)
  - plaintext     → R155-3.5 (OTA kanal gizliliği ihlali)
  - rollback      → R155-3.6 (eski sürüme geri döndürme / downgrade)

Saha araştırmasında UN R156 (SUMS) ve OTA kanalı kritik bir saldırı yüzeyi
olarak tanımlanmıştı; bu modül o boşluğu kapatır.

Her zafiyetli senaryo, KENDİ R155 vektörüyle AYRI bir Finding olarak
raporlanır (List[Finding]) — böylece üç vektör de kapsam sayımına doğru
şekilde yansır; hiçbiri "birincil vektör" gölgesinde kaybolmaz.
"""

from ..base_plugin import BasePlugin, Finding

# Senaryo → (R155 vektörü, insan-okur etiket, impact_safety, cvss, remediation)
_SCENARIOS = {
    "bad_signature": {
        "vector": "R155-3.4",
        "label": "İmza doğrulama atlatma",
        "impact_safety": "high",
        "cvss": 8.1,
        "remediation": (
            "1. Tüm OTA paketlerinde asimetrik imza doğrulamasını zorunlu kıl "
            "(ör. Uptane çerçevesi). "
            "2. Güncelleme meta verisini (manifest) ayrıca imzala ve doğrula."
        ),
    },
    "plaintext": {
        "vector": "R155-3.5",
        "label": "OTA kanal gizliliği (şifreleme)",
        "impact_safety": "medium",
        "cvss": 5.9,
        "remediation": (
            "1. OTA kanalını uçtan uca TLS ile şifrele ve sunucu kimliğini doğrula. "
            "2. Sertifika pinleme (certificate pinning) uygula."
        ),
    },
    "rollback": {
        "vector": "R155-3.6",
        "label": "Downgrade / rollback koruması",
        "impact_safety": "high",
        "cvss": 7.6,
        "remediation": (
            "1. Monoton artan sürüm sayacı ile downgrade/rollback'i engelle. "
            "2. Eski (zafiyetli olduğu bilinen) sürümleri kara listeye al."
        ),
    },
}

_COMMON_REMEDIATION = (
    " 3. UN R156 SUMS gereksinimlerine uygun güncelleme yönetim süreci kur."
)


class OTAAttackPlugin(BasePlugin):
    module_id = "ota-attack"
    name = "OTA / Firmware Güncelleme Saldırısı"
    surface = "ota"
    technique = "update-manipulation"
    r155_vector_id = "R155-3.4"   # birincil (koruma aktifse tek özet Finding için)
    r155_category = 3
    avcat_id = "OTA-UPDATE-ATTACK"
    applicable_adapters = ["socketcan", "carla", "eth"]
    severity_hint = "high"
    description = (
        "OTA güncelleme kanalına rollback (R155-3.6), imza atlatma (R155-3.4) ve "
        "şifrelenmemiş kanal (R155-3.5) senaryolarını uygulayarak UN R156/R155 "
        "Kategori 3 güncelleme güvenliğini test eder."
    )

    def run(self, component_config: dict):
        comp_id = component_config.get("id", "unknown")

        try:
            outcomes = {
                scenario: self.adapter.ota_update_probe(comp_id, scenario)
                for scenario in _SCENARIOS
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
                title="OTA Saldırı: Güncelleme korumaları aktif",
                description=(
                    "Üç OTA saldırı senaryosunun tamamı ilgili koruma mekanizması "
                    "tarafından engellendi:\n\n" + "\n".join(lines)
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
                title=f"OTA Saldırı: {meta['label']} başarılı",
                description=(
                    f"'{comp_id}' güncelleme kanalında '{meta['label'].lower()}' "
                    f"senaryosu başarılı oldu: {outcome.get('detail', '')}\n\n"
                    "İmza doğrulama, kanal şifrelemesi veya downgrade korumasının "
                    "atlatılabilmesi, saldırganın araca zararlı/eski firmware "
                    "yüklemesine olanak tanır — bu, tüm filoyu etkileyebilecek "
                    "doğrudan bir safety ve bütünlük riskidir."
                ),
                impact_safety=meta["impact_safety"],
                impact_operational="high",
                impact_financial="medium",
                attack_feasibility="medium",
                remediation=meta["remediation"] + _COMMON_REMEDIATION,
                cvss_score=meta["cvss"],
            ))
        return findings
