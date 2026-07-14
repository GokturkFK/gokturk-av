"""
GÖKTÜRK — İletişim Kanalı Dinleme/Araya Girme Test Modülü (R155 Kategori 2)
Taktik: gateway/iletişim kanalı üzerinden PASİF dinleme ile AKTİF araya
girmeyi (MitM) İKİ AYRI YETENEK olarak test eder:

  - can_sniffing -> R155-2.3 (bilgi dinleme/sniffing) — PASİF: ağ üzerinde
    salt-okunur konumdaki bir saldırganın hassas sinyalleri dinleyip tam
    çözebilmesi. Yalnızca GİZLİLİĞİ tehdit eder, mesajı değiştirmez.
  - gateway_mitm -> R155-2.6 (ortadaki adam/MitM) — AKTİF: saldırganın iki
    segment arasına yerleşip trafiği hem okuyup hem DEĞİŞTİREBİLMESİ. Hem
    GİZLİLİĞİ hem BÜTÜNLÜĞÜ tehdit eder.

CAN Replay (R155-2.5) ve CAN Fuzz (R155-2.2) mesaj ENJEKSİYONUNU test
ederken, bu modül önce DİNLEME (pasif) sonra ARAYA GİRME (aktif) yeteneğini
sınar — replay/fuzz'un ön koşulu olan "trafiği görebilme" yeteneğinin
kendisini ayrı bir vektör olarak değerlendirir.

Her zafiyetli senaryo, KENDİ R155 vektörüyle AYRI bir Finding olarak
raporlanır (List[Finding]) — böylece her iki vektör de kapsam sayımına
doğru şekilde yansır.
"""

from ..base_plugin import BasePlugin, Finding

_SCENARIOS = {
    "can_sniffing": {
        "vector": "R155-2.3",
        "label": "Ağ trafiği pasif dinleme (sniffing)",
        "impact_safety": "low",
        "impact_operational": "medium",
        "impact_privacy": "high",
        "cvss": 5.9,
        "remediation": (
            "1. Hassas sinyalleri (konum, kimlik, güvenlik-kritik komutlar) "
            "payload seviyesinde şifrele veya mesaj kimlik doğrulama kodu "
            "(MAC) ekle (ör. AUTOSAR SecOC). "
            "2. Ağ segmentasyonu ile hassas trafiği yalnızca ihtiyacı olan "
            "düğümlere sınırla (VLAN/zonal mimari)."
        ),
    },
    "gateway_mitm": {
        "vector": "R155-2.6",
        "label": "Ortadaki adam (MitM) araya girme",
        "impact_safety": "high",
        "impact_operational": "high",
        "impact_privacy": "high",
        "cvss": 7.6,
        "remediation": (
            "1. Segmentler arası iletişimde karşılıklı TLS (mutual TLS) ve "
            "sertifika sabitleme (certificate pinning) zorunlu kıl. "
            "2. Gateway'de mesaj kaynağı doğrulaması yaparak yalnızca "
            "beklenen, kimliği doğrulanmış düğümlerden gelen trafiği "
            "yönlendir."
        ),
    },
}


class CommInterceptionPlugin(BasePlugin):
    module_id = "comm-interception"
    name = "İletişim Kanalı Dinleme/Araya Girme"
    surface = "communication"
    technique = "eavesdropping-and-mitm"
    r155_vector_id = "R155-2.3"   # birincil (koruma aktifse tek özet Finding için)
    r155_category = 2
    avcat_id = "COMM-INTERCEPTION"
    applicable_adapters = ["socketcan", "carla", "simulation"]
    severity_hint = "medium"
    description = (
        "Ağ trafiğinin pasif dinlenmesini (R155-2.3) ve saldırganın iki "
        "segment arasına aktif olarak yerleşerek trafiği değiştirebilmesini "
        "(R155-2.6) ayrı ayrı test eder."
    )

    def run(self, component_config: dict):
        comp_id = component_config.get("id", "unknown")

        try:
            outcomes = {
                scenario: self.adapter.comm_interception_probe(comp_id, scenario)
                for scenario in _SCENARIOS
            }
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="İletişim Dinleme/MitM: Adaptör desteklemiyor",
                description=(
                    "Bu test için ağ trafiğini modelleyen bir adaptör "
                    "(SocketCAN/CARLA/simülasyon) gerekli. Gerçek dinleme/MitM "
                    "testi yalnızca yetkili sahada yapılır."
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
                title="İletişim Dinleme/MitM: Pasif ve aktif korumalar aktif",
                description=(
                    "İki iletişim kanalı saldırı senaryosunun tamamı ilgili "
                    "koruma mekanizması tarafından engellendi:\n\n" + "\n".join(lines)
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
                title=f"İletişim Dinleme/MitM: {meta['label']} başarılı",
                description=(
                    f"'{comp_id}' üzerinde '{meta['label'].lower()}' senaryosu "
                    f"başarılı oldu: {outcome.get('detail', '')}\n\n"
                    "İletişim kanalı koruma eksikliği, saldırgana hassas "
                    "verilere erişim (dinleme) veya trafiği değiştirme "
                    "(araya girme) yeteneği kazandırır — ikincisi doğrudan "
                    "sürüş kararlarını etkileyecek komutların manipülasyonuna "
                    "kadar tırmanabilir."
                ),
                impact_safety=meta["impact_safety"],
                impact_operational=meta["impact_operational"],
                impact_privacy=meta["impact_privacy"],
                attack_feasibility="medium",
                remediation=meta["remediation"],
                cvss_score=meta["cvss"],
            ))
        return findings
