"""
GÖKTÜRK — Firmware Çıkarma / Tersine Mühendislik Test Modülü (R155 Kat.6)
Taktik: ECU firmware imajından SIR (kriptografik anahtar) ve MANTIK (çalışan
kod) çıkarılabilirliğini İKİ FARKLI AÇIDAN test eder:

  - key_extraction               → R155-6.2 (kriptografik anahtar çalma)
    - SIR çıkarma: firmware/flash bellekte saklanan anahtarların HSM/secure
    element olmadan bellek dökümüyle çıkarılabilmesi
  - firmware_reverse_engineering  → R155-6.5 (ECU firmware tersine mühendislik)
    - MANTIK çıkarma: firmware imajının kendisinin şifreleme/gizleme olmadan
    dökülüp disassemble/decompile edilerek tescilli mantığın ortaya çıkması

Firmware Integrity modülü (R155-6.1/6.4/6.13) firmware'in ÇALIŞMA ANINDA
DEĞİŞTİRİLİP DEĞİŞTİRİLEMEDİĞİNİ (bütünlük) test ederken, bu modül firmware'in
İÇİNDEKİ SIRLARIN ve MANTIĞIN çıkarılabilir olup olmadığını (gizlilik) test
eder — biri bütünlüğü, diğeri gizliliği hedefler.

Her zafiyetli senaryo, KENDİ R155 vektörüyle AYRI bir Finding olarak
raporlanır (List[Finding]) — böylece her iki vektör de kapsam sayımına
doğru şekilde yansır.
"""

from ..base_plugin import BasePlugin, Finding

_SCENARIOS = {
    "key_extraction": {
        "vector": "R155-6.2",
        "label": "Kriptografik anahtar çalma",
        "impact_safety": "high",
        "impact_operational": "high",
        "impact_privacy": "medium",
        "cvss": 8.0,
        "remediation": (
            "1. Kriptografik anahtarları HSM (Hardware Security Module) veya "
            "secure element'te sakla; anahtarlar asla düz metin olarak flash "
            "bellekte bulunmasın. "
            "2. Anahtar kullanımını donanım düzeyinde imzalama/şifreleme "
            "işlemleriyle sınırla; anahtarın kendisi hiçbir zaman CPU'ya "
            "okunabilir biçimde çıkmasın (secure boot zinciriyle entegre)."
        ),
    },
    "firmware_reverse_engineering": {
        "vector": "R155-6.5",
        "label": "ECU firmware tersine mühendislik",
        "impact_safety": "medium",
        "impact_operational": "medium",
        "impact_privacy": "none",
        "cvss": 5.8,
        "remediation": (
            "1. Firmware imajını dağıtım ve depolama sırasında şifrele; "
            "yalnızca çalışma anında güvenli bir alanda (secure enclave/TEE) "
            "çöz. "
            "2. Kod gizleme (obfuscation) ve anti-debug/anti-tamper "
            "teknikleriyle statik analiz/disassemble maliyetini artır."
        ),
    },
}


class FirmwareExtractionPlugin(BasePlugin):
    module_id = "firmware-extraction"
    name = "Firmware Çıkarma / Tersine Mühendislik"
    surface = "firmware"
    technique = "extraction-and-reverse-engineering"
    r155_vector_id = "R155-6.2"   # birincil (koruma aktifse tek özet Finding için)
    r155_category = 6
    avcat_id = "FIRMWARE-EXTRACTION"
    applicable_adapters = ["socketcan", "carla"]
    severity_hint = "high"
    description = (
        "ECU firmware imajından kriptografik anahtar çıkarma (R155-6.2) ve "
        "firmware'in tersine mühendislik ile mantık çıkarma (R155-6.5) "
        "senaryolarını ayrı ayrı test eder."
    )

    def run(self, component_config: dict):
        comp_id = component_config.get("id", "unknown")

        try:
            outcomes = {
                scenario: self.adapter.firmware_extraction_probe(comp_id, scenario)
                for scenario in _SCENARIOS
            }
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="Firmware Çıkarma: Adaptör desteklemiyor",
                description=(
                    "Bu test için firmware/flash bellek erişimini modelleyen "
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
                title="Firmware Çıkarma: Sır ve mantık koruması aktif",
                description=(
                    "İki firmware çıkarma senaryosunun tamamı ilgili koruma "
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
                title=f"Firmware Çıkarma: {meta['label']} başarılı",
                description=(
                    f"'{comp_id}' üzerinde '{meta['label'].lower()}' senaryosu "
                    f"başarılı oldu: {outcome.get('detail', '')}\n\n"
                    "Firmware'den sır veya mantık çıkarılabilmesi, saldırganın "
                    "kalıcı erişim anahtarları elde etmesine ya da tescilli/"
                    "güvenlik-kritik mantığı analiz edip yeni zafiyetler "
                    "bulmasına zemin hazırlar."
                ),
                impact_safety=meta["impact_safety"],
                impact_operational=meta["impact_operational"],
                impact_privacy=meta["impact_privacy"],
                attack_feasibility="medium",
                remediation=meta["remediation"],
                cvss_score=meta["cvss"],
            ))
        return findings
