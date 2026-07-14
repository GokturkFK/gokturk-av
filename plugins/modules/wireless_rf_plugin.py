"""
GÖKTÜRK — Kablosuz RF Arayüzleri Test Modülü (R155 Kategori 2)
Taktik: aracın iki farklı RF/kablosuz arayüzünü — hücresel telematik modem
ve DSRC/V2X radyosu — ayrı ayrı test eder:

  - cellular_jamming_undetected → R155-2.11 (hücresel ağ kanalı jamming /
    sinyal manipülasyonu) — kasıtlı RF jamming ile normal sinyal kaybının
    AYIRT edilip edilemediğini ve fail-safe/degraded moda geçilip
    geçilmediğini sınar
  - dsrc_protocol_exploit        → R155-2.13 (DSRC / IEEE 802.11p protokol
    açıklarının istismarı) — DSRC/802.11p MAC/PHY katmanının kendisinin
    (kanal erişimi, hatalı biçimlendirilmiş çerçeve) istismarına karşı
    dayanıklı olup olmadığını sınar

V2X Spoof modülü (R155-2.7) mesaj İÇERİĞİNİN (imza/geçerlilik) doğrulanıp
doğrulanmadığını test ederken, dsrc_protocol_exploit senaryosu mesaj
içeriğinden BAĞIMSIZ olarak PROTOKOLÜN/MAC katmanının kendisini hedefler —
biri uygulama katmanı, diğeri protokol katmanı zafiyetidir.

Her zafiyetli senaryo, KENDİ R155 vektörüyle AYRI bir Finding olarak
raporlanır (List[Finding]) — böylece her iki vektör de kapsam sayımına
doğru şekilde yansır.
"""

from ..base_plugin import BasePlugin, Finding

_SCENARIOS = {
    "cellular_jamming_undetected": {
        "vector": "R155-2.11",
        "label": "Hücresel jamming tespiti eksikliği",
        "impact_safety": "high",
        "impact_operational": "high",
        "impact_privacy": "none",
        "cvss": 6.9,
        "remediation": (
            "1. Hücresel modemde sinyal kalitesi/gürültü tabanı anomali "
            "tespiti uygula; kasıtlı jamming'e özgü imzaları (ani, sürekli "
            "SNR düşüşü) normal sinyal kaybından ayırt et. "
            "2. Jamming tespit edildiğinde aracı önceden tanımlı bir "
            "fail-safe/degraded moda (ör. güvenli durma, yerel otonomi "
            "seviyesini düşürme) geçir ve operatöre bildir."
        ),
    },
    "dsrc_protocol_exploit": {
        "vector": "R155-2.13",
        "label": "DSRC/IEEE 802.11p protokol istismarı",
        "impact_safety": "high",
        "impact_operational": "high",
        "impact_privacy": "none",
        "cvss": 7.2,
        "remediation": (
            "1. DSRC/802.11p yığınının MAC/PHY katmanını hatalı "
            "biçimlendirilmiş çerçevelere karşı fuzz testinden geçir; "
            "üretici yazılımını güncel tut. "
            "2. WAVE kanal geçişi ve servis reklamı (WSA) işlemlerinde "
            "girdi doğrulaması ve kaynak hız sınırlaması uygula."
        ),
    },
}


class WirelessRFPlugin(BasePlugin):
    module_id = "wireless-rf"
    name = "Kablosuz RF Arayüzleri"
    surface = "telematics"
    technique = "rf-jamming-and-protocol-exploit"
    r155_vector_id = "R155-2.11"   # birincil (koruma aktifse tek özet Finding için)
    r155_category = 2
    avcat_id = "WIRELESS-RF"
    applicable_adapters = ["telematics", "carla", "simulation"]
    severity_hint = "high"
    description = (
        "Hücresel telematik kanalında jamming tespitini (R155-2.11) ve "
        "DSRC/V2X radyosunda protokol/MAC katmanı dayanıklılığını "
        "(R155-2.13) ayrı ayrı test eder."
    )

    def run(self, component_config: dict):
        comp_id = component_config.get("id", "unknown")

        try:
            outcomes = {
                scenario: self.adapter.wireless_rf_probe(comp_id, scenario)
                for scenario in _SCENARIOS
            }
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="Kablosuz RF: Adaptör desteklemiyor",
                description=(
                    "Bu test için hücresel/DSRC RF arayüzlerini modelleyen "
                    "bir adaptör gerekli. Gerçek RF testi (SDR ile jamming/"
                    "protokol fuzzing) yalnızca yetkili, RF-izole bir sahada "
                    "yapılır."
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
                title="Kablosuz RF: Jamming tespiti ve protokol dayanıklılığı aktif",
                description=(
                    "İki kablosuz RF senaryosunun tamamı ilgili koruma "
                    "mekanizması tarafından engellendi:\n\n" + "\n".join(lines)
                ),
                attack_feasibility="low",
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
                title=f"Kablosuz RF: {meta['label']} başarılı",
                description=(
                    f"'{comp_id}' üzerinde '{meta['label'].lower()}' senaryosu "
                    f"başarılı oldu: {outcome.get('detail', '')}\n\n"
                    "RF/protokol katmanındaki bu boşluk, saldırgana fiziksel "
                    "yakınlıkla (SDR/jamming ekipmanı) aracın iletişimini "
                    "sessizce kesme veya OBU'yu istikrarsızlaştırma yeteneği "
                    "verir — sabit güzergâhlı otonom operasyonda bu "
                    "doğrudan bir süreklilik riskidir."
                ),
                impact_safety=meta["impact_safety"],
                impact_operational=meta["impact_operational"],
                impact_privacy=meta["impact_privacy"],
                attack_feasibility="low",
                remediation=meta["remediation"],
                cvss_score=meta["cvss"],
            ))
        return findings
