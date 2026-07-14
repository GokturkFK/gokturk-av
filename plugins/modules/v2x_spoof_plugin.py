"""
GÖKTÜRK — V2X Mesaj Manipülasyonu ve V2I Güven Sömürüsü Test Modülü
Taktik: V2X iletişim yığınına üç ayrı saldırı senaryosu uygular ve her birini
ilgili R155 vektörüne çapalar:

  - unsigned_bsm    → R155-2.7 (V2X mesaj manipülasyonu — imzasız/sahte BSM)
  - identity_spoof  → R155-2.1 (genel mesaj sahteciliği — taklit edilmiş kimlik)
  - v2i_infra_trust → R155-5.12 (V2I altyapısı üzerinden araç sistemlerine saldırı)

unsigned_bsm senaryosu, alıcı yığının PKI/SCMS imza doğrulaması yapıp
yapmadığını ölçer (imza tamamen yok). identity_spoof bundan farklı olarak
mesajın GEÇERLİ görünen bir imzası/sertifikası olsa da, o kimliğin taklit
edilmiş (başka bir meşru katılımcının kimliğine bürünülmüş) olması
durumunu test eder — yani imza doğrulamasının varlığı tek başına yeterli
değildir, kimlik/sertifik doğruluğu da ayrıca sınanmalıdır. v2i_infra_trust
ise mesajın kaynağını değil, RSU/altyapı GÜVENİNİN kendisini hedef alır:
ele geçirilmiş veya sahte bir yol kenarı biriminden gelen komutların
(hız sınırı, sinyal durumu vb.) araç tarafından sorgusuz uygulanıp
uygulanmadığını ölçer.

Her zafiyetli senaryo, KENDİ R155 vektörüyle AYRI bir Finding olarak
raporlanır (List[Finding]) — böylece üç vektör de kapsam sayımına doğru
şekilde yansır; hiçbiri "birincil vektör" gölgesinde kaybolmaz.
"""

from ..base_plugin import BasePlugin, Finding

_PROBE_SCENARIOS = {
    "identity_spoof": {
        "vector": "R155-2.1",
        "label": "Kimlik taklidiyle mesaj sahteciliği",
        "impact_safety": "high",
        "impact_operational": "high",
        "cvss": 7.4,
        "remediation": (
            "1. Sertifika zincirini yalnızca imza gecerliligi icin degil, sertifikanin "
            "GERCEKTEN o katilimciya (arac/RSU) ait oldugunu dogrulayacak sekilde "
            "kontrol et (SCMS pseudonym-kimlik eslesmesi). "
            "2. Misbehavior detection ile ayni kimligi farkli fiziksel konum/zamanda "
            "kullanan mesajlari isaretle."
        ),
    },
    "v2i_infra_trust": {
        "vector": "R155-5.12",
        "label": "V2I altyapı güveni sömürüsü (sahte RSU)",
        "impact_safety": "high",
        "impact_operational": "high",
        "cvss": 7.8,
        "remediation": (
            "1. RSU/altyapi kaynakli komutlari ayri, daha kisitli bir guven "
            "seviyesinde isle; kritik komutlari (hiz/sinyal) arac tarafi sagduyu "
            "kontrolunden (plausibility check) gecirmeden uygulama. "
            "2. RSU sertifikalarini merkezi bir V2I guven listesi (trust list) "
            "uzerinden duzenli olarak dogrula ve iptal edilenleri aninda reddet."
        ),
    },
}

_COMMON_REMEDIATION = (
    " 3. Tum V2X/V2I mesajlarinda IEEE 1609.2 / SCMS sertifika ve imza "
    "dogrulamasini zorunlu kil."
)


class V2XSpoofPlugin(BasePlugin):
    module_id = "v2x-spoof"
    name = "V2X Mesaj Manipülasyonu"
    surface = "v2x"
    technique = "spoofing"
    r155_vector_id = "R155-2.7"
    r155_category = 2
    avcat_id = "V2X-MSG-SPOOF"
    applicable_adapters = ["carla", "v2x", "simulation"]
    severity_hint = "high"
    description = (
        "İmzasız/sahte BSM enjeksiyonu (R155-2.7), taklit edilmiş kimlikle mesaj "
        "sahteciliği (R155-2.1) ve sahte RSU üzerinden V2I altyapı güveni "
        "sömürüsü (R155-5.12) senaryolarını uygulayarak V2X/V2I iletişim "
        "katmanının bütünlüğünü test eder."
    )

    DEFAULT_MSG_TYPE = "BSM"

    def run(self, component_config: dict):
        comp_id = component_config.get("id", "unknown")
        msg_type = str(self.config.get("v2x_msg_type", self.DEFAULT_MSG_TYPE))

        try:
            unsigned_bsm_accepted = self.adapter.inject_v2x_message(
                msg_type=msg_type, signed=False
            )
            probe_outcomes = {
                scenario: self.adapter.v2x_attack_probe(comp_id, scenario)
                for scenario in _PROBE_SCENARIOS
            }
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="V2X Spoof: Adaptör desteklemiyor",
                description=(
                    "Bu test için CARLA/V2X simülasyon adaptörü gerekli. "
                    "Fiziksel DSRC/C-V2X mesaj enjeksiyonu yalnızca yetkili sahada yapılır."
                ),
            )
        except Exception as e:
            return self.make_error_finding(comp_id, e)

        vulnerable_probes = {s: o for s, o in probe_outcomes.items() if o.get("accepted")}

        if not unsigned_bsm_accepted and not vulnerable_probes:
            probe_lines = [
                f"  [{meta['vector']}] {meta['label']}: korumali - "
                f"{probe_outcomes[s].get('detail', '')}"
                for s, meta in _PROBE_SCENARIOS.items()
            ]
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                status="not_vulnerable",
                title=f"V2X Spoof: İmzasız {msg_type} mesajı reddedildi, tüm senaryolar korumalı",
                description=(
                    f"İmzasız/sahte V2X {msg_type} mesajı reddedildi — PKI/SCMS imza "
                    "doğrulaması çalışıyor.\n\n"
                    "Ayrıca kimlik taklidi ve V2I altyapı güveni senaryoları da "
                    "korumalı:\n\n" + "\n".join(probe_lines)
                ),
                attack_feasibility="high",
            )

        findings = []

        if unsigned_bsm_accepted:
            findings.append(Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                avcat_id=self.avcat_id,
                status="vulnerable",
                title=f"V2X Spoof: İmzasız {msg_type} mesajı kabul edildi",
                description=(
                    f"İmzasız/sahte bir V2X {msg_type} mesajı, alıcı yığın tarafından "
                    "PKI/SCMS imza doğrulaması olmadan kabul edildi.\n\n"
                    "Bu; sahte 'hayalet araç', sahte acil durum uyarısı veya sahte "
                    "trafik durumu enjekte ederek aracın gereksiz ani fren, manevra "
                    "veya güzergâh değişikliği yapmasına yol açabilir.\n\n"
                    "Sabit güzergâhlı otonom otobüste bu doğrudan güvenlik (safety) "
                    "ve operasyonel süreklilik riski taşır."
                ),
                impact_safety="high",
                impact_operational="high",
                impact_financial="low",
                attack_feasibility="medium",
                remediation=(
                    "1. Tüm V2X mesajlarında IEEE 1609.2 / SCMS sertifika ve imza "
                    "doğrulamasını zorunlu kıl. "
                    "2. İmzasız veya geçersiz sertifikalı mesajları sessizce düşür. "
                    "3. Mesaj makullük kontrolü uygula (fiziksel olarak imkânsız "
                    "konum/hız iddialarını reddet). "
                    "4. Misbehavior detection ile tekrarlayan sahte mesaj "
                    "kaynaklarını raporla/dışla."
                ),
                cvss_score=7.1,
            ))

        for scenario, outcome in vulnerable_probes.items():
            meta = _PROBE_SCENARIOS[scenario]
            findings.append(Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=meta["vector"],
                r155_category=self.r155_category,
                avcat_id=self.avcat_id,
                status="vulnerable",
                title=f"V2X Spoof: {meta['label']} başarılı",
                description=(
                    f"'{comp_id}' üzerinde '{meta['label'].lower()}' senaryosu "
                    f"başarılı oldu: {outcome.get('detail', '')}\n\n"
                    "Bu, saldırganın araca yetkisiz/yanlış bilgi enjekte ederek "
                    "sürüş kararlarını doğrudan etkilemesine olanak tanır — sabit "
                    "güzergâhlı, sürücüsüz operasyonda bu bir safety riskidir."
                ),
                impact_safety=meta["impact_safety"],
                impact_operational=meta["impact_operational"],
                impact_financial="low",
                attack_feasibility="medium",
                remediation=meta["remediation"] + _COMMON_REMEDIATION,
                cvss_score=meta["cvss"],
            ))

        return findings
