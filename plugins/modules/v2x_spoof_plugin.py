"""
GÖKTÜRK — V2X Mesaj Manipülasyonu Test Modülü
Taktik: imzasız/sahte bir V2X mesajı (ör. sahte BSM — Basic Safety Message,
"hayalet araç" veya sahte trafik durumu) enjekte ederek alıcı yığının
PKI/SCMS imza doğrulaması yapıp yapmadığını ölçer.

R155-2.7: V2X mesaj manipülasyonu
"""

from ..base_plugin import BasePlugin, Finding


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
        "İmzasız/sahte bir V2X mesajı (sahte BSM — hayalet araç, sahte trafik "
        "durumu) enjekte ederek alıcı yığının PKI/SCMS imza doğrulaması yapıp "
        "yapmadığını test eder."
    )

    # Test edilen sahte mesaj tipi (BSM = Basic Safety Message)
    DEFAULT_MSG_TYPE = "BSM"

    def run(self, component_config: dict) -> Finding:
        comp_id = component_config.get("id", "unknown")
        msg_type = str(self.config.get("v2x_msg_type", self.DEFAULT_MSG_TYPE))

        try:
            accepted = self.adapter.inject_v2x_message(msg_type=msg_type, signed=False)
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

        if accepted:
            return Finding(
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
            )
        return Finding(
            component_id=comp_id,
            test_module_id=self.module_id,
            r155_vector_id=self.r155_vector_id,
            r155_category=self.r155_category,
            status="not_vulnerable",
            title=f"V2X Spoof: İmzasız {msg_type} mesajı reddedildi",
            description=(
                f"İmzasız/sahte V2X {msg_type} mesajı alıcı yığın tarafından "
                "reddedildi — PKI/SCMS imza doğrulaması çalışıyor görünüyor."
            ),
            attack_feasibility="high",
        )
