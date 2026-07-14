"""
GÖKTÜRK — İzinsiz Fiziksel ECU Erişimi Test Modülü (R155 Kategori 7)
Taktik: bir ECU/port'un (ör. OBD-II) fiziksel muhafaza korumasını (kilit,
mühür, gizli/erişilmesi zor montaj) test eder.

Bu, hem OBD-II/UDS protokol istismarından (R155-5.5, obd2-enum) hem de
donanım debug arayüzü erişiminden (R155-7.4, debug-port-access) farklıdır:

  - R155-5.5 (obd2-enum): port ELEKTRONİĞİ üzerinden, protokol (UDS)
    seviyesinde bir istismardır — port fiziksel olarak korumalı olsa bile
    yetkili bir teşhis cihazı bağlandığında protokol güvenliği test edilir.
  - R155-7.4 (debug-port-access): PCB üzerindeki AYRI bir düşük seviye
    debug arayüzünü (JTAG/UART) hedefler.
  - R155-7.1 (bu modül): portun/ECU'nun kendisinin fiziksel muhafaza
    korumasını hedefler. Kilit/mühür yoksa saldırgan port elektroniğini/
    protokolünü hiç uğraşmadan doğrudan konnektör pinlerine veya kablo
    demetine erişip (tap/splice) ECU ile doğrudan iletişim kurabilir —
    yani protokol güvenliği ne kadar iyi olursa olsun, fiziksel muhafaza
    yoksa saldırgan protokolü tamamen atlayabilir.

R155-7.1: İzinsiz fiziksel ECU erişimi
"""

from ..base_plugin import BasePlugin, Finding

_METHOD_LABELS = {
    "enclosure_bypass": "Muhafaza kilidi/mührü atlatma",
    "harness_tap": "Kablo demetine doğrudan splice/tap",
}


class PhysicalECUAccessPlugin(BasePlugin):
    module_id = "physical-ecu-access"
    name = "İzinsiz Fiziksel ECU Erişimi"
    surface = "physical"
    technique = "physical-access"
    r155_vector_id = "R155-7.1"
    r155_category = 7
    avcat_id = "PHYS-ECU-ACCESS"
    applicable_adapters = ["socketcan", "carla"]
    severity_hint = "high"
    description = (
        "Bir ECU/port'un (ör. OBD-II) fiziksel muhafaza korumasını (kilit, "
        "mühür, gizli montaj) test eder; koruma yoksa saldırganın port "
        "elektroniğini/protokolünü atlayıp doğrudan konnektör/kablo demetine "
        "erişebileceğini doğrular."
    )

    DEFAULT_METHOD = "enclosure_bypass"

    def run(self, component_config: dict) -> Finding:
        comp_id = component_config.get("id", "unknown")
        method = str(self.config.get("physical_access_method", self.DEFAULT_METHOD))
        method_label = _METHOD_LABELS.get(method, method)

        try:
            accessible = self.adapter.physical_ecu_access_probe(comp_id, method=method)
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="Fiziksel ECU Erişimi: Adaptör desteklemiyor",
                description=(
                    "Bu test için hedefin fiziksel muhafaza durumunu modelleyen "
                    "bir adaptör gerekli. Gerçek testte fiziksel erişim ve uygun "
                    "sahaya gitme yetkisi gerekir; yalnızca yetkili tezgâhta/araçta "
                    "yapılmalıdır."
                ),
            )
        except Exception as e:
            return self.make_error_finding(comp_id, e)

        if accessible:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                avcat_id=self.avcat_id,
                status="vulnerable",
                title=f"Fiziksel ECU Erişimi: Muhafaza korumasız ({method_label})",
                description=(
                    f"'{comp_id}' üzerinde fiziksel muhafaza koruması (kilit/mühür) "
                    f"yok veya atlatıldı ({method_label.lower()}); saldırgan port "
                    "elektroniğini/protokol güvenliğini hiç uğraşmadan doğrudan "
                    "konnektör pinlerine veya kablo demetine erişebiliyor.\n\n"
                    "Bu, protokol seviyesindeki (ör. UDS) güvenlik önlemlerinin "
                    "tamamen atlanabileceği, doğrudan bir bypass yolu açar — "
                    "saldırgan port elektroniğiyle hiç etkileşmeden ECU ile "
                    "iletişim kurabilir."
                ),
                impact_safety="high",
                impact_operational="medium",
                impact_financial="low",
                attack_feasibility="low",
                remediation=(
                    "1. Port/ECU muhafazasına fiziksel kilit veya kurcalama-belirgin "
                    "(tamper-evident) mühür ekle. "
                    "2. Kablo demetini araç şasisi içinde erişimi zor bir güzergâha "
                    "yönlendir; açıkta/kolay erişilebilir bırakma. "
                    "3. Kurcalama tespiti (tamper detection) sensörü ile fiziksel "
                    "müdahaleyi telemetriye/loga yansıt. "
                    "4. Kritik ECU'ları araç gövdesinde daha az erişilebilir "
                    "konumlara yerleştir."
                ),
                cvss_score=6.8,
            )

        return Finding(
            component_id=comp_id,
            test_module_id=self.module_id,
            r155_vector_id=self.r155_vector_id,
            status="not_vulnerable",
            title=f"Fiziksel ECU Erişimi: Muhafaza korumalı ({method_label})",
            description=(
                f"'{comp_id}' üzerindeki fiziksel muhafaza koruması "
                f"({method_label.lower()}) etkin; doğrudan fiziksel erişim "
                "engellendi."
            ),
            attack_feasibility="low",
        )
