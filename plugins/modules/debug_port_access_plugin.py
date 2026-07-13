"""
GÖKTÜRK — Fiziksel Debug Portu Erişimi Test Modülü (R155 Kategori 7)
Taktik: bir donanım debug arayüzüne (JTAG/UART) fiziksel erişim dener.
Üretim ECU'larında bu arayüzlerin devre dışı bırakılması (fuse/lock)
beklenir; aksi halde bellek dökümü, bootloader kesintisi veya doğrudan
flash erişimi ile firmware çıkarma/değiştirme mümkün olabilir.

OBD-II teşhis portundan (R155-5.5, obd2-enum) farkı: bu, aracın normal
teşhis arayüzü değil, PCB üzerindeki ayrı ve genelde geliştirme aşamasında
kalan bir düşük seviye debug arayüzüdür. Erişim fiziksel temas gerektirir,
bu yüzden saldırı fizibilitesi genelde 'low' (fiziksel erişim şart) olarak
değerlendirilir; ancak etkisi kritik olabilir (tam ECU ele geçirme).

R155-7.4: Debug portları üzerinden erişim (JTAG/UART)
"""

from ..base_plugin import BasePlugin, Finding

_ACTION_LABELS = {
    "jtag_connect": "JTAG bağlantısı",
    "uart_console": "UART seri konsol erişimi",
}


class DebugPortAccessPlugin(BasePlugin):
    module_id = "debug-port-access"
    name = "Fiziksel Debug Portu Erişimi"
    surface = "physical"
    technique = "hardware-debug-access"
    r155_vector_id = "R155-7.4"
    r155_category = 7
    avcat_id = "PHYS-DEBUG-PORT"
    applicable_adapters = ["socketcan", "carla"]
    severity_hint = "high"
    description = (
        "PCB üzerindeki JTAG/UART debug arayüzüne fiziksel erişim dener; "
        "üretim ECU'larında bu arayüzlerin kilitlenip kilitlenmediğini "
        "(fuse/lock) test eder."
    )

    DEFAULT_ACTION = "jtag_connect"

    def run(self, component_config: dict) -> Finding:
        comp_id = component_config.get("id", "unknown")
        action = str(self.config.get("debug_action", self.DEFAULT_ACTION))
        action_label = _ACTION_LABELS.get(action, action)

        try:
            accessible = self.adapter.debug_port_probe(comp_id, action=action)
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="Debug Portu Erişimi: Adaptör desteklemiyor",
                description=(
                    "Bu test için donanım debug arayüzünü modelleyen bir "
                    "adaptör gerekli. Gerçek testte fiziksel erişim ve uygun "
                    "donanım (JTAG probu/UART-USB adaptörü) gerekir; yalnızca "
                    "yetkili tezgâhta yapılmalıdır."
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
                title=f"Debug Portu Erişimi: Arayüz kilitlenmemiş ({action_label})",
                description=(
                    f"'{comp_id}' üzerindeki debug arayüzü ({action_label.lower()}) "
                    "üretimde kilitlenmemiş/eritilmemiş (fused) durumda; fiziksel "
                    "erişimle bağlantı kuruldu.\n\n"
                    "Bu, saldırganın bellek dökümü alabilmesi, bootloader'ı "
                    "kesintiye uğratabilmesi veya doğrudan flash/firmware "
                    "erişimi sağlayabilmesi anlamına gelir — tam ECU ele "
                    "geçirmeye kadar tırmanabilir. Saldırı, fiziksel erişim "
                    "gerektirdiği için fizibilitesi düşüktür ama etkisi "
                    "kritik olabilir."
                ),
                impact_safety="high",
                impact_operational="medium",
                attack_feasibility="low",
                remediation=(
                    "1. Üretim ECU'larında JTAG/UART debug arayüzlerini kalıcı "
                    "olarak kilitle (fuse bit / debug-disable). "
                    "2. Kilitlenemiyor ise fiziksel erişimi zorlaştıran "
                    "kurcalama-belirgin (tamper-evident) mühürleme uygula. "
                    "3. Debug arayüzü zorunluysa kimlik doğrulamalı/imzalı "
                    "debug erişimi (ör. ARM CoreSight kilit mekanizmaları) kullan. "
                    "4. Fiziksel muhafazaya kurcalama tespiti (tamper detection) "
                    "sensörü ekle."
                ),
                cvss_score=7.3,
            )

        return Finding(
            component_id=comp_id,
            test_module_id=self.module_id,
            r155_vector_id=self.r155_vector_id,
            status="not_vulnerable",
            title=f"Debug Portu Erişimi: Arayüz kilitli ({action_label})",
            description=(
                f"'{comp_id}' üzerindeki debug arayüzü ({action_label.lower()}) "
                "kilitli/eritilmiş durumda; fiziksel erişimle bağlantı "
                "kurulamadı."
            ),
            attack_feasibility="low",
        )
