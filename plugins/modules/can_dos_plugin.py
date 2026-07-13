"""
GÖKTÜRK — CAN Bus Servis Engelleme (DoS) Test Modülü (R155 Kategori 2)
Taktik: CAN veri yoluna iki farklı DoS tekniği uygular:

  - high_priority_flood → düşük arbitration ID'li (yüksek öncelikli)
    çerçeveleri sürekli basarak diğer düğümleri aç bırakır (starvation)
  - error_frame_attack  → hedef düğümü zorla 'bus-off' durumuna düşürür

CAN protokolü tasarım gereği önceliklendirme temellidir (en düşük
arbitration ID her zaman kazanır); bu, can-replay/can-fuzz'un test ettiği
kimlik doğrulama eksikliğinden FARKLI bir zafiyet sınıfıdır — burada
sorun mesaj sahteciliği değil, kaynak tükenmesi/erişilebilirliktir.

R155-2.4: Servis engelleme / DoS
"""

from ..base_plugin import BasePlugin, Finding

_TECHNIQUE_LABELS = {
    "high_priority_flood": "Yüksek öncelikli mesaj seli (aç bırakma)",
    "error_frame_attack": "Hata çerçevesi enjeksiyonu (bus-off zorlama)",
}


class CANDosPlugin(BasePlugin):
    module_id = "can-dos"
    name = "CAN Bus Servis Engelleme (DoS)"
    surface = "communication"
    technique = "denial-of-service"
    r155_vector_id = "R155-2.4"
    r155_category = 2
    avcat_id = "CAN-DOS"
    applicable_adapters = ["socketcan", "carla"]
    severity_hint = "high"
    description = (
        "CAN veri yoluna yüksek öncelikli mesaj seli veya hata çerçevesi "
        "enjeksiyonu ile servis engelleme (DoS) saldırısı dener; CAN'ın "
        "tasarımsal önceliklendirme zafiyetini ölçer."
    )

    DEFAULT_TECHNIQUE = "high_priority_flood"

    def run(self, component_config: dict) -> Finding:
        comp_id = component_config.get("id", "unknown")
        technique = str(self.config.get("dos_technique", self.DEFAULT_TECHNIQUE))
        technique_label = _TECHNIQUE_LABELS.get(technique, technique)

        try:
            outcome = self.adapter.can_dos_probe(comp_id, technique=technique)
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="CAN DoS: Adaptör desteklemiyor",
                description=(
                    "Bu test için SocketCAN/CARLA adaptörü gerekli. Gerçek DoS "
                    "testi, aracın tüm CAN ağını etkileyebileceğinden yalnızca "
                    "izole test tezgâhında yapılmalıdır."
                ),
            )
        except Exception as e:
            return self.make_error_finding(comp_id, e)

        if outcome.get("succeeded"):
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                avcat_id=self.avcat_id,
                status="vulnerable",
                title=f"CAN DoS: {technique_label} başarılı",
                description=(
                    f"'{comp_id}' üzerinde '{technique_label.lower()}' tekniği "
                    f"başarılı oldu: {outcome.get('detail', '')}\n\n"
                    "CAN protokolü tasarım gereği önceliklendirme temellidir; "
                    "en düşük arbitration ID'li mesaj her zaman kazanır. Bu, "
                    "sahte kimlik doğrulama olmadan bile bir düğümü tamamen "
                    "susturabilecek (starvation) veya bus-off durumuna "
                    "zorlayabilecek bir DoS yüzeyi oluşturur — özellikle "
                    "güvenlik-kritik mesajların (fren, direksiyon) gecikmesi "
                    "veya kaybı ciddi operasyonel risk taşır."
                ),
                impact_safety="high",
                impact_operational="high",
                attack_feasibility="medium",
                remediation=(
                    "1. Kritik ECU'larda hata sayacı izleme ve anomali tespiti "
                    "(beklenmeyen bus-off geçişlerini alarm) uygula. "
                    "2. Mesaj hızı sınırlama (rate limiting) ve düğüm bazlı "
                    "izinli mesaj listesi (allowlisting) kullan. "
                    "3. Kritik fonksiyonlar için CAN yerine zamanlama garantili "
                    "bir protokole (ör. FlexRay, TSN) geçişi değerlendir. "
                    "4. Gateway ECU'da zonal ayrıştırma ile DoS'un tüm ağa "
                    "yayılmasını sınırla."
                ),
                cvss_score=7.4,
            )

        return Finding(
            component_id=comp_id,
            test_module_id=self.module_id,
            r155_vector_id=self.r155_vector_id,
            status="not_vulnerable",
            title=f"CAN DoS: {technique_label} engellendi",
            description=(
                f"'{comp_id}' üzerinde '{technique_label.lower()}' denemesi "
                f"engellendi: {outcome.get('detail', '')}"
            ),
            attack_feasibility="medium",
        )
