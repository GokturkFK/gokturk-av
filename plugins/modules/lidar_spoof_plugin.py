"""
GÖKTÜRK — LiDAR Spoofing Test Modülü
Taktik: LiDAR nokta bulutuna iki senaryoda sahte veri enjekte etmeyi dener:
  - "inject" : var olmayan bir engeli var gibi gösterme (sahte fren/durma tetikleyebilir)
  - "remove" : gerçek bir engeli görünmez kılma (en yüksek safety riski)
Sensör füzyonu / tutarlılık kontrolünün (ör. LiDAR-GPS çapraz doğrulama)
bu enjeksiyonları reddedip reddetmediğini ölçer.

R155-2.9: Sensör (LiDAR/kamera/radar) spoofing
"""

from ..base_plugin import BasePlugin, Finding

SCENARIOS = ("inject", "remove")

_SCENARIO_LABEL = {
    "inject": "Sahte engel enjeksiyonu (hayalet nesne)",
    "remove": "Gerçek engelin görünmez kılınması (removal)",
}


class LidarSpoofPlugin(BasePlugin):
    module_id = "lidar-spoof"
    name = "LiDAR Spoofing"
    surface = "sensor"
    technique = "spoofing"
    r155_vector_id = "R155-2.9"
    r155_category = 2
    avcat_id = "SENSOR-LIDAR-SPOOF"
    applicable_adapters = ["carla", "simulation"]
    severity_hint = "critical"
    description = (
        "LiDAR nokta bulutuna sahte engel enjekte etme (inject) ve gerçek "
        "engeli gizleme (remove) senaryolarını dener; sensör füzyonu / "
        "tutarlılık kontrolünün bunları reddedip reddetmediğini ölçer."
    )

    def run(self, component_config: dict) -> Finding:
        comp_id = component_config.get("id", "unknown")
        target = component_config.get("id")

        results = {}
        for scenario in SCENARIOS:
            try:
                results[scenario] = self.adapter.inject_lidar_spoof(
                    mode=scenario, target=target
                )
            except NotImplementedError:
                return Finding(
                    component_id=comp_id,
                    test_module_id=self.module_id,
                    r155_vector_id=self.r155_vector_id,
                    status="inconclusive",
                    title="LiDAR Spoof: Adaptör desteklemiyor",
                    description=(
                        "Bu test için CARLA/simülasyon adaptörü gerekli. "
                        "Fiziksel lazer tabanlı spoofing yalnızca yetkili sahada yapılır."
                    ),
                )
            except Exception as e:
                return self.make_error_finding(comp_id, e)

        succeeded = [s for s, ok in results.items() if ok]

        if not succeeded:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                status="not_vulnerable",
                title="LiDAR Spoof: Her iki senaryo da reddedildi",
                description=(
                    "Hem sahte engel enjeksiyonu hem de gerçek engelin gizlenmesi "
                    "denendi; sensör füzyonu / tutarlılık kontrolü ikisini de reddetti."
                ),
                attack_feasibility="high",
            )

        detail = "\n".join(f"  ⚠ {_SCENARIO_LABEL[s]}" for s in succeeded)
        # 'remove' başarılıysa safety etkisi en üst seviyede: gerçek engel görünmez
        # olduğunda araç fren/durma kararını hiç veremez.
        safety = "critical" if "remove" in succeeded else "high"

        return Finding(
            component_id=comp_id,
            test_module_id=self.module_id,
            r155_vector_id=self.r155_vector_id,
            r155_category=self.r155_category,
            avcat_id=self.avcat_id,
            status="vulnerable",
            title=f"LiDAR Spoof: {len(succeeded)}/{len(SCENARIOS)} senaryo başarılı",
            description=(
                f"Aşağıdaki LiDAR spoofing senaryoları algı hattı tarafından "
                f"reddedilmeden kabul edildi:\n\n{detail}\n\n"
                "Sabit güzergâhlı otonom otobüste bu; ya var olmayan bir engel için "
                "gereksiz/tehlikeli ani fren (inject), ya da gerçek bir engelin fark "
                "edilmemesi (remove) anlamına gelir — ikincisi doğrudan çarpışma "
                "riski taşır."
            ),
            impact_safety=safety,
            impact_operational="high",
            attack_feasibility="medium" if "remove" not in succeeded else "low",
            remediation=(
                "1. Çoklu sensör füzyonu (LiDAR + kamera + radar) ile çapraz doğrulama uygula. "
                "2. Nokta bulutu için istatistiksel tutarlılık/ki-kare residual dedektörü ekle. "
                "3. Ani, fiziksel olarak imkânsız nokta bulutu değişimlerini (anlık ekleme/silme) "
                "anomali olarak işaretle. "
                "4. Kritik karar noktalarında (fren/durma) tek sensöre bağımlılığı kaldır."
            ),
            cvss_score=8.8 if "remove" in succeeded else 6.9,
        )
