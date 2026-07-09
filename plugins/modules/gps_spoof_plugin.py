"""
GÖKTÜRK — GPS/GNSS Spoofing Test Modülü
Taktik: sahte bir konum enjekte ederek aracın konumlandırma yığınının
makullük (plausibility) / sensör füzyonu kontrolü yapıp yapmadığını ölçer.

R155-2.8: GPS/GNSS spoofing
"""

from ..base_plugin import BasePlugin, Finding


class GPSSpoofPlugin(BasePlugin):
    module_id = "gps-spoof"
    name = "GPS/GNSS Spoofing"
    surface = "sensor"
    technique = "spoofing"
    r155_vector_id = "R155-2.8"
    r155_category = 2
    avcat_id = "SENSOR-GNSS-SPOOF"
    applicable_adapters = ["carla", "gnss", "simulation"]
    severity_hint = "high"
    description = (
        "Sahte GNSS konumu enjekte ederek konumlandırma yığınının bunu "
        "reddedip reddetmediğini (çapraz doğrulama / sensör füzyonu) test eder."
    )

    # Varsayılan hedef: gerçek konumdan ~2 km sapmış sahte nokta (Van, TR civarı)
    DEFAULT_LAT = 38.5012
    DEFAULT_LON = 43.4089

    def run(self, component_config: dict) -> Finding:
        comp_id = component_config.get("id", "unknown")
        lat = float(self.config.get("spoof_lat", self.DEFAULT_LAT))
        lon = float(self.config.get("spoof_lon", self.DEFAULT_LON))

        try:
            accepted = self.adapter.inject_gps_spoof(lat, lon)
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="GPS Spoof: Adaptör desteklemiyor",
                description=(
                    "Bu test için CARLA/GNSS simülasyon adaptörü gerekli. "
                    "Fiziksel SDR tabanlı spoofing yalnızca yetkili sahada yapılır."
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
                title=f"GPS Spoof: Sahte konum kabul edildi ({lat:.4f}, {lon:.4f})",
                description=(
                    "Enjekte edilen sahte GNSS konumu konumlandırma yığını tarafından "
                    "reddedilmeden kabul edildi. Araç, gerçek konumundan sapmış bir "
                    "koordinatta olduğuna inandırılabilir.\n\n"
                    "Sabit güzergâhlı otonom otobüste bu; yanlış durak, yanlış şerit "
                    "veya güzergâh dışına yönlendirme gibi doğrudan güvenlik (safety) "
                    "sonuçları doğurabilir."
                ),
                impact_safety="high",
                impact_operational="high",
                impact_privacy="low",
                attack_feasibility="medium",
                remediation=(
                    "1. Çoklu sensör füzyonu (GNSS + IMU + LiDAR/harita) ile konum "
                    "makullük kontrolü uygula. "
                    "2. Ani/fiziksel olarak imkânsız konum sıçramalarını reddet "
                    "(ki-kare residual / RAIM). "
                    "3. Mümkünse imzalı GNSS (Galileo OSNMA) desteği ekle. "
                    "4. Konum güvenilirliği düştüğünde güvenli duruş (fail-safe) tetikle."
                ),
                cvss_score=7.4,
            )
        return Finding(
            component_id=comp_id,
            test_module_id=self.module_id,
            r155_vector_id=self.r155_vector_id,
            r155_category=self.r155_category,
            status="not_vulnerable",
            title="GPS Spoof: Sahte konum reddedildi",
            description=(
                "Enjekte edilen sahte konum konumlandırma yığını tarafından "
                "reddedildi — makullük kontrolü / sensör füzyonu çalışıyor görünüyor."
            ),
            attack_feasibility="high",
        )
