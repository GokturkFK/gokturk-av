"""
GÖKTÜRK — Adversarial ML / Algı Manipülasyonu Test Modülü
Taktik: algı ML modeline (kamera/LiDAR nesne tanıma) karşı adversarial bir
perturbation (fiziksel yama veya Lp-sınırlı gürültü) uygulayıp modelin yanlış
sınıflandırma yapıp yapmadığını ölçer.

LiDAR/kamera SPOOFING'den (R155-2.9 — ham sensör verisine sahte veri
enjeksiyonu) farkı: burada sensör verisi DOĞRU gelir; saldırı, modelin karar
katmanını hedefler. Klasik örnek: yola/işarete yapıştırılan adversarial patch
ile "dur" işaretini "hız limiti" olarak okutma.

Savunma tarafı (adversarial training, girdi temizleme/tespit) gerçekten çalışıp
çalışmadığı test edilir.

R155-6.7: Adversarial ML / algı manipülasyonu
"""

from ..base_plugin import BasePlugin, Finding


class AdversarialMLPlugin(BasePlugin):
    module_id = "adversarial-ml"
    name = "Adversarial ML / Algı Manipülasyonu"
    surface = "sensor"
    technique = "adversarial-perturbation"
    r155_vector_id = "R155-6.7"
    r155_category = 6
    avcat_id = "PERCEPTION-ADV-ML"
    applicable_adapters = ["carla", "simulation"]
    severity_hint = "critical"
    description = (
        "Algı ML modeline adversarial patch/gürültü uygulayarak yanlış "
        "sınıflandırma tetiklemeyi dener (ör. 'dur' işaretini 'hız limiti' "
        "olarak okutma). Adversarial savunmanın çalışıp çalışmadığını ölçer."
    )

    DEFAULT_SENSOR = "camera"
    DEFAULT_TECHNIQUE = "patch"

    def run(self, component_config: dict) -> Finding:
        comp_id = component_config.get("id", "unknown")
        # Sensör tipi: açıkça config'te verilmişse onu kullan; yoksa bileşen
        # kimliğinden/kategorisinden çıkar (lidar_* → lidar, aksi halde camera).
        default_sensor = "lidar" if "lidar" in comp_id.lower() else self.DEFAULT_SENSOR
        sensor = str(self.config.get("adv_sensor", default_sensor))
        technique = str(self.config.get("adv_technique", self.DEFAULT_TECHNIQUE))

        try:
            res = self.adapter.inject_adversarial_perturbation(
                target=comp_id, sensor=sensor, technique=technique
            )
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="Adversarial ML: Adaptör desteklemiyor",
                description=(
                    "Bu test için bir algı modeli barındıran CARLA/simülasyon "
                    "adaptörü gerekli. Fiziksel adversarial patch testi yalnızca "
                    "yetkili sahada/tezgâhta yapılır."
                ),
            )
        except Exception as e:
            return self.make_error_finding(comp_id, e)

        original = res.get("original", "?")
        adversarial = res.get("adversarial", "?")

        if res.get("fooled"):
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                avcat_id=self.avcat_id,
                status="vulnerable",
                title=(
                    f"Adversarial ML: Model yanıltıldı ({sensor}/{technique}) — "
                    f"'{original}' → '{adversarial}'"
                ),
                description=(
                    f"'{comp_id}' algı modeline uygulanan adversarial {technique} "
                    f"({sensor}) saldırısı başarılı oldu: model, doğru tahmini "
                    f"'{original}' yerine '{adversarial}' üretti.\n\n"
                    "Girdi doğru sensör verisi olduğu için klasik tutarlılık/"
                    "füzyon kontrolleri bu saldırıyı yakalayamaz; adversarial "
                    "savunma katmanı devrede değil. Otonom sürüşte yanlış "
                    "sınıflandırma doğrudan hatalı karar (fren/hızlanma/manevra) "
                    "ve güvenlik (safety) riski demektir."
                ),
                impact_safety="critical",
                impact_operational="high",
                attack_feasibility="medium",
                remediation=(
                    "1. Adversarial training ile modeli sağlamlaştır (robust training). "
                    "2. Girdi ön-işleme/temizleme (input sanitization, feature "
                    "squeezing) ve adversarial örnek tespiti ekle. "
                    "3. Çok-sensörlü füzyon ile karar tutarlılığını çapraz doğrula "
                    "(kamera ↔ LiDAR ↔ harita/HD-map). "
                    "4. Güvenlik-kritik sınıflar için güven eşiği + insan/sistem "
                    "yedekleme (fail-safe) davranışı tanımla."
                ),
                cvss_score=8.1,
            )

        if res.get("defended"):
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                status="not_vulnerable",
                title=f"Adversarial ML: Savunma perturbation'ı reddetti ({sensor})",
                description=(
                    f"'{comp_id}' modeline uygulanan adversarial {technique} "
                    f"saldırısı adversarial savunma tarafından etkisiz kılındı; "
                    f"model doğru tahmini ('{original}') korudu."
                ),
                attack_feasibility="high",
            )

        return Finding(
            component_id=comp_id,
            test_module_id=self.module_id,
            r155_vector_id=self.r155_vector_id,
            status="inconclusive",
            title="Adversarial ML: Model yanıt vermedi",
            description=(
                f"'{comp_id}' algı hattı adversarial girdiye yanıt üretmedi "
                "(model erişilemez veya sessiz)."
            ),
            attack_feasibility="unknown",
        )
