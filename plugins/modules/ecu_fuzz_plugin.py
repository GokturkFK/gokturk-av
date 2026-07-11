"""
GÖKTÜRK — ECU Firmware Fuzzing Test Modülü
Taktik: bir ECU'ya yapılandırılmış fuzzing girdileri (dumb / smart /
replay-mutate) göndererek girdi doğrulama eksikliğini ve bellek bozulması
(buffer overflow) / mantık hatası kaynaklı çökme belirtilerini tespit eder.

CAN Fuzz (R155-2.2) ağ katmanında mesaj enjeksiyonunu ölçerken, bu modül
ECU'nun KENDİSİNİ (firmware/bellek) hedefler ve bellek bozulması sinyallerini
arar.

R155-6.8: Arabellek taşması / bellek bozulması istismarı
(ikincil: R155-6.9 yarış koşulu / mantık hatası — 'hang' sinyaliyle)
"""

from ..base_plugin import BasePlugin, Finding


class ECUFuzzPlugin(BasePlugin):
    module_id = "ecu-fuzz"
    name = "ECU Firmware Fuzzing"
    surface = "firmware"
    technique = "fuzzing"
    r155_vector_id = "R155-6.8"
    r155_category = 6
    avcat_id = "ECU-MEMFUZZ"
    applicable_adapters = ["socketcan", "carla"]
    severity_hint = "high"
    description = (
        "Bir ECU'ya yapılandırılmış fuzzing girdileri göndererek girdi doğrulama "
        "eksikliğini ve bellek bozulması (buffer overflow) / mantık hatası "
        "kaynaklı çökmeleri tespit eder."
    )

    # Bu modülün hedeflediği bileşen kategorileri (orchestrator surface/vektör
    # eşleşmesine ek bağlamsal bilgi; zorunlu değil ama belge amaçlı).
    applicable_component_categories = ("compute", "network", "ecu")

    DEFAULT_MODE = "smart"       # dumb / smart / replay-mutate
    DEFAULT_COUNT = 200

    def run(self, component_config: dict) -> Finding:
        comp_id = component_config.get("id", "unknown")
        mode = str(self.config.get("fuzz_mode", self.DEFAULT_MODE))
        count = int(self.config.get("count", self.DEFAULT_COUNT))

        try:
            results = self.adapter.fuzz_ecu(comp_id, mode=mode, count=count)
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="ECU Fuzz: Adaptör desteklemiyor",
                description=(
                    "Bu test için SocketCAN, mock veya CARLA adaptörü gerekli. "
                    "Gerçek ECU fuzzing yalnızca yetkili tezgâh/sahada yapılır."
                ),
            )
        except Exception as e:
            return self.make_error_finding(comp_id, e)

        if not results:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="ECU Fuzz: ECU yanıt vermedi",
                description=(
                    f"'{comp_id}' hedefine {mode} fuzzing girdileri gönderildi ama "
                    "ECU hiç yanıt üretmedi (erişilemez veya sessiz)."
                ),
                attack_feasibility="unknown",
            )

        accepted = sum(1 for r in results if r.get("accepted"))
        mem_faults = sum(1 for r in results if r.get("memory_fault"))
        hangs = sum(1 for r in results if r.get("hang"))

        if accepted == 0:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                status="not_vulnerable",
                title=f"ECU Fuzz: Girdiler reddedildi ({comp_id})",
                description=(
                    f"{len(results)} {mode} fuzzing girdisinin tamamı ECU tarafından "
                    "reddedildi; bellek bozulması veya hang gözlenmedi. Girdi "
                    "doğrulama / bellek koruması devrede görünüyor."
                ),
                attack_feasibility="high",
            )

        # En az bir girdi işlendi → bellek bozulması sinyallerine bak
        if mem_faults or hangs:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                avcat_id=self.avcat_id,
                status="vulnerable",
                title=(
                    f"ECU Fuzz: Bellek bozulması tetiklendi ({comp_id}) — "
                    f"{mem_faults} fault, {hangs} hang"
                ),
                description=(
                    f"'{comp_id}' hedefine gönderilen {len(results)} {mode} fuzzing "
                    f"girdisinden {accepted} tanesi işlendi; {mem_faults} tanesi "
                    f"bellek bozulması (buffer overflow / memory corruption) ve "
                    f"{hangs} tanesi ECU hang (yanıtsızlık) tetikledi.\n\n"
                    "Bellek bozulması, kontrollü koşullarda rastgele kod yürütmeye "
                    "(RCE) kadar tırmanabilir; güvenlik-kritik bir ECU'da bu doğrudan "
                    "safety etkisi taşır."
                ),
                impact_safety="high",
                impact_operational="high",
                impact_financial="medium",
                attack_feasibility="medium",
                remediation=(
                    "1. Tüm harici girdilerde sıkı sınır/uzunluk doğrulaması uygula "
                    "(bounds checking). "
                    "2. Bellek-güvenli derleme korumaları etkinleştir (stack canary, "
                    "ASLR, DEP/NX, -D_FORTIFY_SOURCE). "
                    "3. Girdi ayrıştırıcılarını (parser) fuzzing ile CI'da sürekli test et. "
                    "4. Güvenlik-kritik ECU'ları bellek koruma birimi (MPU) ile izole et."
                ),
                cvss_score=8.2,
            )

        # Girdiler işlendi ama fault yok → zayıf ama net bir bulgu
        return Finding(
            component_id=comp_id,
            test_module_id=self.module_id,
            r155_vector_id=self.r155_vector_id,
            r155_category=self.r155_category,
            avcat_id=self.avcat_id,
            status="vulnerable",
            title=f"ECU Fuzz: Girdiler doğrulanmadan işlendi ({comp_id})",
            description=(
                f"{accepted}/{len(results)} {mode} fuzzing girdisi ECU tarafından "
                "reddedilmeden işlendi. Çökme gözlenmedi ancak girdi doğrulama "
                "eksikliği, daha hedefli bir saldırıyla bellek bozulmasına "
                "yol açabilir."
            ),
            impact_safety="medium",
            impact_operational="medium",
            attack_feasibility="medium",
            remediation=(
                "1. Girdi doğrulama ve uzunluk kontrolleri ekle. "
                "2. Fuzzing'i CI güvenlik test hattına dahil et. "
                "3. Bellek-güvenli derleme korumalarını etkinleştir."
            ),
            cvss_score=5.5,
        )
