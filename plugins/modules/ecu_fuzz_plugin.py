"""
GÖKTÜRK — ECU Firmware Fuzzing Test Modülü
Taktik: bir ECU'ya yapılandırılmış fuzzing girdileri (dumb / smart /
replay-mutate) göndererek girdi doğrulama eksikliğini, bellek bozulması
(buffer overflow) belirtilerini VE mantık hatası/yarış koşulu kaynaklı
yanıtsızlık (hang) belirtilerini ayrı ayrı tespit eder.

CAN Fuzz (R155-2.2) ağ katmanında mesaj enjeksiyonunu ölçerken, bu modül
ECU'nun KENDİSİNİ (firmware/bellek) hedefler.

İki sinyal, İKİ AYRI R155 vektörüne çapalanır:
  - memory_fault → R155-6.8 (arabellek taşması / bellek bozulması istismarı)
  - hang         → R155-6.9 (yarış koşulu / mantık hatası istismarı — girdi,
                    ECU'yu çökertmeden ama yanıt vermez hale getirerek bir
                    mantık/senkronizasyon hatasını tetikler)

Her ikisi de gözlemlenirse, her biri KENDİ R155 vektörüyle AYRI bir Finding
olarak raporlanır (List[Finding]) — böylece iki vektör de kapsam sayımına
doğru şekilde yansır; hiçbiri diğerinin gölgesinde kaybolmaz.
"""

from ..base_plugin import BasePlugin, Finding

_MEMORY_FAULT_VECTOR = "R155-6.8"
_HANG_VECTOR = "R155-6.9"


class ECUFuzzPlugin(BasePlugin):
    module_id = "ecu-fuzz"
    name = "ECU Firmware Fuzzing"
    surface = "firmware"
    technique = "fuzzing"
    r155_vector_id = _MEMORY_FAULT_VECTOR
    r155_category = 6
    avcat_id = "ECU-MEMFUZZ"
    applicable_adapters = ["socketcan", "carla"]
    severity_hint = "high"
    description = (
        "Bir ECU'ya yapılandırılmış fuzzing girdileri göndererek bellek "
        "bozulması (R155-6.8) ve yarış koşulu/mantık hatası kaynaklı "
        "yanıtsızlık (R155-6.9) belirtilerini ayrı ayrı tespit eder."
    )

    applicable_component_categories = ("compute", "network", "ecu")

    DEFAULT_MODE = "smart"
    DEFAULT_COUNT = 200

    def run(self, component_config: dict):
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

        findings = []

        if mem_faults:
            findings.append(Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=_MEMORY_FAULT_VECTOR,
                r155_category=self.r155_category,
                avcat_id=self.avcat_id,
                status="vulnerable",
                title=f"ECU Fuzz: Bellek bozulması tetiklendi ({comp_id}) — {mem_faults} fault",
                description=(
                    f"'{comp_id}' hedefine gönderilen {len(results)} {mode} fuzzing "
                    f"girdisinden {accepted} tanesi işlendi; {mem_faults} tanesi "
                    "bellek bozulması (buffer overflow / memory corruption) "
                    "tetikledi.\n\n"
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
            ))

        if hangs:
            findings.append(Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=_HANG_VECTOR,
                r155_category=self.r155_category,
                avcat_id=self.avcat_id,
                status="vulnerable",
                title=f"ECU Fuzz: Yanıtsızlık/hang tetiklendi ({comp_id}) — {hangs} hang",
                description=(
                    f"'{comp_id}' hedefine gönderilen {len(results)} {mode} fuzzing "
                    f"girdisinden {accepted} tanesi işlendi; {hangs} tanesi ECU'yu "
                    "çökertmeden ama yanıt vermez hale getirdi (hang).\n\n"
                    "Çökme veya bellek bozulması olmadan yanıtsız kalması, "
                    "genellikle bir yarış koşulu (race condition), kilitlenme "
                    "(deadlock) veya durum makinesi mantık hatasına işaret eder. "
                    "Sürekli işlem gerektiren güvenlik-kritik bir ECU'nun "
                    "yanıtsız kalması, kendi başına bir DoS ve operasyonel "
                    "süreklilik riskidir."
                ),
                impact_safety="high",
                impact_operational="high",
                impact_financial="low",
                attack_feasibility="medium",
                remediation=(
                    "1. Durum makinesi/kilitleme mantığını yarış koşulu analizi "
                    "(ör. statik analiz, ThreadSanitizer) ile denetle. "
                    "2. Kritik işlemlere watchdog zaman aşımı ve otomatik kurtarma "
                    "(recovery) ekle. "
                    "3. Girdi işleme sırasına bağlı senkronizasyon varsayımlarını "
                    "kaldır; durum geçişlerini idempotent ve zaman aşımlı tasarla. "
                    "4. Fuzzing'i CI güvenlik test hattına dahil ederek "
                    "regresyonları erken yakala."
                ),
                cvss_score=6.5,
            ))

        if findings:
            return findings

        return Finding(
            component_id=comp_id,
            test_module_id=self.module_id,
            r155_vector_id=_MEMORY_FAULT_VECTOR,
            r155_category=self.r155_category,
            avcat_id=self.avcat_id,
            status="vulnerable",
            title=f"ECU Fuzz: Girdiler doğrulanmadan işlendi ({comp_id})",
            description=(
                f"{accepted}/{len(results)} {mode} fuzzing girdisi ECU tarafından "
                "reddedilmeden işlendi. Çökme veya hang gözlenmedi ancak girdi "
                "doğrulama eksikliği, daha hedefli bir saldırıyla bellek "
                "bozulmasına yol açabilir."
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
