"""
GÖKTÜRK — ROS2/DDS Mesaj Enjeksiyonu Modülü
Taktik: ros2-topic-enum'un bulduğu kritik kontrol/algı topic'lerine
kimlik doğrulaması olmadan doğrudan mesaj basmayı dener. Sadece dinleme
(enumeration) değil, aktif enjeksiyonun mümkün olup olmadığını ölçer.

R155-5.7: ROS2/DDS mesaj enjeksiyonu
"""

from ..base_plugin import BasePlugin, Finding

# ros2-topic-enum ile aynı hassas topic listesi — iki modül aynı taksonomiyi paylaşır
SENSITIVE_TOPICS = [
    ("/cmd_vel", "geometry_msgs/msg/Twist"),
    ("/vehicle_cmd", "autoware_msgs/msg/VehicleCmd"),
    ("/emergency", "std_msgs/msg/Bool"),
    ("/steering", "autoware_msgs/msg/SteeringCommand"),
    ("/brake", "autoware_msgs/msg/BrakeCommand"),
]


class ROS2TopicInjectionPlugin(BasePlugin):
    module_id = "ros2-topic-injection"
    name = "ROS2/DDS Mesaj Enjeksiyonu"
    surface = "ros2-dds"
    technique = "injection"
    r155_vector_id = "R155-5.7"
    r155_category = 5
    avcat_id = "ROS2-INJECT"
    applicable_adapters = ["ros2", "simulation"]
    severity_hint = "critical"
    description = (
        "Kritik kontrol/algı topic'lerine kimlik doğrulaması olmadan doğrudan "
        "mesaj basmayı dener; ros2-topic-enum'un tespit ettiği erişimin "
        "salt-okunur mu yoksa yazılabilir mi olduğunu doğrular."
    )

    def run(self, component_config: dict) -> Finding:
        comp_id = component_config.get("id", "unknown")

        try:
            topics = self.adapter.list_topics()
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="ROS2 Enjeksiyon: Adaptör desteklemiyor",
                description="Bu test için ROS2 veya simülasyon adaptörü gerekli.",
            )
        except Exception as e:
            return self.make_error_finding(comp_id, e)

        if not topics:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="ROS2 Enjeksiyon: Topic bulunamadı",
                description="Domain'da aktif topic yok; enjeksiyon denenecek hedef yok.",
            )

        live_names = {t.get("name", "") for t in topics}
        candidates = [
            (name, msg_type) for name, msg_type in SENSITIVE_TOPICS
            if name in live_names
        ] or SENSITIVE_TOPICS[:1]  # hiçbiri listede değilse en azından bir tanesini dene

        injected = []
        for name, msg_type in candidates:
            try:
                ok = self.adapter.publish_topic(name, msg_type, {"probe": True})
            except NotImplementedError:
                ok = False
            except Exception:
                ok = False
            if ok:
                injected.append(name)

        if injected:
            injected_list = "\n".join(f"  ⚠ {n}" for n in injected)
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                avcat_id=self.avcat_id,
                status="vulnerable",
                title=f"ROS2 Enjeksiyon: {len(injected)} kritik topic'e yazılabildi",
                description=(
                    f"Aşağıdaki kontrol/algı topic'lerine kimlik doğrulaması olmadan "
                    f"sahte mesaj başarıyla basıldı:\n\n{injected_list}\n\n"
                    "Bu, ros2-topic-enum'daki 'görünürlük' bulgusunun ötesine geçer: "
                    "saldırgan yalnızca dinlemekle kalmıyor, aracın davranışını "
                    "doğrudan komutlayabiliyor (örn. sahte durdurma/direksiyon komutu)."
                ),
                impact_safety="critical",
                impact_operational="high",
                attack_feasibility="medium",
                remediation=(
                    "1. SROS2/DDS-Security ile mesaj imzalama ve erişim kontrol listesi (ACL) uygula. "
                    "2. Kritik topic'lere yalnızca yetkili, sertifikalı node'ların publish etmesine izin ver. "
                    "3. Komut topic'lerinde plausibility/rate-limiting katmanı ekle (ör. ani, fiziksel "
                    "olarak imkânsız komutları reddet). "
                    "4. DDS domain'ini ağ segmentasyonu ile izole et."
                ),
                cvss_score=8.6,
            )

        return Finding(
            component_id=comp_id,
            test_module_id=self.module_id,
            r155_vector_id=self.r155_vector_id,
            r155_category=self.r155_category,
            status="not_vulnerable",
            title="ROS2 Enjeksiyon: Kritik topic'lere yazma engellendi",
            description=(
                f"{len(candidates)} kritik topic denendi, hiçbirine mesaj basılamadı. "
                "SROS2/DDS-Security erişim kontrolü çalışıyor görünüyor."
            ),
            attack_feasibility="high",
        )
