"""
GÖKTÜRK — ROS2/DDS Topic Keşfi Modülü
SROS2 kapalıysa herhangi bir düğüm tüm topic'leri
kimlik doğrulaması olmadan listeleyebilir.

R155-5.6: ROS2/DDS kimliksiz topic erişimi
"""

from ..base_plugin import BasePlugin, Finding


class ROS2TopicEnumPlugin(BasePlugin):
    module_id = "ros2-topic-enum"
    name = "ROS2/DDS Topic Keşfi"
    surface = "ros2-dds"
    technique = "enumeration"
    r155_vector_id = "R155-5.6"
    r155_category = 5
    avcat_id = "ROS2-ENUM"
    applicable_adapters = ["ros2", "simulation"]
    severity_hint = "medium"
    description = (
        "ROS2 DDS domain'ındaki tüm topic, node ve servis bilgilerini "
        "kimlik doğrulaması gerektirmeden listeler."
    )

    SENSITIVE_KEYWORDS = [
        "/cmd_vel", "/vehicle_cmd", "/control",
        "/steering", "/brake", "/throttle",
        "/emergency", "/lidar", "/camera", "/gps",
        "/localization", "/planning", "/trajectory",
    ]

    def run(self, component_config: dict) -> Finding:
        comp_id = component_config.get("id", "unknown")
        try:
            topics = self.adapter.list_topics()
        except NotImplementedError:
            # Adapter desteklemiyorsa placeholder döndür
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="ROS2 Topic Enum: Adaptör desteklemiyor",
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
                title="ROS2 Topic Enum: Topic bulunamadı",
                description="Domain'da aktif topic yok veya SROS2 erişimi tamamen kısıtlıyor.",
            )

        # Hassas topic'leri bul
        sensitive = [
            t for t in topics
            if any(kw in t.get("name", "").lower() for kw in self.SENSITIVE_KEYWORDS)
        ]

        topic_list = "\n".join(
            f"  • {t.get('name', '?')}: {t.get('type', '?')}" for t in topics[:30]
        )
        sensitive_list = "\n".join(f"  ⚠ {t.get('name', '?')}" for t in sensitive)

        if sensitive:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                avcat_id=self.avcat_id,
                status="vulnerable",
                title=f"ROS2 Topic Enum: {len(sensitive)} kritik topic erişilebilir",
                description=(
                    f"Kimlik doğrulaması olmadan {len(topics)} topic listelendi; "
                    f"{len(sensitive)} tanesi kritik kontrol/algı topic'i.\n\n"
                    f"Kritik topic'ler:\n{sensitive_list}\n\n"
                    f"Tüm topic'ler ({min(len(topics),30)}/{len(topics)}):\n{topic_list}"
                ),
                impact_safety="high",
                impact_operational="high",
                attack_feasibility="medium",
                remediation=(
                    "1. SROS2'yi etkinleştir ve tüm node'lar için politika dosyaları yaz. "
                    "2. DDS Domain ID'yi güçlendirme ile kısıtla. "
                    "3. Kritik topic'lere yalnızca yetkili node'ların erişimini sağla. "
                    "4. ROS2 ağını güvenilir olmayan ağlardan izole et."
                ),
                cvss_score=6.5,
            )
        else:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="not_vulnerable",
                title=f"ROS2 Topic Enum: Kritik topic görünmüyor ({len(topics)} topic)",
                description=(
                    f"{len(topics)} topic listelendi ama hiçbiri kritik kontrol "
                    f"topic'i değil veya SROS2 gizliyor.\n\n{topic_list}"
                ),
            )
