"""
GÖKTÜRK — CAN Fuzzing Test Modülü
Taktik: bir arbitration ID'ye rastgele/yapılandırılmış payload akıtarak
mesaj enjeksiyonuna karşı giriş filtresinin olup olmadığını ve
beklenmedik ECU davranışlarını (anomali/çökme) tespit eder.

R155-2.2: Mesaj enjeksiyonu (CAN, Ethernet)
"""

from ..base_plugin import BasePlugin, Finding


class CANFuzzPlugin(BasePlugin):
    module_id = "can-fuzz"
    name = "CAN Fuzzing (Mesaj Enjeksiyonu)"
    surface = "in-vehicle-network"
    technique = "fuzzing"
    r155_vector_id = "R155-2.2"
    r155_category = 2
    avcat_id = "IVN-FUZZ"
    applicable_adapters = ["socketcan", "carla"]
    severity_hint = "high"
    description = (
        "Hedef arbitration ID'ye rastgele payload'lar enjekte ederek "
        "giriş filtresinin yokluğunu ve fuzzing kaynaklı anomali/çökmeleri ölçer."
    )

    DEFAULT_ARB_ID = 0x244
    DEFAULT_COUNT = 200

    def run(self, component_config: dict) -> Finding:
        comp_id = component_config.get("id", "unknown")
        arb_id = int(component_config.get("arb_id", self.DEFAULT_ARB_ID))
        count = int(self.config.get("count", self.DEFAULT_COUNT))
        arb_hex = f"0x{arb_id:03X}"

        try:
            results = self.adapter.fuzz_frames(arb_id, count=count)
        except NotImplementedError:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="CAN Fuzz: Adaptör fuzzing desteklemiyor",
                description="Bu test için SocketCAN veya CARLA adaptörü gerekli.",
            )
        except Exception as e:
            return self.make_error_finding(comp_id, e)

        if not results:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                status="inconclusive",
                title="CAN Fuzz: Sonuç üretilemedi",
                description=f"{arb_hex} için fuzzing çerçevesi gönderilemedi.",
                attack_feasibility="unknown",
            )

        accepted = sum(1 for r in results if r.get("sent"))
        anomalies = sum(1 for r in results if r.get("anomaly"))

        if accepted == 0:
            return Finding(
                component_id=comp_id,
                test_module_id=self.module_id,
                r155_vector_id=self.r155_vector_id,
                r155_category=self.r155_category,
                status="not_vulnerable",
                title=f"CAN Fuzz: Enjeksiyon engellendi ({arb_hex})",
                description=(
                    f"{len(results)} fuzzing çerçevesinin tamamı reddedildi. "
                    "Gateway/ECU'da bir giriş (ingress) filtresi devrede görünüyor."
                ),
                attack_feasibility="high",
            )

        # En az bir çerçeve kabul edildi → enjeksiyon mümkün
        safety = "high" if anomalies else "medium"
        feasibility = "high" if anomalies else "medium"
        return Finding(
            component_id=comp_id,
            test_module_id=self.module_id,
            r155_vector_id=self.r155_vector_id,
            r155_category=self.r155_category,
            avcat_id=self.avcat_id,
            status="vulnerable",
            title=(
                f"CAN Fuzz: Enjeksiyon mümkün ({arb_hex}), "
                f"{anomalies} anomali"
            ),
            description=(
                f"{arb_hex} hedefine gönderilen {len(results)} fuzzing çerçevesinden "
                f"{accepted} tanesi bus'a kabul edildi; {anomalies} tanesi anormal "
                "ECU davranışı/çökme tetikledi.\n\n"
                "Kimlik doğrulaması ve giriş filtresi olmayan CAN hattına sahte "
                "mesaj enjekte edilebiliyor — R155-2.2 kapsamında dokümante edilmeli."
            ),
            impact_safety=safety,
            impact_operational="high",
            impact_financial="low",
            attack_feasibility=feasibility,
            remediation=(
                "1. Kritik CAN mesajları için AUTOSAR SecOC (MAC + freshness) uygula. "
                "2. Gateway ECU'da mesaj beyaz listesi / ingress filtreleme ekle. "
                "3. Anormal frekans/oran tespiti için araç içi IDS (IDPS) konumlandır. "
                "4. Kritik alt sistemleri ayrı, kimlik doğrulamalı ağ segmentlerine taşı."
            ),
            cvss_score=7.1 if anomalies else 6.0,
        )
