"""
GÖKTÜRK — CAN Replay Test Modülü
Taktik: yakalanan CAN çerçevesini tekrar göndererek
kimlik doğrulama eksikliğini tespit eder.

R155-2.5: Replay saldırısı
"""

from ..base_plugin import BasePlugin, Finding


class CANReplayPlugin(BasePlugin):
    module_id = "can-replay"
    name = "CAN Replay Saldırısı"
    surface = "in-vehicle-network"
    technique = "replay"
    r155_vector_id = "R155-2.5"
    r155_category = 2
    avcat_id = "IVN-REPLAY"
    applicable_adapters = ["socketcan", "carla"]
    severity_hint = "high"
    description = (
        "CAN bus üzerinde bir çerçeve yakalar ve aynısını tekrar göndererek "
        "mesaj kimlik doğrulamasının olmadığını doğrular."
    )

    def run(self, component_config: dict) -> Finding:
        comp_id = component_config.get("id", "unknown")
        interface = component_config.get("interface", "vcan0")

        try:
            # 1. Trafiği yakala
            frames = self.adapter.receive_frames(count=20, timeout=2.5)

            if not frames:
                return Finding(
                    component_id=comp_id,
                    test_module_id=self.module_id,
                    r155_vector_id=self.r155_vector_id,
                    r155_category=self.r155_category,
                    status="inconclusive",
                    title="CAN Replay: Trafik alınamadı",
                    description=(
                        f"'{interface}' üzerinde {2.5}s içinde CAN çerçevesi yakalanamadı. "
                        "ICSim çalışıyor mu? Arayüz aktif mi?"
                    ),
                    attack_feasibility="unknown",
                )

            # 2. İlk çerçeveyi seç ve tekrar gönder
            frame = frames[0]
            success = self.adapter.send_frame(frame)
            arb_hex = f"0x{frame.get('arb_id', 0):03X}"

            if success:
                return Finding(
                    component_id=comp_id,
                    test_module_id=self.module_id,
                    r155_vector_id=self.r155_vector_id,
                    r155_category=self.r155_category,
                    avcat_id=self.avcat_id,
                    status="vulnerable",
                    title=f"CAN Replay: Kimlik doğrulama YOK ({arb_hex})",
                    description=(
                        f"'{interface}' üzerinde yakalanan CAN çerçevesi başarıyla tekrar gönderildi.\n"
                        f"Arbitration ID: {arb_hex} | "
                        f"DLC: {frame.get('dlc', 0)} | "
                        f"Data: {frame.get('hex', '??')}\n\n"
                        "CAN protokolü tasarım gereği kimlik doğrulama içermez. "
                        "Bu beklenen ama belgelenmesi ve değerlendirilmesi gereken bir durumdur."
                    ),
                    impact_safety="medium",
                    impact_operational="high",
                    impact_financial="low",
                    attack_feasibility="medium",  # fiziksel/ağ erişimi gerekiyor
                    remediation=(
                        "1. CAN mesaj kimlik doğrulama (MAC) mekanizması ekle (örn. AUTOSAR SecOC). "
                        "2. Kritik mesajlar için Automotive Ethernet + SOME/IP geçişini değerlendir. "
                        "3. Gateway ECU'da replay koruması (zaman damgası / sayaç) uygula."
                    ),
                    cvss_score=5.7,
                )
            else:
                return Finding(
                    component_id=comp_id,
                    test_module_id=self.module_id,
                    r155_vector_id=self.r155_vector_id,
                    r155_category=self.r155_category,
                    status="not_vulnerable",
                    title="CAN Replay: Gönderme engellendi",
                    description=(
                        f"Çerçeve yakalandı ({arb_hex}) ama tekrar gönderme başarısız oldu. "
                        "Muhtemelen bir koruma mekanizması devrede."
                    ),
                    attack_feasibility="high",
                )

        except Exception as e:
            return self.make_error_finding(comp_id, e)
