"""
GÖKTÜRK — Mock (Sahte) Adaptör
Donanımsız / CI ortamında tüm test modüllerini deterministik olarak
çalıştırmak için sahte bir araç hedefi simüle eder.

Üç mod:
    - "vulnerable" : hedef zafiyetli davranır (plugin'ler 'vulnerable' üretir)
    - "secure"     : koruma mekanizmaları aktif ('not_vulnerable' üretir)
    - "empty"      : hedef sessiz / erişilemez ('inconclusive' üretir)

`as_type` config anahtarı ile başka bir adaptörü taklit edebilir; böylece
plugin'lerin `applicable_adapters` ön koşul kontrolü CI'da da geçer.
Örn:  MockAdapter({"mode": "vulnerable", "as_type": "socketcan"})
"""

import random
import time
from typing import Any, Dict, List, Optional

from .base_adapter import BaseAdapter

VALID_MODES = ("vulnerable", "secure", "empty")

_SENSITIVE_TOPICS = [
    {"name": "/cmd_vel", "type": "geometry_msgs/msg/Twist"},
    {"name": "/vehicle_cmd", "type": "autoware_msgs/msg/VehicleCmd"},
    {"name": "/lidar/points", "type": "sensor_msgs/msg/PointCloud2"},
    {"name": "/gps/fix", "type": "sensor_msgs/msg/NavSatFix"},
    {"name": "/planning/trajectory", "type": "autoware_msgs/msg/Trajectory"},
]

_BENIGN_TOPICS = [
    {"name": "/rosout", "type": "rcl_interfaces/msg/Log"},
    {"name": "/diagnostics", "type": "diagnostic_msgs/msg/DiagnosticArray"},
    {"name": "/clock", "type": "rosgraph_msgs/msg/Clock"},
]

# obd2/uds plugin'in sorguladığı güvenlik-kritik servisler
_SENSITIVE_UDS = (0x27, 0x2E, 0x31, 0x34)


class MockAdapter(BaseAdapter):
    """Deterministik sahte araç hedefi (donanımsız test için)."""

    adapter_type = "mock"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config or {})
        self.mode = (config or {}).get("mode", "vulnerable")
        if self.mode not in VALID_MODES:
            raise ValueError(
                f"Geçersiz mock modu: {self.mode!r}. Geçerli: {VALID_MODES}"
            )
        # İstenirse başka bir adaptör tipini taklit et (ön koşul kontrolü için)
        self.adapter_type = (config or {}).get("as_type", "mock")
        random.seed((config or {}).get("seed", 1337))

    # ── Bağlantı ─────────────────────────────────────────────────────────────

    def connect(self) -> bool:
        self._connected = True
        return True

    def disconnect(self) -> None:
        self._connected = False

    def is_connected(self) -> bool:
        return self._connected

    # ── CAN / araç içi ağ ────────────────────────────────────────────────────

    def receive_frames(self, count: int = 10, timeout: float = 1.0) -> List[Dict]:
        if self.mode == "empty":
            return []
        frames = []
        for _ in range(min(count, 8)):
            data = [random.randint(0, 255) for _ in range(8)]
            arb = random.choice([0x100, 0x1A0, 0x244, 0x3E9])
            frames.append({
                "arb_id": arb,
                "extended": False,
                "dlc": 8,
                "data": data,
                "hex": " ".join(f"{b:02X}" for b in data),
                "timestamp": time.time(),
            })
        return frames

    def send_frame(self, frame: Dict[str, Any]) -> bool:
        # secure modda gateway sahte/replay çerçeveyi düşürür
        return self.mode != "secure"

    def fuzz_frames(self, arb_id: int, count: int = 100) -> List[Dict]:
        if self.mode == "empty":
            return []  # hedef sessiz / erişilemez → sonuç yok
        results = []
        for i in range(count):
            data = [random.randint(0, 255) for _ in range(8)]
            if self.mode == "secure":
                sent, anomaly = False, False          # ingress filtresi engelliyor
            else:  # vulnerable
                sent = True
                anomaly = (i % 17 == 0)                # ara sıra ECU anomali/çökme
            results.append({
                "frame": {"arb_id": arb_id, "data": data},
                "sent": sent,
                "anomaly": anomaly,
            })
        return results

    # ── UDS / Teşhis ─────────────────────────────────────────────────────────

    def uds_request(self, service_id: int, sub_func: int = 0, data: bytes = b"") -> Optional[bytes]:
        if self.mode == "empty":
            return None  # port erişilemez
        positive = bytes([service_id + 0x40, sub_func])
        negative = bytes([0x7F, service_id, 0x33])  # 0x33 = securityAccessDenied
        if service_id == 0x10:  # oturum başlatma her iki modda da açılır
            return positive
        if self.mode == "secure":
            return negative
        # vulnerable: güvenlik-kritik servisler dahil pozitif yanıt
        return positive

    # ── ROS2 / DDS ───────────────────────────────────────────────────────────

    def list_topics(self) -> List[Dict]:
        if self.mode == "empty":
            return []
        if self.mode == "secure":
            return list(_BENIGN_TOPICS)  # SROS2 kritik topic'leri gizler
        return _SENSITIVE_TOPICS + _BENIGN_TOPICS

    def subscribe_topic(self, topic: str, msg_type: str, duration: float = 1.0) -> List[Any]:
        if self.mode == "empty":
            return []
        return [{"topic": topic, "type": msg_type, "seq": i} for i in range(3)]

    def publish_topic(self, topic: str, msg_type: str, data: Any) -> bool:
        return self.mode == "vulnerable"

    # ── Simülasyon / sensör ───────────────────────────────────────────────────

    def inject_gps_spoof(self, lat: float, lon: float, alt: float = 0.0) -> bool:
        # secure modda sensör füzyonu / makullük kontrolü sahte konumu reddeder
        return self.mode == "vulnerable"

    def inject_lidar_spoof(self, mode: str = "remove", target: Optional[str] = None) -> bool:
        return self.mode == "vulnerable"
