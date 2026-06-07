"""
GÖKTÜRK — Temel Adaptör Sınıfı
Tüm araç bağlantı adaptörleri bu sınıfı miras alır.
Yeni otobüs modeli / protokol = bu sınıfı miras alan yeni bir adaptör.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseAdapter(ABC):
    """Abstract base for all vehicle target adapters.

    Çekirdek motor hiçbir zaman adaptörü doğrudan tanımaz;
    sadece bu arayüzü görür. Bu, aracın "ölmemesini" sağlar.
    """

    adapter_type: str = "base"

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self._connected = False

    @abstractmethod
    def connect(self) -> bool:
        """Hedefe bağlan. True = başarılı."""
        pass

    @abstractmethod
    def disconnect(self) -> None:
        pass

    @abstractmethod
    def is_connected(self) -> bool:
        pass

    # ── CAN / araç içi ağ ────────────────────────────────────────────────────

    def send_frame(self, frame: Dict[str, Any]) -> bool:
        raise NotImplementedError(f"{self.adapter_type}: send_frame desteklenmez")

    def receive_frames(self, count: int = 10, timeout: float = 1.0) -> List[Dict]:
        raise NotImplementedError(f"{self.adapter_type}: receive_frames desteklenmez")

    def fuzz_frames(self, arb_id: int, count: int = 100) -> List[Dict]:
        raise NotImplementedError(f"{self.adapter_type}: fuzz_frames desteklenmez")

    # ── UDS / Teşhis ─────────────────────────────────────────────────────────

    def uds_request(self, service_id: int, sub_func: int = 0, data: bytes = b"") -> Optional[bytes]:
        raise NotImplementedError(f"{self.adapter_type}: uds_request desteklenmez")

    # ── ROS2 / DDS ───────────────────────────────────────────────────────────

    def list_topics(self) -> List[Dict]:
        raise NotImplementedError(f"{self.adapter_type}: list_topics desteklenmez")

    def subscribe_topic(self, topic: str, msg_type: str, duration: float = 1.0) -> List[Any]:
        raise NotImplementedError(f"{self.adapter_type}: subscribe_topic desteklenmez")

    def publish_topic(self, topic: str, msg_type: str, data: Any) -> bool:
        raise NotImplementedError(f"{self.adapter_type}: publish_topic desteklenmez")

    # ── Simülasyon ────────────────────────────────────────────────────────────

    def inject_lidar_spoof(self, mode: str = "remove", target: Optional[str] = None) -> bool:
        raise NotImplementedError(f"{self.adapter_type}: inject_lidar_spoof desteklenmez")

    def inject_gps_spoof(self, lat: float, lon: float, alt: float = 0.0) -> bool:
        raise NotImplementedError(f"{self.adapter_type}: inject_gps_spoof desteklenmez")

    # ── Yardımcılar ──────────────────────────────────────────────────────────

    def get_info(self) -> Dict[str, Any]:
        return {
            "adapter_type": self.adapter_type,
            "config": self.config,
            "connected": self._connected,
        }

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.disconnect()

    def __repr__(self):
        return f"<{self.__class__.__name__} type={self.adapter_type} connected={self._connected}>"
