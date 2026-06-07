"""
GÖKTÜRK — SocketCAN Adaptörü
Linux vcan / gerçek CAN bus bağlantısı.

Lab kurulumu (sanal CAN):
    sudo modprobe vcan
    sudo ip link add dev vcan0 type vcan
    sudo ip link set up vcan0
    # Test: cangen vcan0 &   (trafik üret)
"""

import socket
import struct
import time
import random
import os
from typing import Any, Dict, List, Optional

from .base_adapter import BaseAdapter

CAN_FRAME_FMT = "=IB3x8s"
CAN_FRAME_SIZE = struct.calcsize(CAN_FRAME_FMT)  # 16 bytes


class SocketCANAdapter(BaseAdapter):
    """Linux SocketCAN üzerinden CAN/CAN-FD erişimi."""

    adapter_type = "socketcan"

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.interface = config.get("interface", "vcan0")
        self._sock: Optional[socket.socket] = None

    def connect(self) -> bool:
        if not self._interface_exists():
            raise ConnectionError(
                f"CAN arayüzü bulunamadı: {self.interface}\n"
                f"Sanal CAN için:\n"
                f"  sudo modprobe vcan\n"
                f"  sudo ip link add dev {self.interface} type vcan\n"
                f"  sudo ip link set up {self.interface}"
            )
        try:
            self._sock = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
            self._sock.bind((self.interface,))
            self._sock.setblocking(False)
            self._connected = True
            return True
        except OSError as e:
            self._connected = False
            raise ConnectionError(f"SocketCAN bağlantı hatası ({self.interface}): {e}")

    def disconnect(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        self._connected = False

    def is_connected(self) -> bool:
        return self._connected and self._sock is not None

    def _interface_exists(self) -> bool:
        return os.path.exists(f"/sys/class/net/{self.interface}")

    # ── CAN İşlemleri ─────────────────────────────────────────────────────────

    def send_frame(self, frame: Dict[str, Any]) -> bool:
        """CAN çerçevesi gönder."""
        if not self.is_connected():
            return False
        arb_id = int(frame.get("arb_id", 0))
        data = bytes(frame.get("data", [0x00]))[:8]
        dlc = len(data)
        raw = struct.pack(CAN_FRAME_FMT, arb_id, dlc, data.ljust(8, b"\x00"))
        try:
            self._sock.send(raw)
            return True
        except (OSError, BlockingIOError):
            return False

    def receive_frames(self, count: int = 10, timeout: float = 2.0) -> List[Dict]:
        """CAN çerçevelerini yakala."""
        if not self.is_connected():
            return []
        frames = []
        deadline = time.monotonic() + timeout
        while len(frames) < count and time.monotonic() < deadline:
            try:
                raw = self._sock.recv(CAN_FRAME_SIZE)
                if len(raw) < CAN_FRAME_SIZE:
                    continue
                arb_id, dlc = struct.unpack_from("=IB", raw)
                data = list(raw[4:4 + min(dlc, 8)])
                frames.append({
                    "arb_id": arb_id & 0x1FFFFFFF,
                    "extended": bool(arb_id & 0x80000000),
                    "dlc": dlc,
                    "data": data,
                    "hex": " ".join(f"{b:02X}" for b in data),
                    "timestamp": time.time(),
                })
            except BlockingIOError:
                time.sleep(0.005)
            except OSError:
                break
        return frames

    def fuzz_frames(self, arb_id: int, count: int = 100, delay: float = 0.01) -> List[Dict]:
        """Belirtilen arb_id için rastgele payload fuzzing."""
        results = []
        for _ in range(count):
            frame = {
                "arb_id": arb_id,
                "data": [random.randint(0, 255) for _ in range(8)],
            }
            sent = self.send_frame(frame)
            results.append({"frame": frame, "sent": sent})
            if delay:
                time.sleep(delay)
        return results
