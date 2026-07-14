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

    def inject_adversarial_perturbation(
        self, target: str, sensor: str = "camera", technique: str = "patch"
    ) -> dict:
        # Kamera örneği: "dur" işaretini "hız limiti" olarak okutma (klasik senaryo).
        # LiDAR örneği: nesne sınıfını gizleme/değiştirme.
        pairs = {
            "camera": ("dur işareti", "hız limiti 80"),
            "lidar": ("yaya", "boş yol"),
        }
        original, adversarial = pairs.get(sensor, ("nesne A", "nesne B"))
        if self.mode == "empty":
            # Model yanıt vermiyor / algı hattı erişilemez
            return {"fooled": False, "defended": False,
                    "original": original, "adversarial": original}
        if self.mode == "secure":
            # Adversarial-savunma (ör. adversarial training / girdi temizleme) devrede:
            # perturbation tespit edilir, model doğru tahminini korur.
            return {"fooled": False, "defended": True,
                    "original": original, "adversarial": original}
        # vulnerable: savunma yok, model yanıltılır
        return {"fooled": True, "defended": False,
                "original": original, "adversarial": adversarial}

    def inject_v2x_message(self, msg_type: str = "BSM", signed: bool = False) -> bool:
        # İmzalı bir mesaj her modda kabul edilir (meşru trafik).
        # İmzasız/sahte mesaj yalnızca vulnerable modda kabul edilir;
        # secure modda PKI/SCMS imza doğrulaması onu reddeder.
        if signed:
            return True
        if self.mode == "empty":
            return False  # V2X yığını yanıt vermiyor
        return self.mode == "vulnerable"

    def v2x_attack_probe(self, target: str, scenario: str) -> Dict:
        # secure modda kimlik/sertifika çapraz doğrulaması + RSU güven listesi aktif.
        # vulnerable modda ikisi de yok. empty modda V2X yığını yanıtsız (korumalı sayılır).
        if self.mode == "empty":
            detail = {
                "identity_spoof": "V2X yığını yanıt vermiyor",
                "v2i_infra_trust": "V2I kanalı erişilemez",
            }.get(scenario, "Yanıt yok")
            return {"accepted": False, "detail": detail}
        if self.mode == "secure":
            detail = {
                "identity_spoof": "Sertifika/kimlik çapraz doğrulaması taklit edilen kimliği reddetti",
                "v2i_infra_trust": "RSU güven listesi doğrulaması yetkisiz altyapı komutunu reddetti",
            }.get(scenario, "Koruma aktif")
            return {"accepted": False, "detail": detail}
        # vulnerable
        detail = {
            "identity_spoof": "Taklit edilen kimlikle gönderilen mesaj meşru kabul edildi",
            "v2i_infra_trust": "Sahte RSU'dan gelen yetkisiz komut (hız/sinyal) doğrudan uygulandı",
        }.get(scenario, "Koruma atlatıldı")
        return {"accepted": True, "detail": detail}

    def fuzz_ecu(self, target_ecu: str, mode: str = "smart", count: int = 200) -> List[Dict]:
        if self.mode == "empty":
            return []  # ECU yanıt vermiyor / erişilemez
        results = []
        for i in range(count):
            if self.mode == "secure":
                # Girdi doğrulama + bellek koruması: girdiler reddedilir,
                # hiçbir bellek bozulması/hang tetiklenmez.
                results.append({"accepted": False, "memory_fault": False, "hang": False})
            else:  # vulnerable
                # Girdiler işleniyor; 'smart'/'replay-mutate' modları geçerli
                # çerçeve yapısı kullandığı için daha sık fault tetikler.
                if mode == "dumb":
                    memory_fault = (i % 40 == 0)
                    hang = (i % 90 == 0)
                else:  # smart / replay-mutate — daha etkili
                    memory_fault = (i % 20 == 0)
                    hang = (i % 60 == 0)
                results.append({
                    "accepted": True,
                    "memory_fault": memory_fault,
                    "hang": hang,
                })
        return results

    def ota_update_probe(self, target: str, scenario: str) -> Dict:
        # secure modda tüm OTA korumaları aktif (imza + versiyon + şifreleme).
        # vulnerable modda hepsi atlatılabilir. empty modda kanal yanıtsız.
        if self.mode == "empty":
            return {"accepted": False, "detail": "OTA kanalı yanıt vermiyor"}
        if self.mode == "secure":
            detail = {
                "rollback": "Versiyon kontrolü eski paketi reddetti",
                "bad_signature": "İmza doğrulama bozuk paketi reddetti",
                "plaintext": "Kanal TLS ile şifreli",
                "pre_update_tamper": "Build/staging bütünlük hash'i uyuşmazlığı yakaladı",
                "manifest_tamper": "Manifest ayrıca imzalı; değiştirilmiş meta veri reddedildi",
            }.get(scenario, "Koruma aktif")
            return {"accepted": False, "detail": detail}
        # vulnerable
        detail = {
            "rollback": "Eski sürüm imzalı paket kabul edildi (downgrade koruması yok)",
            "bad_signature": "Bozuk imzalı paket kabul edildi (imza doğrulama yok)",
            "plaintext": "OTA trafiği düz metin (şifreleme yok)",
            "pre_update_tamper": "Build/staging aşamasında değiştirilmiş paket fark edilmeden imzalandı",
            "manifest_tamper": "Manifest (versiyon/hedef ECU/hash) imzasız; değiştirilip kabul edildi",
        }.get(scenario, "Koruma atlatıldı")
        return {"accepted": True, "detail": detail}

    def backend_server_probe(self, target: str, scenario: str) -> Dict:
        # secure modda kimlik doğrulama sıkı + hız sınırlama (rate limiting) aktif.
        # vulnerable modda ikisi de yok. empty modda sunucu erişilemez.
        if self.mode == "empty":
            return {"accepted": False, "detail": "Backend sunucusu erişilemez"}
        if self.mode == "secure":
            detail = {
                "weak_auth": "Çok faktörlü kimlik doğrulama zayıf/varsayılan girişi reddetti",
                "dos": "Hız sınırlama (rate limiting) yüksek istek hacmini engelledi",
            }.get(scenario, "Koruma aktif")
            return {"accepted": False, "detail": detail}
        # vulnerable
        detail = {
            "weak_auth": "Varsayılan/zayıf kimlik bilgileriyle yönetim paneline erişildi",
            "dos": "Sunucu yüksek istek hacmi altında yanıt vermemeye başladı",
        }.get(scenario, "Koruma atlatıldı")
        return {"accepted": True, "detail": detail}

    def diagnostic_scope_probe(self, target: str, action: str = "write_critical_param") -> bool:
        # secure modda kapsam sınırlaması + ek yetkilendirme/denetim devrede:
        # oturum meşru olsa da kapsam dışı işlem reddedilir.
        # vulnerable modda açık oturum sınırsız yetki taşır (klasik senaryo).
        if self.mode == "empty":
            return False  # teşhis oturumu hiç açılamadı
        return self.mode == "vulnerable"

    def debug_port_probe(self, target: str, action: str = "jtag_connect") -> bool:
        # secure modda debug arayüzü üretimde kilitli/eritilmiş (fused) —
        # fiziksel erişim olsa bile bağlantı reddedilir.
        # vulnerable modda arayüz açık/kilitlenmemiş (yaygın geliştirme hatası).
        if self.mode == "empty":
            return False  # arayüz fiziksel olarak mevcut değil/erişilemez
        return self.mode == "vulnerable"

    def physical_ecu_access_probe(self, target: str, method: str = "enclosure_bypass") -> bool:
        # secure modda muhafaza kilitli/mühürlü ve kablo demeti korumalı —
        # fiziksel erişim engellenir. vulnerable modda kilit/mühür yok veya
        # kablo demeti açıkta, doğrudan erişim mümkün.
        if self.mode == "empty":
            return False  # hedef fiziksel olarak mevcut değil/test edilemedi
        return self.mode == "vulnerable"

    def firmware_integrity_probe(self, target: str, scenario: str) -> Dict:
        # secure modda secure boot zinciri + çalışma anı bütünlük doğrulaması
        # aktif. vulnerable modda ikisi de yok/atlatılabilir.
        if self.mode == "empty":
            return {"accepted": False, "detail": "ECU yanıt vermiyor"}
        if self.mode == "secure":
            detail = {
                "malicious_replace": "Secure boot imza doğrulaması kötü niyetli firmware'i reddetti",
                "integrity_check_bypass": "Çalışma anı bütünlük denetimi (runtime attestation) tutarsızlığı tespit etti",
            }.get(scenario, "Koruma aktif")
            return {"accepted": False, "detail": detail}
        # vulnerable
        detail = {
            "malicious_replace": "İmzasız/kötü niyetli firmware imajı kabul edildi",
            "integrity_check_bypass": "Çalışan yazılım hiçbir checksum/imza doğrulaması olmadan yürütüldü",
        }.get(scenario, "Koruma atlatıldı")
        return {"accepted": True, "detail": detail}

    def remote_telematics_exploit_probe(self, target: str) -> bool:
        # secure modda TCU sertleştirilmiş (yamalı işletim sistemi, kapalı
        # debug servisleri, güçlü kimlik doğrulama) — uzaktan exploit başarısız.
        # vulnerable modda TCU eski/yamasız yazılım çalıştırıyor, exploit başarılı.
        if self.mode == "empty":
            return False  # TCU uzaktan erişilemez/yanıt vermiyor
        return self.mode == "vulnerable"

    def can_dos_probe(self, target: str, technique: str = "high_priority_flood") -> Dict:
        if self.mode == "empty":
            return {"succeeded": False, "detail": "Bus erişilemez / yanıt yok"}
        if self.mode == "secure":
            detail = {
                "high_priority_flood": "Mesaj hız sınırlama düğümleri aç kalmaktan korudu",
                "error_frame_attack": "Hata sayacı izleme, bus-off girişimini engelledi",
            }.get(technique, "Koruma aktif")
            return {"succeeded": False, "detail": detail}
        detail = {
            "high_priority_flood": "Düşük öncelikli düğümler mesaj gönderemez hale geldi (aç kalma)",
            "error_frame_attack": "Hedef düğüm bus-off durumuna zorlandı, iletişim tamamen kesildi",
        }.get(technique, "DoS başarılı")
        return {"succeeded": True, "detail": detail}

    def ivi_pivot_probe(self, target: str) -> bool:
        # secure modda gateway ECU, IVI ile kritik CAN ağı arasında sıkı
        # filtreleme/ayrıştırma uygular — pivot engellenir.
        # vulnerable modda yeterli ağ ayrıştırması yok, pivot başarılı.
        if self.mode == "empty":
            return False  # IVI erişilemez / yanıt yok
        return self.mode == "vulnerable"

    def telematics_channel_probe(self, target: str) -> bool:
        # secure modda kanal güçlü şifreleme + karşılıklı kimlik doğrulama
        # kullanır. vulnerable modda zayıf/eski şifreleme veya sahte baz
        # istasyonu/AP kabul edilebilir.
        if self.mode == "empty":
            return False  # kanal erişilemez / yanıt yok
        return self.mode == "vulnerable"
