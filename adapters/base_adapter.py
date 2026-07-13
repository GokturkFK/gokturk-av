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

    def inject_adversarial_perturbation(
        self, target: str, sensor: str = "camera", technique: str = "patch"
    ) -> dict:
        """Algı ML modeline karşı adversarial saldırı dener.

        LiDAR/kamera spoofing'den (ham veri enjeksiyonu) farklı olarak burada
        sensör verisi DOĞRU gelir; üzerine ince, çoğu zaman insan gözüyle fark
        edilmeyen bir perturbation (adversarial patch / gürültü) eklenerek
        modelin YANLIŞ sınıflandırma yapması hedeflenir.

        sensor: 'camera' | 'lidar'
        technique: 'patch' (fiziksel yama) | 'noise' (Lp-sınırlı gürültü)

        Dönüş:
          {
            'fooled': bool,          # model yanıltıldı mı
            'defended': bool,        # adversarial-savunma (ör. tespit/temizleme) devrede mi
            'original': str,         # modelin perturbation'sız tahmini
            'adversarial': str,      # perturbation sonrası (yanlış) tahmin
          }
        """
        raise NotImplementedError(
            f"{self.adapter_type}: inject_adversarial_perturbation desteklenmez"
        )

    # ── V2X (Araç-Araç / Araç-Altyapı) ────────────────────────────────────────

    def inject_v2x_message(self, msg_type: str = "BSM", signed: bool = False) -> bool:
        """Sahte/imzasız bir V2X mesajı enjekte etmeyi dener.

        Dönüş True ise: mesaj alıcı yığın tarafından reddedilmeden kabul edildi
        (yani PKI/SCMS imza doğrulaması eksik/atlatılabilir) — zafiyet.
        False ise: mesaj reddedildi (imza doğrulama çalışıyor).
        """
        raise NotImplementedError(f"{self.adapter_type}: inject_v2x_message desteklenmez")

    # ── ECU / Firmware Fuzzing ────────────────────────────────────────────────

    def fuzz_ecu(self, target_ecu: str, mode: str = "smart", count: int = 200) -> list:
        """Bir ECU'ya yapılandırılmış fuzzing girdileri gönderir.

        Her sonuç öğesi şu anahtarları taşır:
          - accepted: girdi ECU tarafından işlendi mi (reddedilmedi mi)
          - memory_fault: bellek bozulması/çökme belirtisi (R155-6.8) görüldü mü
          - hang: ECU yanıt vermeyi bıraktı mı (mantık hatası/DoS belirtisi)

        mode: 'dumb' (tam rastgele), 'smart' (geçerli çerçeve + bozuk payload),
              'replay-mutate' (kaydedilmiş trafik + mutasyon).
        """
        raise NotImplementedError(f"{self.adapter_type}: fuzz_ecu desteklenmez")

    # ── OTA / Güncelleme Kanalı (UN R156 / R155 Kat.3) ────────────────────────

    def ota_update_probe(self, target: str, scenario: str) -> Dict:
        """OTA güncelleme kanalına bir saldırı senaryosu uygular.

        scenario:
          - 'rollback'      : eski sürüm imzalı paket gönder (R155-3.6 downgrade)
          - 'bad_signature' : bozuk imzalı paket gönder (R155-3.4 imza atlatma)
          - 'plaintext'     : kanalın şifreli olup olmadığını sorgula (R155-3.5)

        Dönüş: {'accepted': bool, 'detail': str}
          accepted=True → saldırı başarılı (koruma yok) = zafiyet
          accepted=False → koruma mekanizması engelledi
        """
        raise NotImplementedError(f"{self.adapter_type}: ota_update_probe desteklenmez")

    # ── Arka Uç / Filo Yönetim Sunucusu (R155 Kat.1) ──────────────────────────

    def backend_server_probe(self, target: str, scenario: str) -> Dict:
        """Araç servisleri arka uç (backend/filo yönetim) sunucusuna bir
        erişim/dayanıklılık saldırı senaryosu uygular.

        scenario:
          - 'weak_auth' : zayıf/varsayılan kimlik bilgileriyle erişim dener
                          (R155-1.1 yetkisiz uzaktan sunucu erişimi)
          - 'dos'       : sunucuyu yüksek istek hacmiyle yorar
                          (R155-1.5 backend DoS)

        Dönüş: {'accepted': bool, 'detail': str}
          accepted=True → saldırı başarılı (koruma yok) = zafiyet
          accepted=False → koruma mekanizması engelledi
        """
        raise NotImplementedError(f"{self.adapter_type}: backend_server_probe desteklenmez")

    # ── Teşhis Erişimi Suistimali (R155 Kat.4 — İnsan Davranışları) ───────────

    def diagnostic_scope_probe(self, target: str, action: str = "write_critical_param") -> bool:
        """Zaten AÇIK/MEŞRU bir teşhis oturumu (ör. yetkili tamirci) kapsamı
        aşan bir işlem denediğinde, kapsam sınırlaması / ek yetkilendirme /
        denetim (audit) kontrolünün devrede olup olmadığını sınar.

        Bu, obd2-enum'un (R155-5.5) test ettiği "kimlik doğrulamasız dış
        erişim"den FARKLIDIR: burada oturum zaten meşru şekilde açık; sınanan
        şey içeriden/yetkili kullanıcının kapsam suistimalidir (R155-4.2).

        action: 'write_critical_param' (güvenlik-kritik parametre yazma) |
                'bulk_extract' (oturum kapsamının çok üzerinde veri çekme)

        Dönüş: True → işlem ek yetkilendirme/denetim olmadan kabul edildi
        (kapsam sınırlaması yok = zafiyet). False → engellendi/denetlendi.
        """
        raise NotImplementedError(f"{self.adapter_type}: diagnostic_scope_probe desteklenmez")

    # ── Fiziksel Debug Portu Erişimi (R155 Kat.7 — Fiziksel Zafiyetler) ───────

    def debug_port_probe(self, target: str, action: str = "jtag_connect") -> bool:
        """Bir donanım debug arayüzüne (JTAG/UART) fiziksel erişim dener.

        OBD-II teşhis portundan (R155-5.5) farklı olarak bu, PCB üzerindeki
        ayrı bir düşük seviye debug arayüzünü hedefler — bellek dökümü,
        bootloader kesintisi veya doğrudan bellek/flash erişimi sağlayabilir.

        action: 'jtag_connect' (JTAG üzerinden bağlantı) |
                'uart_console' (UART seri konsola erişim)

        Dönüş: True → debug arayüzü kilitlenmemiş/etkin, erişim sağlandı
        (üretimde devre dışı bırakılmamış = zafiyet). False → arayüz
        kilitli/eritilmiş (fused) veya erişilemez.
        """
        raise NotImplementedError(f"{self.adapter_type}: debug_port_probe desteklenmez")

    # ── Firmware / Yazılım Bütünlüğü (R155 Kat.6 — Veri ve Kod) ───────────────

    def firmware_integrity_probe(self, target: str, scenario: str) -> Dict:
        """ECU'nun çalışan firmware/yazılımının bütünlük doğrulamasını test eder.

        scenario:
          - 'malicious_replace'      : firmware'i kötü niyetli kodla değiştirmeyi
                                        dener (R155-6.1 firmware değiştirme)
          - 'integrity_check_bypass' : çalışma anında bütünlük doğrulamasını
                                        (checksum/imza) atlatmayı dener
                                        (R155-6.4 yazılım bütünlüğü ihlali)

        Dönüş: {'accepted': bool, 'detail': str}
          accepted=True → saldırı başarılı (bütünlük koruması yok) = zafiyet
          accepted=False → koruma mekanizması (imza doğrulama/secure boot
          zinciri) engelledi
        """
        raise NotImplementedError(f"{self.adapter_type}: firmware_integrity_probe desteklenmez")

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
