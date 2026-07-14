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

    def v2x_attack_probe(self, target: str, scenario: str) -> Dict:
        """V2X iletişim yığınına, imza eksikliğinden ayrı, ek saldırı senaryoları uygular.

        scenario:
          - 'identity_spoof'   : geçerli görünen ama başka bir meşru katılımcının
                                 (ör. komşu araç/RSU) kimliğini/sertifikasını taklit
                                 eden bir mesaj gönderir — imza VAR ama kimlik sahte
                                 (R155-2.1 genel mesaj sahteciliği/spoofing)
          - 'v2i_infra_trust'  : ele geçirilmiş/sahte bir yol kenarı birimi (RSU) gibi
                                 davranarak araca yetkisiz komut/veri (ör. sahte hız
                                 sınırı, sahte sinyal durumu) enjekte etmeyi dener
                                 (R155-5.12 V2I altyapısı üzerinden araç sistemlerine
                                 saldırı)

        Dönüş: {'accepted': bool, 'detail': str}
          accepted=True → saldırı başarılı (koruma yok) = zafiyet
          accepted=False → koruma mekanizması engelledi
        """
        raise NotImplementedError(f"{self.adapter_type}: v2x_attack_probe desteklenmez")

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
          - 'rollback'       : eski sürüm imzalı paket gönder (R155-3.6 downgrade)
          - 'bad_signature'  : bozuk imzalı paket gönder (R155-3.4 imza atlatma)
          - 'plaintext'      : kanalın şifreli olup olmadığını sorgula (R155-3.5)
          - 'pre_update_tamper' : paket derlenmeden/imzalanmadan önce (build/staging
                                  aşamasında) değiştirilmiş güncellemeyi dener
                                  (R155-3.1 güncelleme öncesi yazılım manipülasyonu)
          - 'manifest_tamper'   : imza geçerli kalırken yalnızca manifest/meta veriyi
                                  (versiyon, hedef ECU listesi, hash) değiştirip gönderir
                                  (R155-3.7 güncelleme meta verisi manipülasyonu)
          - 'channel_dos'       : güncelleme kanalını/sunucusunu yüksek istek
                                  hacmiyle yorarak meşru araçların güncelleme
                                  indirmesini engellemeyi dener (R155-3.2
                                  güncelleme kanalına DoS — ERİŞİLEBİLİRLİK;
                                  paketin kendisiyle değil, kanalın MEŞGUL
                                  edilmesiyle ilgilidir)
          - 'unauthorized_upload' : OTA dağıtım sunucusuna, uygun yetkilendirme
                                  olmadan doğrudan yeni bir paket YÜKLEMEYİ
                                  dener — 'bad_signature'dan FARKLI olarak bu,
                                  ARACIN paketi kabul edip etmediğini değil,
                                  SUNUCUNUN yetkisiz bir yayıncıdan paket kabul
                                  edip etmediğini sınar (R155-3.3 yetkisiz
                                  yazılım yükleme — SUNUCU TARAFI yetkilendirme)

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
          - 'supply_chain_compromise' : backend'in dağıtım/derleme hattına
                          (CI/CD) doğrulanmamış/imzasız bir üçüncü taraf
                          bağımlılık (paket/kütüphane/konteyner imajı)
                          enjekte etmeyi dener — 'weak_auth'dan FARKLI olarak
                          burada saldırgan sunucuya doğrudan erişmiyor,
                          sunucunun GÜVENDİĞİ tedarik zincirini hedefliyor
                          (R155-1.4 tedarik zinciri saldırısı — backend)
          - 'insider_privilege_abuse' : ZATEN GEÇERLİ kimlik bilgileriyle
                          giriş yapmış bir personelin, kendisine tanınan rol/
                          yetki kapsamının ÖTESİNDE bir işlem (ör. başka bir
                          filo operatörünün araçlarına erişim, denetim
                          kaydı olmadan toplu veri dışa aktarma) yapıp
                          yapamadığını sınar — 'weak_auth'dan FARKLI olarak
                          burada kimlik doğrulama SORUN DEĞİL, yetkilendirme/
                          en az yetki (least privilege) ilkesinin uygulanıp
                          uygulanmadığı sınanır (R155-1.2 personel tarafından
                          hak kötüye kullanımı)
          - 'unrestricted_internet_exposure' : yönetim panelinin/iç API'nin
                          VPN, IP izin listesi veya ağ segmentasyonu olmadan
                          doğrudan genel internetten erişilebilir olup
                          olmadığını sınar — 'weak_auth'dan FARKLI olarak bu,
                          kimlik bilgisinin GÜCÜNÜ değil, arayüzün BAŞTAN
                          İTİBAREN internetten erişilebilir olup olmaması
                          gereken bir çevre güvenliği (perimeter) sorununu
                          test eder (R155-1.3 sunucuya yetkisiz internet
                          erişimi)

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

    def physical_ecu_access_probe(self, target: str, method: str = "enclosure_bypass") -> bool:
        """Bir ECU/port'a (ör. OBD-II) izinsiz FİZİKSEL erişim dener.

        Hem OBD-II/UDS protokol istismarından (R155-5.5, obd2-enum — mantıksal/
        protokol katmanı, port elektroniği üzerinden yapılır) hem de donanım
        debug arayüzü erişiminden (R155-7.4, debug-port-access — JTAG/UART gibi
        AYRI bir arayüz) farklı olarak, bu metod portun/ECU'nun kendisinin
        FİZİKSEL MUHAFAZA korumasını (kilit, mühür, gizli/erişilmesi zor montaj)
        hedefler: kilit/mühür yoksa saldırgan port elektroniğini/protokolünü
        hiç uğraşmadan doğrudan konnektör pinlerine veya kablo demetine erişip
        (tap/splice) ECU ile doğrudan iletişim kurabilir.

        method: 'enclosure_bypass' (port/ECU muhafazasının kilidi/mührü
                atlatılıp fiziksel olarak açılır) |
                'harness_tap'       (kablo demetine doğrudan splice/tap
                yapılarak port elektroniği tamamen atlanır)

        Dönüş: True → fiziksel erişim engellenmedi (kilit/mühür/koruma yok
        veya atlatıldı) = zafiyet. False → fiziksel koruma erişimi engelledi.
        """
        raise NotImplementedError(
            f"{self.adapter_type}: physical_ecu_access_probe desteklenmez"
        )

    # ── Firmware / Yazılım Bütünlüğü (R155 Kat.6 — Veri ve Kod) ───────────────

    def firmware_integrity_probe(self, target: str, scenario: str) -> Dict:
        """ECU'nun çalışan firmware/yazılımının bütünlük doğrulamasını test eder.

        scenario:
          - 'malicious_replace'      : firmware'i kötü niyetli kodla değiştirmeyi
                                        dener (R155-6.1 firmware değiştirme)
          - 'integrity_check_bypass' : çalışma anında bütünlük doğrulamasını
                                        (checksum/imza) atlatmayı dener
                                        (R155-6.4 yazılım bütünlüğü ihlali)
          - 'secure_boot_bypass'     : önyükleme (boot) sırasındaki güven
                                        zincirinin kendisini (bootloader → çekirdek
                                        → uygulama imza doğrulama basamakları)
                                        atlatmayı dener — 'integrity_check_bypass'
                                        çalışma ANINDAKİ periyodik doğrulamayı test
                                        ederken, bu senaryo SADECE önyükleme
                                        ZAMANINDAKİ ilk güven kurulumunu hedefler
                                        (R155-6.13 güvenli önyükleme atlatma)

        Dönüş: {'accepted': bool, 'detail': str}
          accepted=True → saldırı başarılı (bütünlük koruması yok) = zafiyet
          accepted=False → koruma mekanizması (imza doğrulama/secure boot
          zinciri) engelledi
        """
        raise NotImplementedError(f"{self.adapter_type}: firmware_integrity_probe desteklenmez")

    # ── Uzaktan Telematik Exploit Erişimi (R155 Kat.5 — Dış Bağlanabilirlik) ──

    def remote_telematics_exploit_probe(self, target: str) -> bool:
        """Telematik/TCU birimine uzaktan erişilebilir servisleri hedefleyen
        bilinen bir zafiyet sınıfını istismar etmeyi dener.

        2015 Jeep Cherokee vakası bu vektörün arketipidir: TCU üzerinden
        uzaktan erişim sağlanıp iç araç ağına pivot yapılmıştır.

        Dönüş: True → uzaktan exploit başarılı (TCU'ya kod yürütme/erişim
        sağlandı) = zafiyet. False → yama/sertleştirme (hardening) engelledi.
        """
        raise NotImplementedError(
            f"{self.adapter_type}: remote_telematics_exploit_probe desteklenmez"
        )

    # ── CAN Bus Servis Engelleme (R155 Kat.2 — İletişim Kanalları) ────────────

    def can_dos_probe(self, target: str, technique: str = "high_priority_flood") -> Dict:
        """CAN veri yoluna servis engelleme (DoS) saldırısı dener.

        technique:
          - 'high_priority_flood' : en yüksek öncelikli (düşük arbitration ID)
                                     çerçeveleri sürekli basarak diğer tüm
                                     düğümleri aç bırakır
          - 'error_frame_attack'  : hedef düğümü zorla 'bus-off' durumuna
                                     düşürmeyi dener (hata çerçevesi enjeksiyonu)

        Dönüş: {'succeeded': bool, 'detail': str}
          succeeded=True → hedef düğüm/bus etkilendi (mesaj kaybı/bus-off) = zafiyet
          succeeded=False → önceliklendirme/hata sayacı koruması engelledi
        """
        raise NotImplementedError(f"{self.adapter_type}: can_dos_probe desteklenmez")

    # ── IVI / Infotainment Üzerinden Pivot (R155 Kat.5 — Dış Bağlanabilirlik) ──

    def ivi_pivot_probe(self, target: str) -> bool:
        """IVI/infotainment sistemi ele geçirildikten sonra araç içi kritik
        ağlara (CAN/gateway) pivot yapılıp yapılamadığını test eder.

        Klasik senaryo: yolcu WiFi/infotainment üzerinden IVI'ye erişim
        sağlanır, ardından IVI ile gateway/CAN arasında yeterli ağ
        ayrıştırması (segmentation) yoksa saldırgan kritik ağlara sızar.

        Dönüş: True → pivot başarılı (IVI ile kritik ağ arasında izolasyon
        yok) = zafiyet. False → ağ ayrıştırması/gateway filtrelemesi pivotu
        engelledi.
        """
        raise NotImplementedError(f"{self.adapter_type}: ivi_pivot_probe desteklenmez")

    # ── Telematik Kanalı İstismarı (R155 Kat.5 — Dış Bağlanabilirlik) ─────────

    def telematics_channel_probe(self, target: str) -> bool:
        """Hücresel/WiFi telematik kanalının kendisine yönelik bir istismar
        dener — zayıf şifreleme, sahte baz istasyonu/AP kabulü veya kanal
        üzerinde dinleme/enjeksiyon.

        Dönüş: True → kanal istismar edilebildi (zafiyet). False → kanal
        koruması engelledi.
        """
        raise NotImplementedError(f"{self.adapter_type}: telematics_channel_probe desteklenmez")

    # ── Yardımcılar ──────────────────────────────────────────────────────────

    # ── Harici Cihaz Bağlantı Arayüzleri (R155 Kat.4/5) ───────────────────────

    def external_device_probe(self, target: str, scenario: str) -> Dict:
        """IVI/kabin bağlantı merkezinin harici cihaz erişim kontrollerini
        üç farklı açıdan test eder.

        scenario:
          - 'bluetooth_pairing_bypass' : kimlik doğrulaması/kullanıcı onayı
                                          olmadan Bluetooth eşleştirmesi dener
                                          (R155-5.2 Bluetooth / kısa mesafeli
                                          kablosuz saldırı — PROTOKOL katmanı)
          - 'usb_autorun_exploit'      : USB üzerinden takılan kötü niyetli bir
                                          cihazın (mass storage/HID) kullanıcı
                                          onayı olmadan otomatik çalıştırılmasını
                                          dener (R155-5.3 USB / fiziksel port
                                          saldırısı — PROTOKOL katmanı)
          - 'rogue_device_enrollment'  : kanaldan (BT/USB/vb.) BAĞIMSIZ olarak,
                                          yeni bir cihazın filo POLİTİKASI
                                          gerektirdiği operatör onayı/denetim
                                          adımı olmadan kalıcı olarak kaydını
                                          dener (R155-4.4 iç tehdit: yetkisiz
                                          harici cihaz bağlantısı — KURUMSAL/
                                          POLİTİKA katmanı; 5.2/5.3'ten farklı
                                          olarak burada test edilen protokol
                                          güvenliği değil, filo YÖNETİM
                                          POLİTİKASININ uygulanıp uygulanmadığı)

        Dönüş: {'accepted': bool, 'detail': str}
          accepted=True → saldırı/kayıt onaysız kabul edildi = zafiyet
          accepted=False → ilgili kontrol (protokol veya politika) engelledi
        """
        raise NotImplementedError(f"{self.adapter_type}: external_device_probe desteklenmez")

    # ── Bağlantılı Uygulama Katmanı (R155 Kat.5 — Dış Bağlanabilirlik) ────────

    def app_layer_probe(self, target: str, scenario: str) -> Dict:
        """Araçla/backend'le konuşan uygulama katmanının GÜVEN SINIRLARINI
        iki farklı konumda test eder.

        scenario:
          - 'mobile_app_insecure_api'          : akıllı telefondaki refakatçi
                                                  (companion) uygulamanın araç/
                                                  backend API'siyle konuşurken
                                                  kimlik doğrulama/token
                                                  güvenliğinin (ör. sabit
                                                  kodlanmış anahtar, sertifika
                                                  pinleme eksikliği) yeterli
                                                  olup olmadığını sınar
                                                  (R155-5.9 bağlantılı mobil
                                                  uygulama güvenlik açığı —
                                                  araç DIŞINDAKİ uygulama)
          - 'third_party_app_privilege_escape' : IVI (infotainment) üzerinde
                                                  çalışan üçüncü taraf bir
                                                  uygulamanın, kendisine
                                                  tanınan izin/sandbox
                                                  sınırının ÖTESİNDE araç
                                                  verisine/fonksiyonuna
                                                  erişip erişemediğini sınar
                                                  (R155-5.10 üçüncü taraf IVI
                                                  uygulaması zafiyeti — araç
                                                  İÇİNDEKİ uygulama)

        İkisi de "uygulama katmanı güveni" temasını paylaşır ama FARKLI
        konumları hedefler: biri aracın dışındaki (telefon) uygulamanın
        API'ye erişimini, diğeri aracın içindeki (IVI) uygulamanın kendi
        sandbox sınırını aşıp aşamadığını test eder.

        Dönüş: {'accepted': bool, 'detail': str}
          accepted=True → güven sınırı aşıldı = zafiyet
          accepted=False → sınır/kontrol korundu
        """
        raise NotImplementedError(f"{self.adapter_type}: app_layer_probe desteklenmez")

    # ── Araç İçi Kişisel Veri (R155 Kat.6 — Veri ve Kod) ──────────────────────

    def personal_data_probe(self, target: str, scenario: str) -> Dict:
        """Araç içinde toplanan/saklanan kişisel verinin (yolcu geçmişi,
        eşleştirilmiş cihaz bilgisi, konum geçmişi vb.) TRANSIT ve AT-REST
        koruma durumunu iki farklı açıdan test eder.

        scenario:
          - 'telemetry_data_leak'             : backend'e gönderilen telemetri/
                                                  log akışının, anonimleştirme/
                                                  veri minimizasyonu olmadan
                                                  kişisel veri (PII) içerip
                                                  içermediğini sınar — TRANSIT
                                                  (aktarım sırasında sızıntı)
                                                  (R155-6.3 kişisel veri
                                                  sızdırma)
          - 'local_storage_unauthorized_access' : araç içinde yerel olarak
                                                  saklanan kişisel verinin
                                                  (yolculuk geçmişi, eşleştirilmiş
                                                  cihaz kayıtları vb.) şifreleme/
                                                  erişim kontrolü olmadan yerel
                                                  erişimi olan biri tarafından
                                                  okunup okunamadığını sınar —
                                                  AT-REST (durağan veri)
                                                  (R155-6.10 araç içinde
                                                  saklanan kişisel veriye
                                                  yetkisiz erişim)

        İkisi de "kişisel veri koruması" temasını paylaşır ama FARKLI bir
        veri durumunu (data state) hedefler: biri verinin AKTARILIRKEN,
        diğeri verinin DURURKEN korunup korunmadığını sınar.

        Dönüş: {'accepted': bool, 'detail': str}
          accepted=True → veri korumasız açığa çıktı = zafiyet
          accepted=False → ilgili koruma (minimizasyon veya şifreleme/erişim
          kontrolü) etkili
        """
        raise NotImplementedError(f"{self.adapter_type}: personal_data_probe desteklenmez")

    # ── İletişim Kanalı Dinleme/Araya Girme (R155 Kat.2 — İletişim Kanalları) ─

    def comm_interception_probe(self, target: str, scenario: str) -> Dict:
        """Gateway/iletişim kanalı üzerinden PASİF dinleme ile AKTİF araya
        girmeyi (MitM) iki ayrı yetenek olarak test eder.

        scenario:
          - 'can_sniffing'         : ağ üzerinde salt-okunur konumdaki bir
                                      saldırganın, hassas sinyalleri (payload
                                      seviyesinde ek şifreleme/MAC olmadan)
                                      pasif olarak dinleyip tam çözebildiğini
                                      sınar (R155-2.3 bilgi dinleme/sniffing —
                                      yalnızca GİZLİLİK, mesajı DEĞİŞTİRMEZ)
          - 'gateway_mitm'         : saldırganın iki segment arasına (ör. IVI
                                      ile backend, ya da gateway'in yönlendirdiği
                                      iki ağ) aktif olarak yerleşip trafiği hem
                                      okuyup hem DEĞİŞTİREBİLDİĞİNİ sınar —
                                      karşılıklı kimlik doğrulama/TLS eksikliği
                                      (R155-2.6 ortadaki adam/MitM — GİZLİLİK +
                                      BÜTÜNLÜK, mesaj aktif olarak değiştirilir)

        can_sniffing pasif bir yetenek (yalnızca dinleme) test ederken,
        gateway_mitm saldırganın iletişim yoluna aktif olarak yerleşip trafiği
        değiştirebildiğini test eder — biri gizliliği, diğeri hem gizliliği
        hem bütünlüğü tehdit eder.

        Dönüş: {'accepted': bool, 'detail': str}
          accepted=True → yetenek başarılı (koruma yok) = zafiyet
          accepted=False → ilgili koruma (payload şifreleme/MAC veya karşılıklı
          kimlik doğrulama) engelledi
        """
        raise NotImplementedError(f"{self.adapter_type}: comm_interception_probe desteklenmez")

    # ── Firmware Çıkarma / Tersine Mühendislik (R155 Kat.6 — Veri ve Kod) ─────

    def firmware_extraction_probe(self, target: str, scenario: str) -> Dict:
        """ECU firmware imajından SIR (kriptografik anahtar) ve MANTIK
        (çalışan kod) çıkarılabilirliğini iki farklı açıdan test eder.

        scenario:
          - 'key_extraction'               : firmware/flash bellekte saklanan
                                              kriptografik anahtarların HSM/
                                              secure element olmadan bellek
                                              dökümüyle çıkarılabilmesini sınar
                                              (R155-6.2 kriptografik anahtar
                                              çalma)
          - 'firmware_reverse_engineering'  : firmware imajının kendisinin
                                              şifreleme/gizleme olmadan
                                              dökülüp disassemble/decompile
                                              edilerek tescilli mantığın
                                              ortaya çıkarılabilmesini sınar
                                              (R155-6.5 ECU firmware tersine
                                              mühendislik)

        Firmware Integrity (R155-6.1/6.4/6.13) firmware'in ÇALIŞMA ANINDA
        DEĞİŞTİRİLİP DEĞİŞTİRİLEMEDİĞİNİ (bütünlük) test ederken, bu metod
        firmware'İN İÇİNDEKİ SIRLARIN ve MANTIĞIN çıkarılabilir olup
        olmadığını (gizlilik) test eder.

        Dönüş: {'accepted': bool, 'detail': str}
          accepted=True → çıkarma başarılı (koruma yok) = zafiyet
          accepted=False → ilgili koruma (HSM/secure element veya firmware
          şifreleme) etkili
        """
        raise NotImplementedError(f"{self.adapter_type}: firmware_extraction_probe desteklenmez")

    # ── İnsan/Kurumsal Faktörler (R155 Kat.4 — İstenmeyen İnsan Davranışları) ─

    def human_factor_probe(self, target: str, scenario: str) -> Dict:
        """Filo operasyonlarının insan/kurumsal faktör kontrollerini üç
        farklı açıdan test eder. Bu üçü TEKNİK değil PROSEDÜREL/KURUMSAL
        kontrollerdir; teknik bir güvenlik açığı değil, bir SÜRECİN var olup
        olmadığını ve etkili çalışıp çalışmadığını sınar.

        scenario:
          - 'phishing_susceptibility'          : personelin/operatörlerin
                                                  kimlik avı (phishing)
                                                  denemelerine karşı MFA/
                                                  step-up doğrulama gibi
                                                  telafi edici bir kontrolü
                                                  olup olmadığını sınar —
                                                  tek bir tıklama/kimlik bilgisi
                                                  girişiyle hesabın tamamen
                                                  ele geçirilip geçirilemediği
                                                  (R155-4.1 sosyal mühendislik
                                                  / phishing)
          - 'insecure_default_config'          : yeni devreye alınan bir
                                                  bileşenin (ör. yeni araç,
                                                  yeni backend node) üretici
                                                  varsayılan ayarlarıyla
                                                  (varsayılan parola, açık
                                                  debug modu, gereksiz
                                                  servisler) mi yoksa
                                                  sertleştirilmiş bir taban
                                                  çizgisiyle mi devreye
                                                  girdiğini sınar (R155-4.3
                                                  güvensiz varsayılan
                                                  yapılandırma)
          - 'operator_misconfiguration_unchecked' : bir operatörün güvenlik
                                                  açısından anlamlı bir
                                                  yapılandırma değişikliğinin
                                                  (ör. güvenlik duvarı kuralı
                                                  gevşetme, loglamayı kapatma)
                                                  akran incelemesi/değişiklik
                                                  yönetimi kapısından
                                                  GEÇMEDEN doğrudan
                                                  uygulanıp uygulanamadığını
                                                  sınar (R155-4.5 operatör
                                                  tarafından hatalı güvenlik
                                                  yapılandırması)

        Dönüş: {'accepted': bool, 'detail': str}
          accepted=True → ilgili süreç/telafi edici kontrol YOK veya
          atlatıldı = zafiyet
          accepted=False → süreç/kontrol etkili şekilde çalışıyor
        """
        raise NotImplementedError(f"{self.adapter_type}: human_factor_probe desteklenmez")

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
