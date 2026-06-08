# Otonom Otobüs Siber Güvenlik Testi — Kapsamlı Saha Araştırması

> Bu belge, projeye başlamadan önce alana hâkim olman için hazırlanmış bir referanstır. Sırayla okunabilir ama asıl amacı, ilerledikçe geri dönüp danışacağın bir başucu kaynağı olması. Her bölümün sonunda, o konuyu senin aracına nasıl bağlayacağına dair kısa notlar var.

---

## 0. Yön: bu işin gerçekte ne olduğu

"Otonom otobüsün siber testi" tek bir disiplin değil; en az altı ayrı uzmanlık alanının kesişimi:

1. **Klasik otomotiv ağ güvenliği** (CAN, Ethernet, gateway, teşhis)
2. **Gömülü/donanım güvenliği** (ECU firmware, secure boot, HSM, yan kanal)
3. **Otonom sürüş yığını güvenliği** (ROS2/DDS, sensörler, algı ML, planlama)
4. **Bağlantı ve uzaktan saldırı yüzeyi** (telematik, OTA, bulut, V2X)
5. **Test mühendisliği disiplini** (TARA, fuzzing, HIL/SIL, doğrulama)
6. **Uyumluluk ve kanıt yönetimi** (UN R155, ISO 21434, tip onayı)

Senin avantajın şu: 1, 5 ve 6'nın yazılım/arayüz tarafı zaten yapabildiğin şey. Eksiğin 2, 3 ve otomotiv-özgü domain bilgisi. Bu belge ağırlığı oraya veriyor.

---

## 1. Neden bu alan, neden otobüs?

Otonom otobüs/shuttle, siber güvenlik açısından binek araçtan **daha kritik** bir hedef:

- **Yüksek yolcu yoğunluğu:** Tek bir aracın ele geçirilmesi onlarca insanı aynı anda riske atar. Etki kategorisinde "safety" (güvenlik/can) her zaman en üst seviyededir.
- **Sabit güzergâh ve öngörülebilirlik:** Saldırgan rotayı, durakları, zamanlamayı önceden bilebilir; fiziksel keşif kolaydır.
- **Filo homojenliği:** Aynı model otobüsten yüzlerce var. Bir modelde bulunan bir zafiyet tüm filoyu etkiler — "bir kez yaz, her yerde sömür" senaryosu.
- **Sürücüsüz operasyon:** İnsan müdahalesi yok; algı/karar sistemine yapılan saldırının fiziksel sonucu doğrudan ve geri dönülmezdir.
- **Kamu altyapısına bağımlılık:** V2X, trafik ışıkları, depo/şarj altyapısı, filo yönetim bulutu — saldırı yüzeyi araçla sınırlı değil.

**Tehdit aktörleri:** fırsatçı bireysel saldırganlar, fidye yazılımı grupları (filo operatörünü hedef alır), rakip/sabotaj, devlet destekli aktörler (kritik altyapı), ve içeriden tehdit (depo/bakım personeli).

> **Aracına not:** Otobüse özgü bu özellikler, aracının "varlık kataloğu" ve "etki değerlendirmesi" modüllerinin binek araçtan farklı önceliklendirme yapması gerektiği anlamına gelir. Safety etkisini her zaman birinci sıraya koy.

---

## 2. Regülasyon ve standart omurgası — aracının "ölmeme" çapası

Bu bölüm en önemlisi. Otobüs modelleri 3-5 yılda değişir; **standartlar yavaş değişir.** Aracını araç modeline değil, bu çerçeveye çapalarsan uzun ömürlü olur.

### 2.1 UN R155 (UNECE WP.29) — CSMS

- Birleşmiş Milletler Avrupa Ekonomik Komisyonu'nun (UNECE) düzenlemesi. AB'de 2022'den beri **yeni araç tipleri için zorunlu**; Japonya, Kore ve birçok ülke tip onayı sistemine dahil etti.
- Üreticiden bir **Cyber Security Management System (CSMS)** ister: aracın geliştirme, üretim, operasyon ve bakım ömrü boyunca siber riskin yönetilmesi.
- **Annex 5** kritik: **7 üst düzey tehdit kategorisi** ve toplam **69 saldırı vektörü** listeler. Yedi kategori:
  1. Arka uç sunuculara yönelik tehditler (back-end servers)
  2. İletişim kanallarına yönelik tehditler (communication channels)
  3. Güncelleme prosedürlerine yönelik tehditler (update procedures)
  4. İstenmeyen insan davranışlarına yönelik tehditler (human actions)
  5. Dış bağlanabilirliğe yönelik tehditler (external connectivity)
  6. Veri ve koda yönelik tehditler (data and code)
  7. Aracın fiziksel zafiyetlerine yönelik tehditler (physical vulnerability)

> **Aracına not:** Bu 69 vektör, aracının yerleşik **tehdit taksonomisi** olmalı. Her test modülün en az bir Annex 5 vektörüne eşlenmeli. Bu, hem "ölmeme" çapası hem de raporlarını doğrudan tip onayı kanıtına dönüştüren şey.

### 2.2 UN R156 — SUMS (Software Update Management System)

- R155'in kardeşi; **yazılım güncelleme (OTA) süreçlerinin** güvenli yönetimini zorunlu kılar. Otonom araçta yazılım sürekli güncellendiği için bu kanal başlı başına bir saldırı yüzeyi ve bir uyumluluk gereği.

### 2.3 ISO/SAE 21434 — Road vehicles: Cybersecurity engineering

- UN R155'in **mühendislik karşılığı**. R155 "ne yapmalısın"ı söyler; 21434 "nasıl yapılır"ı tanımlar. Tedarikçiler 21434 uyumluysa R155'e de uyum sağlayabilir.
- Kalbinde **TARA (Threat Analysis and Risk Assessment)** var — Clause 15. Beş adımlı sistematik süreç:
  1. **Varlık tanımlama** (asset identification) — neyi koruyoruz?
  2. **Tehdit tanımlama** (threat scenario identification)
  3. **Etki değerlendirme** (impact rating) — 4 boyut: **safety, financial, operational, privacy**
  4. **Saldırı fizibilitesi** (attack feasibility) — Annex H faktörleri: geçen süre, uzmanlık, bilgi, fırsat penceresi, ekipman
  5. **Risk belirleme ve işleme** (risk determination & treatment)
- TARA yedi adet **work product** (iş ürünü) üretir: varlık kataloğu, tehdit listesi, etki/fizibilite değerlendirmeleri, risk matrisi, risk işleme kararları, siber güvenlik hedefleri. Bunlar OEM'lerin **tip onayı için sunduğu birincil kanıt**.

> **Aracına not:** Pek çok ekip TARA'yı hâlâ Excel'de yapıyor ve bu bir kâbus. Aracın test sonuçlarını otomatik olarak TARA iş ürünlerine bağlayabilirse, gerçek bir acıyı çözersin. Bu tek başına ticari bir ürün fikri.

### 2.4 Komşu standartlar (bilmen yeterli, uzman olman şart değil)

- **ISO 26262** — fonksiyonel güvenlik (functional safety). Siber güvenlikle iç içe: bir siber saldırının güvenlik (safety) sonucu varsa iki disiplin kesişir.
- **ISO 21448 (SOTIF)** — "Safety Of The Intended Functionality"; özellikle otonom algı sistemlerinin (sensör/ML) beklenmedik durumlarda güvenliği. Sensör spoofing burada da gündeme gelir.
- **ISO/PAS 5112** — CSMS denetim (audit) rehberi.
- **SAE J3061** — 21434 öncesi eski rehber (tarihsel bağlam).
- **ISO 15118** — EV şarj iletişimi (Plug & Charge); şarj güvenliği için.

---

## 3. Saldırı yüzeyi haritası

Otonom otobüsün tam saldırı yüzeyi. Aracının "3D saldırı yüzeyi haritası" tam olarak bunu görselleştirmeli.

### 3.1 Araç içi ağlar (in-vehicle networks)

- **CAN / CAN-FD:** Hâlâ omurga. Tasarımda kimlik doğrulama yok; her düğüm her mesajı görür ve gönderebilir. Klasik saldırı zemini.
- **LIN:** Düşük hızlı, basit alt sistemler (cam, ayna).
- **FlexRay:** Yüksek hız, zaman-tetiklemeli (eski lüks/şasi sistemleri).
- **Automotive Ethernet (100/1000BASE-T1):** Yüksek bant genişliği; kamera/LiDAR gibi sensör verisi ve ADAS için. Modern mimarinin omurgası.
- **SOME/IP:** Ethernet üstünde servis odaklı orta katman (service-oriented middleware).
- **DoIP (Diagnostics over IP):** Teşhisin Ethernet üstünden yapılması.
- **Mimari evrim:** Dağıtık ECU → **merkezi/zonal mimari** + yüksek performanslı bilgisayar (HPC). Otonom araçlar zonal mimariye gidiyor; gateway/HPC kritik bir hedef.

### 3.2 ECU'lar ve teşhis

- **ECU firmware:** Çıkarma (extraction), tersine mühendislik, değiştirme.
- **UDS (Unified Diagnostic Services, ISO 14229):** Teşhis protokolü; servis 0x27 (security access), 0x2E (write data), 0x31 (routine), 0x34/0x36 (firmware download). Yanlış yapılandırılmış UDS = devasa saldırı yüzeyi.
- **OBD-II portu:** Fiziksel teşhis erişim noktası; klasik giriş kapısı.
- **Secure boot / HSM (Hardware Security Module):** Savunma tarafı; testte bunların atlatılıp atlatılamadığına bakılır.

### 3.3 Bağlantı ve uzaktan yüzey

- **TCU (Telematics Control Unit):** Hücresel modem; aracın internete açılan kapısı. Uzaktan saldırının ana hedefi.
- **Hücresel (4G/5G), WiFi, Bluetooth, NFC, USB:** Her biri ayrı bir giriş vektörü.
- **OTA güncelleme kanalı:** İmza doğrulama, rollback koruması, güncelleme sunucusu güveni.
- **IVI (In-Vehicle Infotainment):** Genelde en zayıf halka; oradan iç ağa pivot klasik senaryodur (Jeep Cherokee 2015 vakası bunun arketipi).

### 3.4 Otonom sürüş yığını

Bu, aracını binek araç araçlarından ayıracak farklılaştırıcın.

- **Orta katman: ROS2 + DDS.** Otonom yazılımın çoğu ROS2 üzerinde çalışır; ROS2 ise iletişim için **DDS (Data Distribution Service)** kullanır.
  - Varsayılan olarak DDS, herhangi bir katılımcının kimlik doğrulaması olmadan domaine katılmasına izin verir. Ağa erişen biri topic'leri dinleyebilir ve sahte mesaj enjekte edebilir.
  - **SROS2 / DDS-Security:** Kimlik doğrulama, şifreleme (AES-GCM) ve erişim kontrolü ekler. Ama açık edilmesi ve doğru yapılandırılması gerekir; araştırmalar SROS2'nin kendisinde tasarım kusurları ve DDS'te çok sayıda zafiyet buldu.
- **Sensörler (algı katmanı):**
  - **LiDAR:** 3B nokta bulutu; engel algılama ve konumlandırmanın bel kemiği.
  - **Kamera:** Nesne tanıma, şerit, trafik işareti.
  - **Radar (mmWave):** Mesafe/hız.
  - **GNSS/GPS:** Mutlak konum.
  - **IMU:** Atalet/yönelim.
  - **Ultrasonik:** Yakın mesafe.
- **Algı ML modelleri:** Nesne algılama (3B detektörler), segmentasyon. Adversarial saldırılara açık.
- **Konumlandırma (localization) ve SLAM:** LiDAR + GPS + IMU füzyonu. Spoofing burada kritik etki yaratır.
- **Planlama ve kontrol:** Rota planlama, davranış, araç kontrolü (drive-by-wire).

### 3.5 V2X (Vehicle-to-Everything)

- **DSRC ve C-V2X:** Araç-araç (V2V), araç-altyapı (V2I) iletişimi.
- **PKI / SCMS (Security Credential Management System):** V2X mesajlarının imzalanması/doğrulanması. Sahte mesaj enjeksiyonu (hayalet araç, sahte trafik durumu) ana tehdit.

### 3.6 EV şarj

- **ISO 15118 / Plug & Charge:** Şarj sırasında kimlik doğrulama ve ödeme. Şarj istasyonu ↔ araç ↔ backend zinciri yeni ve hızlı büyüyen bir saldırı yüzeyi.

### 3.7 Backend / bulut / filo yönetimi

- Filo yönetim platformu, OTA sunucusu, telemetri toplama, uzaktan komut. Tek bir backend zaafı = tüm filo. R155 Annex 5'in 1. kategorisi tam olarak bu.

---

## 4. Saldırı sınıfları ve teknikleri

### 4.1 CAN bus saldırıları

- **Sniffing / dinleme:** Trafiği yakala, arbitration ID'lerini ve payload'ları çöz.
- **Replay (tekrar):** Yakalanan meşru mesajı yeniden gönder (örn. kapı aç).
- **Injection (enjeksiyon):** Sahte mesaj üret; gösterge, fren, gaz sinyallerini taklit et.
- **Fuzzing:** Rastgele/yapılandırılmış mesaj akıtarak beklenmedik davranış/çökme tetikle.
- **Bus-off / DoS:** Hata bayrakları veya yüksek öncelikli mesaj seliyle bir ECU'yu hattan düşür.

### 4.2 ECU / donanım saldırıları

- **Firmware çıkarma:** JTAG/SWD, flash dökümü, bootloader açıkları.
- **Tersine mühendislik:** Ghidra/IDA ile firmware analizi.
- **Yan kanal (side-channel):** Güç tüketimi/zamanlama analiziyle anahtar çıkarma — **ChipWhisperer** bunun standart aracı.
- **Hata enjeksiyonu (fault/glitch injection):** Voltaj/saat manipülasyonuyla secure boot atlatma.

### 4.3 Sensör spoofing (otonom-özgü)

- **LiDAR spoofing:**
  - *Fiziksel:* Senkronize lazer darbeleriyle sahte nokta enjekte etme veya ayna/optik manipülasyonla algı bozma.
  - *Yazılım seviyesi (ROS2):* Topic'e doğrudan sahte/rastgele nokta bulutu enjekte ederek tüm işleme hattını bozma — ya engeli görünmez yapma (removal) ya da sahte engel yaratma (injection).
- **GPS/GNSS spoofing:** Yaklaşık 200-250 dolarlık bir SDR (örn. HackRF) + açık kaynak sinyal üreticiyle sahte GPS sinyali yayınlanabilir; araç yanlış konumda olduğunu sanır. Düşük maliyet, yüksek etki.
- **Kamera adversarial saldırıları:** Yola/işarete yapıştırılan özel desenlerle (adversarial patch) nesne tanımayı yanıltma; "dur" işaretini "hız limiti" olarak okutma gibi.
- **Radar spoofing/jamming:** Sahte yankı veya gürültü.
- **Savunma tarafı:** Sensör füzyonu + tutarlılık kontrolü (örn. LiDAR-GPS çapraz doğrulama, ki-kare residual dedektörleri) spoofing'i sınırlamak için kullanılır. Test ederken bu savunmaların gerçekten çalışıp çalışmadığını ölçersin.

### 4.4 ROS2 / DDS saldırıları

- **Kimliksiz topic katılımı/enjeksiyonu:** SROS2 kapalıysa ağdaki biri topic'lere yazıp okuyabilir.
- **SROS2 tasarım kusurları:** Akademik çalışma ("On the (In)Security of Secure ROS2") SROS2'nin yerel güvenlik modülünde dört zafiyet buldu; saldırganın SROS2 korumasını tamamen geçersiz kılıp yetkisiz izin/bilgi elde edebildiğini gösterdi (bulgular ROS2 ekibince kabul edildi ve giderildi).
- **DDS zafiyetleri:** Bağımsız araştırmacılar DDS'te ~15 ciddi zafiyet raporladı.
- **Tedarik zinciri:** SROS2'nin kimlik üretim sürecini hedefleyen, keystore'u dağıtımdan önce sızdıran PoC saldırılar (2025) — yani sadece ağ değil, build/dağıtım zinciri de yüzey.
- **Güven varsayımı sorunu:** DDS-Security, altta yatan OS ve OpenSSL'in güvenli olduğunu varsayar ama sürekli bütünlük kontrolü yapmaz.

### 4.5 Uzaktan / telematik saldırıları

- **Arketip vaka:** 2015 Jeep Cherokee — araştırmacılar uzaktan, hücresel üzerinden IVI'ye girip iç ağa pivot yaparak fren ve direksiyona eriştiler. 1.4 milyon araç geri çağrıldı. Bu vaka tüm modern otomotiv siber regülasyonunu tetikleyen olaydır.
- **Modern karşılığı:** TCU/IVI açıkları → iç ağa pivot → güvenlik-kritik fonksiyonlar.

---

## 5. Test metodolojisi — disiplinin kendisi

### 5.1 Test türleri (ISO 21434'ün beklediği V&V)

| Tür | Amaç |
|---|---|
| **Fonksiyonel güvenlik testi** | Güvenlik mekanizmaları spesifikasyona göre doğru çalışıyor mu? (örn. secure boot, mesaj kimlik doğrulama) |
| **Zafiyet tarama** | Bilinen zafiyetlerin (CVE), zayıf yapılandırmaların taranması |
| **Penetrasyon testi** | Saldırgan gibi düşünüp gerçek istismar denemesi |
| **Fuzz testi** | Hatalı/rastgele girdiyle beklenmedik davranış/çökme bulma |

### 5.2 Test ortamları (X-in-the-loop)

- **MIL (Model):** Saf model seviyesi.
- **SIL (Software):** Yazılım sanal ortamda; yüksek ölçeklenebilirlik, donanım gerektirmez. Senin başlangıç noktan.
- **HIL (Hardware):** Gerçek ECU + gerçek zamanlı simülasyon tezgâhı. Pahalı, donanım-yoğun.
- **VIL (Vehicle):** Tüm araçta saha testi.
- **Digital twin:** Aracın sayısal ikizi üzerinde sürekli test.

### 5.3 Simülasyon-öncelikli yaklaşım

- **CARLA:** Açık kaynak otonom sürüş simülatörü; sensör/fizik/trafik modeli. LiDAR ve GPS spoofing senaryoları fiziksel donanım olmadan burada güvenle ve tekrarlanabilir şekilde çalıştırılabilir.
- **Autoware:** Açık kaynak, üretim-sınıfı otonom sürüş yazılım yığını (ROS2 tabanlı). Gerçekçi bir hedef.
- **Gazebo:** Robotik simülasyon.
- Bu üçlü (CARLA + Autoware + ROS2) sana bedava, donanımsız ama gerçek bir test laboratuvarı verir.

### 5.4 V-modelinde testin yeri

ISO 21434, geliştirmeyi bir V-model olarak kurgular: solda gereksinim/tasarım (TARA burada), sağda doğrulama/geçerleme (testler burada). Aracın ideal olarak hem TARA hem test tarafına dokunur; ama önce test+raporlama ile başlamak en gerçekçisi.

---

## 6. Araç kutusu (tools & tech)

### 6.1 Açık kaynak

- **can-utils:** Linux CAN komut satırı araçları (candump, cansend, cangen). Sanal CAN (vcan) ile donanımsız pratik.
- **python-can / cantools:** Python'da CAN ve DBC çözümleme.
- **ICSim:** Instrument Cluster Simulator; donanımsız "araba" simülasyonu (Craig Smith). CAN istismarını öğrenmenin en ucuz yolu.
- **UDSim:** UDS teşhis simülatörü.
- **SavvyCAN:** Qt tabanlı GUI; CAN tersine mühendislik, DBC editör, fuzzing, UDS tarama.
- **CaringCaribou:** "CAN bus'ın nmap'i" — ECU keşfi, fuzzing, saldırı modülleri (Python).
- **CANToolz (YACHT):** Modüler black-box CAN analiz çerçevesi.
- **Scapy (automotive katmanı):** Paket üretimi/manipülasyonu; CAN, UDS, DoIP desteği.
- **Wireshark:** Ethernet/SOME-IP/DoIP analizi.
- **Ghidra / radare2:** Firmware tersine mühendislik.
- **ChipWhisperer:** Yan kanal/glitch (donanım).
- **SROS2 araçları:** ROS2 güvenlik politikası modelleme/denetim.
- **Simülasyon:** CARLA, Autoware, Gazebo.
- **SDR (GPS spoofing araştırması):** HackRF + açık kaynak sinyal üreticiler.

### 6.2 Ticari (rakip manzarası)

- **Keysight (SA8710A):** ISO 21434 / WP.29 uyumlu, donanımdan OSI yığınına otomatize uçtan uca test platformu.
- **dSPACE:** HIL/SIL tabanlı fuzzing ve penetrasyon test araç zinciri.
- **Vector, ETAS:** Otomotiv ağ/test araçları.
- **AUTOCRYPT:** ISO 21434 / R155-156 için entegre test platformu, V2X PKI, Red Team.
- **Block Harbor (VSEC):** Bulut tabanlı araç güvenlik test platformu.
- **VicOne, Argus, Upstream, Karamba:** İzleme/IDS, tehdit istihbaratı, CAN koruma.
- **TÜV SÜD vb.:** Bağımsız test ve tip onayı (homologation).

> **Konumlandırma:** Bu oyuncularla donanım/uçtan uca platformda yarışamazsın. Onların zayıf olduğu yer **kullanım kolaylığı, orkestrasyon ve raporlama**. Senin alanın orası.

---

## 7. Tehdit manzarası — güncel durum (2026)

- Otomotiv siber olayları artıyor: sektör raporları 2026'nın ilk çeyreğinde yüzlerce olay kaydetti; **fidye yazılımı** kalıcı, **EV şarj** olayları katlanarak arttı ve **yapay zeka** yeni bir saldırı yüzeyi olarak öne çıktı.
- ABD'de **CISA**, otonom araçlar için bir rehber ve **AV|CAT (Autonomous Vehicle Cyber-Attack Taxonomy)** aracı yayımladı — saldırı vektörleri, hedefler ve sonuçları çerçeveleyen ücretsiz bir taksonomi. Aracının tehdit modeline ikinci bir referans katman olarak ekleyebilirsin.
- Düzenleyici baskı artıyor: R155 tip onayı zorunluluğu tedarik zincirine yayıldı; Tier-1/Tier-2 tedarikçiler 21434 kanıtı sunmak zorunda. Bu, **kanıt/raporlama araçlarına** talep yaratıyor.

---

## 8. Aracın mimarisi (derinleştirilmiş)

### 8.1 Vehicle Profile (araç profili) — çoklu-model desteğinin anahtarı

Her otobüs modeli, koda dokunmadan bir JSON/YAML profil olarak tanımlanır. Yeni model = yeni profil dosyası.

```yaml
vehicle_profile:
  id: "shuttle-x-2026"
  name: "Otonom Shuttle X"
  model_3d: "models/shuttle_x.glb"
  architecture: "zonal"
  networks:
    - type: "CAN-FD"
      adapter: "socketcan"
      bus: "can0"
    - type: "automotive-ethernet"
      adapter: "someip"
    - type: "ros2-dds"
      adapter: "fastdds"
      domain_id: 0
  components:
    - id: "tcu"
      label: "Telematik Ünitesi"
      position: [x, y, z]
      attack_surfaces: ["cellular", "ota"]
      r155_vectors: ["5.x", "6.x"]
    - id: "lidar_front"
      label: "Ön LiDAR"
      position: [x, y, z]
      attack_surfaces: ["sensor-spoofing"]
      r155_vectors: ["..."]
```

### 8.2 Test eklentileri (deklaratif şablonlar)

```yaml
test_module:
  id: "can-replay-door"
  name: "CAN Replay — Kapı Komutu"
  surface: "in-vehicle-network"
  technique: "replay"
  r155_vector: "2.x"
  avcat_id: "..."
  applicable_to: ["CAN", "CAN-FD"]
  prerequisites: ["bus-access"]
  severity_hint: "high"
  steps: [...]
```

### 8.3 Bulgu şeması (taksonomiye bağlı)

```json
{
  "finding_id": "...",
  "vehicle_profile": "shuttle-x-2026",
  "component": "lidar_front",
  "test_module": "lidar-spoof-removal",
  "r155_vector": "...",
  "impact": {"safety": "high", "operational": "high", "financial": "low", "privacy": "none"},
  "attack_feasibility": "medium",
  "status": "vulnerable",
  "evidence": ["pcap/...", "screenshot/...", "log/..."],
  "timestamp": "..."
}
```

### 8.4 Raporlama motoru

Bulgular → ISO 21434 iş ürünleri ve UN R155 Annex 5 kapsam raporu olarak otomatik dışa aktarılır (docx/pdf).

### 8.5 3B harita = veri-güdümlü navigasyon katmanı

3B model "süs" değil, araç profilindeki `components` listesinden beslenen tıklanabilir bir saldırı yüzeyi haritası. Bir bileşene tıklayınca: saldırı yüzeyleri, ilgili test modülleri, son test durumu ve geçmiş bulgular açılır.

---

## 9. UI/UX tasarım rehberi

### 9.1 Sayfa akışı (önerilen)

1. Giriş / kimlik doğrulama
2. Araç seçim ekranı: filodaki modeller kart olarak; her kartta küçük önizleme + son güvenlik durumu rozeti
3. Araç genel bakış (3B harita): seçilen model döndürülebilir 3B; bileşenler renk kodlu (yeşil=temiz, sarı=test edilmedi, kırmızı=zafiyetli)
4. Test seçim ve çalıştırma: saldırı yüzeyine/taksonomiye göre filtrelenmiş test modülleri; seç, yapılandır, çalıştır
5. Canlı sonuçlar: anomali/IDS paneli, ağ trafiği görünümü
6. Bulgular: filtrelenebilir tablo; her bulgu taksonomi ID, etki, kanıt
7. Raporlama: ISO 21434 / R155 kapsam raporu dışa aktarımı
8. Uyumluluk paneli: Annex 5'in 69 vektörü için kapsam ısı haritası

### 9.2 3B konusunda kıdemli geri bildirim

- **Yapma:** Sadece dönen güzel bir mesh. Demo'da hoş ama erken aşamada haftalarını yer.
- **Yap:** 3B modeli canlı saldırı yüzeyi/dijital ikiz haritasına dönüştür. Mesh aynı; fark, üstündeki tıklanabilir, durum-renkli, veriyle beslenen katman.
- **Sıralama:** 3B'yi en son %10 olarak ele al. Önce çekirdek motor + test modülleri + raporlama.

### 9.3 Teknoloji

- 3B için **three.js** veya **react-three-fiber**; modeller **glTF/GLB**.
- Streamlit ile kalmak istersen 3B'yi gömülü bir HTML/JS bileşeni olarak çalıştırabilirsin; ileride React tabanlı ön yüze geçmeyi düşün.
- MVP'de Streamlit (hız), olgunlaşınca React.

---

## 10. Komşu fırsatlar

1. **V-SOC / filo IDS panosu** — filodaki araçlardan telemetri/CAN/ROS2 logu topla, IsolationForest ile anomali yakala
2. **Otomotiv honeypot / aldatma** — sahte telematik servisi, sahte OBD/teşhis arayüzü, canary token'lı sahte ECU
3. **ATT&CK-for-Automotive tehdit istihbaratı katmanı** — Annex 5 + AV|CAT + kendi matrisini birleştiren korelasyon katmanı
4. **TARA otomasyon aracı** — Excel kâbusunu çözen, varlık→tehdit→risk akışını yöneten araç
5. **Uyumluluk kanıt yöneticisi** — R155/R156 tip onayı için kanıt toplama, Annex 5 kapsam takibi
6. **Otomotiv SBOM yönetimi** — yazılım malzeme listesi + CVE eşleme
7. **Adversarial ML / algı sağlamlık test aracı** — kamera/LiDAR modellerinin spoofing'e dayanıklılığını ölçen, CARLA tabanlı modül
8. **Otomotiv güvenlik eğitim/CTF platformu** — ICSim/CARLA üstüne kurulu

> **Strateji:** Tek bir çekirdek veri modeli (araç profili + taksonomi + bulgu şeması) kur; yukarıdakilerin çoğu bu modelin farklı görünümleri olur.

---

## 11. Öğrenme yol haritası (fazlı)

### Faz 1 — Temeller (donanımsız, ücretsiz)

- **Kitap:** *The Car Hacker's Handbook* (Craig Smith) — Internet Archive'de CC-BY-NC-SA ile ücretsiz
- **Lab:** Kali/Ubuntu + `vcan` + **can-utils** + **ICSim** ile CAN sniff/replay/inject pratiği
- **Araç:** SavvyCAN, CaringCaribou ile tersine mühendislik ve fuzzing

### Faz 2 — Standartlar

- UN R155 (özellikle Annex 5), UN R156, ISO/SAE 21434 (Clause 15 TARA) genel okuması
- CISA Autonomous Ground Vehicle Security Guide + AV|CAT
- Bir mini-TARA egzersizi yap (hayali otobüs için 5 adımı uygula)

### Faz 3 — Otonom yığın

- **ROS2** temelleri (topic/node/DDS), ardından **SROS2 / DDS-Security**
- **CARLA** kurulumu + sensör simülasyonu; sonra **Autoware** entegrasyonu
- ROS2 topic enjeksiyon ve LiDAR/GPS spoofing senaryolarını simülasyonda dene

### Faz 4 — İleri seviye

- Sensör spoofing teorisi (LiDAR injection/removal, GPS SDR spoofing, adversarial patch)
- Firmware RE (Ghidra), yan kanal (ChipWhisperer) — donanım gerektirir, sonraya
- Otomotiv Ethernet/SOME-IP/DoIP derinleşme

### Sürekli

- `awesome-automotive-security` ve `awesome-vehicle-security` GitHub listelerini takip et
- DEF CON Car Hacking Village, Auto-ISAC bültenleri, akademik makaleler (arXiv)

---

## 12. Gerçekçi yol haritası, tuzaklar, kapanış

### 90 günlük ilk hedef

"Simülasyonda çalışan otonom shuttle için ROS2/DDS güvenlik değerlendirme + raporlama aracı." CARLA + Autoware + ROS2 üzerinde 4-5 test modülü, taksonomiye bağlı bulgular, SQLite, Streamlit pano, docx rapor. 3B'yi bu fazda basit tut.

### Sık yapılan hatalar

- **3B'ye/animasyona erken gömülmek.** Önce işlev, sonra görsel cila.
- **Her şeyi kapsamaya çalışmak.** Tek dar şerit seç, derinleş.
- **Standartları sonraya bırakmak.** Taksonomi çapasını en baştan koy; sonradan eklemek mimariyi bozar.
- **Gerçek donanım/araç olmadan ilerleyemeyeceğini sanmak.** Simülasyon + ICSim ile çok yol gidilir.
- **Hukuki sınır:** Gerçek araç/altyapıda test sadece açık yetki/izinle yapılır. Öğrenme ve geliştirmeyi simülasyon ve kendi tezgâhında yap.

### Kapanış çerçevesi

Bu işin uzun ömrü üç şeyden gelir: (1) standart taksonomisine çapalı veri modeli, (2) adaptör/eklenti ile yalıtılmış değişim, (3) rakiplerin zayıf olduğu kullanım kolaylığı + raporlamaya odak. Donanım devleriyle yarışma; onların bıraktığı "anlaşılır, yapılandırılabilir, uyumluluğu otomatikleştiren yazılım katmanı" boşluğunu doldur.

---

## Kaynak / okuma listesi

- The Car Hacker's Handbook — Craig Smith (Internet Archive'de ücretsiz)
- UNECE R155 ve R156 düzenleme metinleri (unece.org)
- ISO/SAE 21434 (özet/rehber makaleler; standart ücretli)
- CISA — Autonomous Ground Vehicle Security Guide & AV|CAT
- ROS2 DDS-Security tasarım dokümanı (design.ros2.org)
- "On the (In)Security of Secure ROS2" (ACM CCS 2022)
- "SROS2: Usable Cyber Security Tools for ROS 2" (IROS 2022)
- CARLA (carla.org), Autoware (autoware.org)
- GitHub: hexsecs/awesome-automotive-security, jaredthecoder/awesome-vehicle-security
- DEF CON Car Hacking Village, Auto-ISAC
