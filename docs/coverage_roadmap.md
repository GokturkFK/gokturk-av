# UN R155 Annex 5 — Kapsam Yol Haritası

> Otomatik üretilmedi ama gerçek orchestrator çıktısından (mock adaptör, vulnerable mod) türetilmiştir — varsayım yok, sadece kod çalıştırılıp sonuç ölçülmüştür. Güncel toplam: **28/69** vektör kapsanmış.

## Üç kategori

- ✅ **Bitmiş** — plugin yazıldı, test edildi, main'de
- 🔧 **Yazılımla yapılabilir** — mock-önce yöntemle ilerletilebilir, henüz yapılmadı
- 🔩 **Donanım/lab gerekli** — gerçek fiziksel ekipman gerektirir (osiloskop, SDR, chip-off rig, gerçek HSM/TPMS donanımı vb.); yazılım oturumuyla ilerlemez


## Kategori 1 — Arka uç sunuculara yönelik tehditler

| Vektör | Açıklama | Durum |
|---|---|---|
| R155-1.1 | Yetkisiz uzaktan sunucu erişimi | ✅ Bitmiş |
| R155-1.2 | Personel tarafından hak kötüye kullanımı | 🔧 Yazılımla yapılabilir |
| R155-1.3 | Sunucuya yetkisiz internet erişimi | 🔧 Yazılımla yapılabilir |
| R155-1.4 | Tedarik zinciri saldırısı (backend) | 🔧 Yazılımla yapılabilir |
| R155-1.5 | Araç servisleri arka uç sunucusuna DoS | ✅ Bitmiş |

## Kategori 2 — İletişim kanallarına yönelik tehditler

| Vektör | Açıklama | Durum |
|---|---|---|
| R155-2.1 | Mesaj sahteciliği / spoofing | ✅ Bitmiş |
| R155-2.2 | Mesaj enjeksiyonu (CAN, Ethernet) | ✅ Bitmiş |
| R155-2.3 | Bilgi dinleme / sniffing | 🔧 Yazılımla yapılabilir |
| R155-2.4 | Servis engelleme / DoS | ✅ Bitmiş |
| R155-2.5 | Replay saldırısı | ✅ Bitmiş |
| R155-2.6 | Ortadaki adam / MitM | 🔧 Yazılımla yapılabilir |
| R155-2.7 | V2X mesaj manipülasyonu | ✅ Bitmiş |
| R155-2.8 | GPS/GNSS spoofing | ✅ Bitmiş |
| R155-2.9 | Sensör (LiDAR/kamera/radar) spoofing | ✅ Bitmiş |
| R155-2.10 | PKES röle saldırısı (anahtarsız giriş sinyal aktarma) | 🔩 Donanım gerekli |
| R155-2.11 | Hücresel ağ kanalı jamming / sinyal manipülasyonu | 🔧 Yazılımla yapılabilir |
| R155-2.12 | NFC/RFID klonlama ve sahteciliği | 🔩 Donanım gerekli |
| R155-2.13 | DSRC / IEEE 802.11p protokol açıklarının istismarı | 🔧 Yazılımla yapılabilir |

## Kategori 3 — Güncelleme prosedürlerine yönelik tehditler

| Vektör | Açıklama | Durum |
|---|---|---|
| R155-3.1 | Güncelleme öncesi yazılım manipülasyonu | ✅ Bitmiş |
| R155-3.2 | Güncelleme kanalına DoS | 🔧 Yazılımla yapılabilir |
| R155-3.3 | Yetkisiz yazılım yükleme | 🔧 Yazılımla yapılabilir |
| R155-3.4 | İmza doğrulama atlatma | ✅ Bitmiş |
| R155-3.5 | OTA kanal gizliliği ihlali | ✅ Bitmiş |
| R155-3.6 | Eski sürüme geri döndürme (downgrade) saldırısı | ✅ Bitmiş |
| R155-3.7 | Güncelleme meta verisi / manifesto manipülasyonu | ✅ Bitmiş |

## Kategori 4 — İstenmeyen insan davranışlarına yönelik tehditler

| Vektör | Açıklama | Durum |
|---|---|---|
| R155-4.1 | Sosyal mühendislik / phishing | 🔧 Yazılımla yapılabilir |
| R155-4.2 | Meşru teşhis erişiminin kötüye kullanımı | ✅ Bitmiş |
| R155-4.3 | Güvensiz varsayılan yapılandırma | 🔧 Yazılımla yapılabilir |
| R155-4.4 | İç tehdit: yetkisiz harici cihaz bağlantısı | 🔧 Yazılımla yapılabilir |
| R155-4.5 | Operatör tarafından hatalı güvenlik yapılandırması | 🔧 Yazılımla yapılabilir |

## Kategori 5 — Dış bağlanabilirliğe yönelik tehditler

| Vektör | Açıklama | Durum |
|---|---|---|
| R155-5.1 | Telematik kanalı istismarı (hücresel/WiFi) | ✅ Bitmiş |
| R155-5.2 | Bluetooth / kısa mesafeli kablosuz saldırı | 🔧 Yazılımla yapılabilir |
| R155-5.3 | USB / fiziksel port saldırısı | 🔧 Yazılımla yapılabilir |
| R155-5.4 | IVI / infotainment üzerinden pivot | ✅ Bitmiş |
| R155-5.5 | OBD-II teşhis portu istismarı | ✅ Bitmiş |
| R155-5.6 | ROS2/DDS kimliksiz topic erişimi | ✅ Bitmiş |
| R155-5.7 | ROS2/DDS mesaj enjeksiyonu | ✅ Bitmiş |
| R155-5.8 | EV şarj kanalı saldırısı (ISO 15118) | 🔩 Donanım gerekli |
| R155-5.9 | Bağlantılı mobil uygulama güvenlik açığı | 🔧 Yazılımla yapılabilir |
| R155-5.10 | Üçüncü taraf IVI uygulaması zafiyeti | 🔧 Yazılımla yapılabilir |
| R155-5.11 | Araç-Bulut API yetkisiz erişimi | 🔧 Yazılımla yapılabilir |
| R155-5.12 | V2I altyapısı üzerinden araç sistemlerine saldırı | ✅ Bitmiş |
| R155-5.13 | Uzaktan telematik sisteme exploit ile erişim | ✅ Bitmiş |

## Kategori 6 — Veri ve koda yönelik tehditler

| Vektör | Açıklama | Durum |
|---|---|---|
| R155-6.1 | Firmware değiştirme / zararlı kod | ✅ Bitmiş |
| R155-6.2 | Kriptografik anahtar çalma | 🔧 Yazılımla yapılabilir |
| R155-6.3 | Kişisel veri sızdırma | 🔧 Yazılımla yapılabilir |
| R155-6.4 | Yazılım bütünlüğü ihlali | ✅ Bitmiş |
| R155-6.5 | ECU firmware tersine mühendislik | 🔧 Yazılımla yapılabilir |
| R155-6.6 | Güvenli depolama (HSM) aşımı | 🔩 Donanım gerekli |
| R155-6.7 | Adversarial ML / algı manipülasyonu | ✅ Bitmiş |
| R155-6.8 | Arabellek taşması / bellek bozulması istismarı | ✅ Bitmiş |
| R155-6.9 | Yarış koşulu / mantık hatası istismarı | 🔧 Yazılımla yapılabilir |
| R155-6.10 | Araç içinde saklanan kişisel veriye yetkisiz erişim | 🔧 Yazılımla yapılabilir |
| R155-6.11 | Olay veri kaydı (EDR / kara kutu) manipülasyonu | 🔧 Yazılımla yapılabilir |
| R155-6.12 | Tedarik zinciri yazılım saldırısı (üçüncü taraf bileşen) | 🔧 Yazılımla yapılabilir |
| R155-6.13 | Güvenli önyükleme (Secure Boot) atlatma | 🔧 Yazılımla yapılabilir |
| R155-6.14 | Hipervizör / konteyner ortamından kaçış | 🔧 Yazılımla yapılabilir |

## Kategori 7 — Araç fiziksel zafiyetlerine yönelik tehditler

| Vektör | Açıklama | Durum |
|---|---|---|
| R155-7.1 | İzinsiz fiziksel ECU erişimi | ✅ Bitmiş |
| R155-7.2 | Donanım manipülasyonu / kurcalama | 🔩 Donanım gerekli |
| R155-7.3 | Yan kanal saldırısı (güç/zamanlama) | 🔩 Donanım gerekli |
| R155-7.4 | Debug portları üzerinden erişim (JTAG/UART) | ✅ Bitmiş |
| R155-7.5 | Hata enjeksiyonu (fault/glitch injection) | 🔩 Donanım gerekli |
| R155-7.6 | TPMS sensörü klonlama ve sahteciliği | 🔩 Donanım gerekli |
| R155-7.7 | Optik sensörlerin lazer/güçlü ışıkla körleştirilmesi | 🔩 Donanım gerekli |
| R155-7.8 | Donanım geri mühendislik (PCB analiz / chip-off) | 🔩 Donanım gerekli |
| R155-7.9 | EMC / EMP tabanlı elektronik bozma saldırısı | 🔩 Donanım gerekli |
| R155-7.10 | Fiziksel erişimle kalıcı arka kapı implantasyonu | 🔩 Donanım gerekli |
| R155-7.11 | Gömülü sistemden fiziksel anahtar / sır çıkarımı | 🔩 Donanım gerekli |
| R155-7.12 | Araç ağına fiziksel cihaz ekleme ile veri enjeksiyonu | 🔩 Donanım gerekli |

## Özet

| Durum | Sayı |
|---|---|
| ✅ Bitmiş | 28 |
| 🔧 Yazılımla yapılabilir (kalan) | 27 |
| 🔩 Donanım gerekli | 14 |
| **Yazılım tavanı (bitmiş + yapılabilir)** | **55** |
| **Toplam** | **69** |

**Sonuç:** Proje, yazılımla ulaşılabilecek 55/69 vektöre ulaştığında (şu an 28/55), yazılım platformu anlamında TAMAMLANMIŞ sayılır. Kalan 14 vektör, gerçek donanım/lab ekipmanı gerektiren ayrı bir faz olarak (CARLA gibi) ileride ele alınır.
