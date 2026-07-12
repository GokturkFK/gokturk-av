# Tehdit Analizi ve Risk Değerlendirmesi (TARA)

**Öğe (Item):** Otonom Servis Aracı v1  
**Profil Kimliği:** `autonomous-shuttle-v1`  
**Mimari:** zonal  
**Metodoloji:** ISO/SAE 21434:2021 — Clause 15 (TARA)  
**Düzenleyici Çerçeve:** UN Regulation No. 155 (CSMS), Annex 5  
**Üretim Tarihi:** 2026-07-12  
**Üretim Yöntemi:** `scripts/generate_tara.py` — profil ve test modüllerinden otomatik türetilmiştir.

> Bu belge otomatik üretilir. Profil (`profiles/autonomous_shuttle_v1.yaml`) veya test modülleri değiştiğinde script yeniden çalıştırılarak güncellenmelidir.

## 1. Kapsam ve Öğe Tanımı

Değerlendirilen öğe, **Otonom Servis Aracı v1** (zonal mimari) aracıdır. Aşağıdaki bileşen sınırları (item boundary) tanımlanmıştır:

| # | Bileşen | Kategori | Ağlar | Saldırı Yüzeyleri |
|---|---------|----------|-------|-------------------|
| 1 | Gateway ECU (`gateway_ecu`) | Ağ | vcan0 | in-vehicle-network, firewall-bypass |
| 2 | HPC / Compute Unit (`hpc_compute`) | Hesaplama | ros2_default, vcan0 | ros2-dds, firmware, os |
| 3 | GNSS Alıcısı (`gnss_receiver`) | Algı/Sensör | ros2_default, carla_sim | sensor-spoofing |
| 4 | LiDAR Kontrolcüsü (`lidar_controller`) | Algı/Sensör | ros2_default, carla_sim | sensor-spoofing, ros2-dds |
| 5 | Kamera İşlemcisi (`camera_processor`) | Algı/Sensör | ros2_default, carla_sim | sensor-spoofing, adversarial-ml |
| 6 | OBD-II Port (`obd2_port`) | Teşhis | vcan0 | diagnostic, physical |
| 7 | V2X OBU (On-Board Unit) (`v2x_obu`) | Bağlanabilirlik | ros2_default | v2x |
| 8 | Telematik Modülü (`telematics_module`) | Bağlanabilirlik | vcan0 | telematics, cellular, ota |
| 9 | OTA Güncelleme İstemcisi (`ota_update_client`) | Bağlanabilirlik | vcan0 | ota |
| 10 | Yolcu Wi-Fi AP (`passenger_wifi_ap`) | Bağlanabilirlik | — | telematics, wifi |

## 2. Varlık Kataloğu ve Siber Güvenlik Özellikleri

Her bileşen bir veya daha fazla **varlık** (asset) barındırır. Korunması gereken siber güvenlik özellikleri (CIA): Gizlilik (C), Bütünlük (I), Erişilebilirlik (A).

| Varlık (Bileşen) | İlgili R155 Vektörleri | Öncelikli Özellik |
|------------------|------------------------|-------------------|
| Gateway ECU | R155-2.2, R155-2.4, R155-2.5, R155-5.4 | Bütünlük + Erişilebilirlik (I/A) |
| HPC / Compute Unit | R155-6.1, R155-6.4, R155-6.8, R155-5.6, R155-5.7 | Bütünlük + Erişilebilirlik (I/A) |
| GNSS Alıcısı | R155-2.8 | Bütünlük (I) |
| LiDAR Kontrolcüsü | R155-2.9, R155-6.7, R155-5.7 | Bütünlük (I) |
| Kamera İşlemcisi | R155-2.9, R155-6.7 | Bütünlük (I) |
| OBD-II Port | R155-5.5, R155-7.1 | Bütünlük (I) |
| V2X OBU (On-Board Unit) | R155-2.7, R155-2.1, R155-5.12 | Gizlilik + Bütünlük (C/I) |
| Telematik Modülü | R155-1.1, R155-5.1, R155-5.13, R155-3.4, R155-3.5, R155-3.6 | Gizlilik + Bütünlük (C/I) |
| OTA Güncelleme İstemcisi | R155-3.1, R155-3.7, R155-3.4 | Gizlilik + Bütünlük (C/I) |
| Yolcu Wi-Fi AP | R155-5.1, R155-5.4 | Gizlilik + Bütünlük (C/I) |

## 3. Tehdit Senaryoları ve Risk Değerlendirmesi

Aşağıdaki tablo, mock (vulnerable) adaptörle çalıştırılan test modüllerinin tespit ettiği tehdit senaryolarını ISO 21434 risk değerlendirmesiyle birlikte listeler. **Etki kısaltmaları:** G=Güvenlik(Safety), O=Operasyonel, F=Finansal, M=Mahremiyet(Privacy). **Risk = f(maks. etki, saldırı fizibilitesi)**; güvenlik-kritik etkiler için taban 'Yüksek' uygulanır.

| Risk | Bileşen | R155 | Tehdit Senaryosu | Etki | Fizibilite | CVSS | Ele Alma |
|------|---------|------|------------------|------|-----------|------|----------|
| **Kritik** | `gateway_ecu` | R155-2.2 | CAN Fuzz: Enjeksiyon mümkün (0x244), 12 anomali | G:high, O:high, F:low | high | 7.1 | Azaltma (zorunlu) — üretim öncesi giderilmeli |
| **Yüksek** | `lidar_controller` | R155-2.9 | LiDAR Spoof: 2/2 senaryo başarılı | G:critical, O:high | low | 8.8 | Azaltma — sonraki sürüm hedefiyle giderilmeli |
| **Yüksek** | `camera_processor` | R155-2.9 | LiDAR Spoof: 2/2 senaryo başarılı | G:critical, O:high | low | 8.8 | Azaltma — sonraki sürüm hedefiyle giderilmeli |
| **Yüksek** | `hpc_compute` | R155-5.7 | ROS2 Enjeksiyon: 2 kritik topic'e yazılabildi | G:critical, O:high | medium | 8.6 | Azaltma — sonraki sürüm hedefiyle giderilmeli |
| **Yüksek** | `lidar_controller` | R155-5.7 | ROS2 Enjeksiyon: 2 kritik topic'e yazılabildi | G:critical, O:high | medium | 8.6 | Azaltma — sonraki sürüm hedefiyle giderilmeli |
| **Yüksek** | `hpc_compute` | R155-6.8 | ECU Fuzz: Bellek bozulması tetiklendi (hpc_compute) — 10 fault, 4 hang | G:high, O:high, F:medium | medium | 8.2 | Azaltma — sonraki sürüm hedefiyle giderilmeli |
| **Yüksek** | `telematics_module` | R155-3.4 | OTA Saldırı: 3/3 senaryo başarılı (birincil: R155-3.4 İmza doğrulama atlatma) | G:high, O:high, F:medium | medium | 8.1 | Azaltma — sonraki sürüm hedefiyle giderilmeli |
| **Yüksek** | `ota_update_client` | R155-3.4 | OTA Saldırı: 3/3 senaryo başarılı (birincil: R155-3.4 İmza doğrulama atlatma) | G:high, O:high, F:medium | medium | 8.1 | Azaltma — sonraki sürüm hedefiyle giderilmeli |
| **Yüksek** | `obd2_port` | R155-5.5 | OBD-II Enum: 4 kritik UDS servisi korumasız | G:high, O:high, F:medium | medium | 7.8 | Azaltma — sonraki sürüm hedefiyle giderilmeli |
| **Yüksek** | `gnss_receiver` | R155-2.8 | GPS Spoof: Sahte konum kabul edildi (38.5012, 43.4089) | G:high, O:high, M:low | medium | 7.4 | Azaltma — sonraki sürüm hedefiyle giderilmeli |
| **Yüksek** | `v2x_obu` | R155-2.7 | V2X Spoof: İmzasız BSM mesajı kabul edildi | G:high, O:high, F:low | medium | 7.1 | Azaltma — sonraki sürüm hedefiyle giderilmeli |
| **Yüksek** | `hpc_compute` | R155-5.6 | ROS2 Topic Enum: 5 kritik topic erişilebilir | G:high, O:high | medium | 6.5 | Azaltma — sonraki sürüm hedefiyle giderilmeli |
| **Yüksek** | `gateway_ecu` | R155-2.5 | CAN Replay: Kimlik doğrulama YOK (0x3E9) | G:medium, O:high, F:low | medium | 5.7 | Azaltma — sonraki sürüm hedefiyle giderilmeli |

## 4. Risk Dağılımı Özeti

| Risk Seviyesi | Tehdit Sayısı | Varsayılan Ele Alma |
|---------------|---------------|---------------------|
| Kritik | 1 | Azaltma (zorunlu) — üretim öncesi giderilmeli |
| Yüksek | 12 | Azaltma — sonraki sürüm hedefiyle giderilmeli |
| **Toplam** | **13** | — |

## 5. Kapsam ve Kısıtlar

- Bu TARA, mevcut **10 test modülünün** kapsadığı **10 / 69** R155 Annex 5 vektörünü yansıtır.
- Kapsanan vektörler: `R155-2.2`, `R155-2.5`, `R155-2.7`, `R155-2.8`, `R155-2.9`, `R155-3.4`, `R155-5.5`, `R155-5.6`, `R155-5.7`, `R155-6.8`
- Bulgular **mock (vulnerable) adaptörle** üretilmiştir; gerçek araç/tezgâh testi (vcan0, ICSim, CARLA) sonuçları farklılık gösterebilir.
- Profildeki bazı bileşenler henüz plugin'i olmayan vektörler taşır (ör. `R155-6.7` adversarial ML) — bunlar bilinçli kapsam boşluğudur ve gelecek geliştirme önceliklerini işaret eder.

---
*ISO/SAE 21434:2021 ve UN R155 Annex 5 referans alınarak GÖKTÜRK-AV tarafından otomatik üretilmiştir.*
