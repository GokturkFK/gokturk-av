# GÖKTÜRK Araç Profili Şeması

Bu dizindeki her YAML dosyası, GÖKTÜRK-AV'nin test edeceği bir araç mimarisini
tanımlar. **Çekirdek motor hiçbir zaman belirli bir araç modelini tanımaz** —
yeni bir araç = bu şemaya uygun yeni bir YAML dosyası; koda dokunulmaz.

## Mevcut profiller

| Dosya | Amaç |
|---|---|
| `shuttle_example.yaml` | Faz 1 simülasyon profili (CARLA + ROS2 FastDDS) |
| `autonomous_shuttle_v1.yaml` | Gerçekçi Level 4 otonom servis aracı referans profili — 10 bileşenlik tam kataloğu (backend, algı, teşhis, güncelleme, yolcu bağlanabilirliği) |

## Kök seviye alanlar

| Alan | Tip | Açıklama |
|---|---|---|
| `profile_version` | string | Şema sürümü (şu an `"1.0"`) |
| `id` | string | Benzersiz profil kimliği (FindingStore anahtarı) |
| `name` | string | İnsan-okur araç adı |
| `model_3d` | string | (opsiyonel) glTF/GLB model yolu — şu an yalnızca belge amaçlı, 3D harita prosedürel geometri kullanır |
| `architecture` | string | Mimari tipi (ör. `zonal`, `centralized-domain`, `distributed`) |
| `notes` | string | Serbest metin bağlam notu |
| `networks` | list | Araçtaki ağ segmentleri (aşağıya bakınız) |
| `components` | list | Test edilecek bileşenler (aşağıya bakınız) |

## `networks` alanı

Her ağ segmenti şu alanları taşır:

| Alan | Açıklama |
|---|---|
| `id` | Ağ kimliği (bileşenlerin `networks` listesinde referans verdiği) |
| `type` | `"CAN"`, `"ros2-dds"`, `"simulation"` vb. |
| `adapter` | Hangi adaptör sınıfının bu ağı kullanacağı (`socketcan`, `ros2`, `carla`) |
| Adaptöre özgü alanlar | ör. CAN için `interface`, ROS2 için `domain_id`/`middleware`, CARLA için `host`/`port` |

## `components` alanı

Her bileşen şu alanları taşımalıdır:

| Alan | Zorunlu | Açıklama |
|---|---|---|
| `id` | ✅ | Benzersiz bileşen kimliği (bulgularda `component_id` olarak görünür) |
| `label` | ✅ | İnsan-okur ad (UI'da gösterilir) |
| `category` | ✅ | Bileşen kategorisi: `network`, `compute`, `sensor`, `diagnostic`, `connectivity`, `physical`, `ev-charging` |
| `position_3d` | ✅ | `[x, y, z]` — 3D saldırı yüzeyi haritasında konum. **Konvansiyon:** x = ön(+)/arka(−), y = yükseklik (gövde tabanı referans, çatı-üstü bileşenler için pozitif büyük değerler kabul edilir — anten/LiDAR gibi), z = küçük yan ofset. Gövde oranları `core/attack_surface.py`'de sabit (7×2.4×2.2), bileşen konumları bu kutuya göreceli olmalı. |
| `attack_surfaces` | ✅ | Saldırı yüzeyi etiketleri listesi (plugin'lerin `surface` alanıyla gevşek eşleşme için) — ör. `["sensor-spoofing"]`, `["ota"]`, `["v2x"]` |
| `r155_vectors` | ✅ | Bu bileşene **gerçekten uygulanabilir** UN R155 Annex 5 vektör ID'leri listesi (ör. `["R155-2.9"]`). **Kopyala-yapıştır yapılmamalı** — her vektör, `taxonomy/r155_annex5.json`'dan bileşenin gerçek fonksiyonuna göre seçilmelidir. Orchestrator önce vektör eşleşmesine bakar (`_match_components` — vektör-öncelikli), yalnızca hiçbir bileşen o vektörü taşımıyorsa yüzey eşleşmesine düşer. |
| `networks` | ✅ | Bu bileşenin bağlı olduğu `networks` listesindeki `id`'ler (yoksa `[]`) |
| `test_status` | ✅ | Başlangıç durumu, her zaman `"not_tested"` (gerçek durum çalışma anında `FindingStore`'dan hesaplanır, bu alan yalnızca ilk yükleme placeholder'ıdır) |

## R155 vektör seçimi — nasıl doğru yapılır

1. `taxonomy/r155_annex5.json` dosyasını aç, 7 kategoriyi ve 69 vektörü incele.
2. Bileşenin **gerçekte** hangi saldırılara maruz kalabileceğini düşün (ör. bir OBD-II portu için R155-5.5 açık ara en isabetlisi; R155-6.1 gibi firmware vektörlerini OBD-II'ye eklemek yanlış olur).
3. Birden fazla vektör uygunsa hepsini listele — orchestrator, mevcut her plugin için ayrı ayrı eşleşme arar.
4. Henüz hiçbir plugin'in kapsamadığı ama bileşenin gerçekten maruz kaldığı vektörleri de eklemekten çekinme (ör. `R155-6.7` adversarial ML — henüz plugin yok ama LiDAR/kamera için gerçek bir vektör). Bu, uyumluluk ısı haritasında dürüst bir "kapsanmayan alan" göstergesi olur ve gelecekteki plugin geliştirme önceliklerini işaret eder.

## Yeni profil ekleme

```bash
cp profiles/autonomous_shuttle_v1.yaml profiles/senin_profilin.yaml
# id, name, components listesini düzenle
```

Streamlit UI'da **Araç Seçimi → Profil Yükle** ile `.yaml` dosyasını yükle;
orchestrator ve 3D harita otomatik olarak yeni profili işler, koda dokunmaya
gerek yoktur.
