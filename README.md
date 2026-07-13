<div align="center">
██████╗  ██████╗ ██╗  ██╗████████╗██╗   ██╗██████╗ ██╗  ██╗       █████╗ ██╗   ██╗
██╔════╝ ██╔═══██╗██║ ██╔╝╚══██╔══╝██║   ██║██╔══██╗██║ ██╔╝      ██╔══██╗██║   ██║
██║  ███╗██║   ██║█████╔╝    ██║   ██║   ██║██████╔╝█████╔╝ █████╗███████║██║   ██║
██║   ██║██║   ██║██╔═██╗    ██║   ██║   ██║██╔══██╗██╔═██╗ ╚════╝██╔══██║╚██╗ ██╔╝
╚██████╔╝╚██████╔╝██║  ██╗   ██║   ╚██████╔╝██║  ██║██║  ██╗      ██║  ██║ ╚████╔╝
╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝      ╚═╝  ╚═╝  ╚═══╝

### Otonom Araç Siber Test ve Uyumluluk Platformu

*UN R155 Annex 5 ve ISO/SAE 21434 TARA'ya çapalı; test eder, raporlar, uyumluluğu görselleştirir.*

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![UI](https://img.shields.io/badge/UI-Streamlit-red)
![DB](https://img.shields.io/badge/DB-SQLite-lightgrey)
![Framework](https://img.shields.io/badge/Framework-UN%20R155%20%2F%20ISO%2021434-orange)
![Vektör Kapsamı](https://img.shields.io/badge/R155%20Kapsam-19%2F69-green)
![Sürüm](https://img.shields.io/badge/Sürüm-v0.2.0-informational)
![License](https://img.shields.io/badge/License-Private-lightgrey)

</div>

---

## Genel Bakış

GÖKTÜRK-AV, otonom otobüs/shuttle sınıfı araçlar için geliştirilmiş bir siber
güvenlik test ve uyumluluk platformudur. Aracın CAN ağından ROS2/DDS algı
yığınına, OTA güncelleme kanalından backend/filo yönetim sunucusuna kadar
tüm saldırı yüzeyini **UN R155 Annex 5'in 69 vektörüne** çapalı olarak test
eder; sonuçları **ISO/SAE 21434 TARA** metodolojisiyle risk değerlendirmesine,
otomatik docx raporuna ve canlı bir uyumluluk ısı haritasına dönüştürür.

Çekirdek motor hiçbir araç modelini doğrudan tanımaz — yeni bir araç, sadece
yeni bir YAML profili demektir; test modülleri deklaratif ve taksonomiye
bağlıdır; adaptör katmanı sayesinde aynı test modülü hem mock'ta hem gerçek
CAN/ROS2/CARLA ortamında değişmeden çalışır.

İki perspektif bir arada:

- 🔴 **Saldırı Simülasyonu** — CAN replay/fuzz, ROS2/DDS enjeksiyon, V2X
  spoofing, GPS/LiDAR/kamera spoofing, ECU firmware fuzzing, OTA saldırısı,
  backend erişimi, teşhis suistimali, fiziksel debug portu erişimi.
- 🔵 **Uyumluluk & Raporlama** — 3D saldırı yüzeyi haritası, UN R155 Annex 5
  ısı haritası (69 hücre), ISO 21434 TARA otomatik üretimi, docx rapor.

---

## Hızlı Başlangıç

Gereksinim: **Python ≥ 3.10**

```bash
# Sanal ortam
python3 -m venv venv

# Linux/macOS
source venv/bin/activate
# Windows
venv\Scripts\activate

pip install -r requirements.txt

# Ortam değişkenleri
cp .env.example .env   # Windows: copy .env.example .env
```

### Lab ortamı (Linux — vcan + can-utils)

```bash
chmod +x lab_setup.sh && ./lab_setup.sh
```

Gerçek `vcan0` üzerinde doğrulanmıştır — bkz. `docs/coverage_roadmap.md`.

### Streamlit UI

```bash
streamlit run ui/app.py
```

### TARA belgesini üret

```bash
python scripts/generate_tara.py > docs/tara.md
```

---

## Proje Yapısı
GÖKTÜRK-AV/
├── core/             → Çekirdek motor (finding store, orchestrator, raporlama, 3D harita, ısı haritası)
├── adapters/         → Araç bağlantı adaptörleri (SocketCAN, mock, CARLA — planlı)
├── plugins/          → Test modülleri (15 modül, R155 vektörüne çapalı)
├── taxonomy/         → UN R155 Annex 5 taksonomisi (69 vektör, 7 kategori)
├── profiles/         → Araç profilleri (YAML) + şema dokümantasyonu
├── scripts/          → TARA belge üreticisi
├── ui/               → Streamlit pano (Araç Seçimi, Saldırı Yüzeyi, Test Çalıştır, Bulgular, Uyumluluk, Raporlama)
├── docs/             → TARA belgesi, kapsam yol haritası, saha araştırması
└── data/             → SQLite DB (runtime, .gitignore'da)

---

## Mimari Felsefesi

- **Sabit çekirdek** — motor hiçbir zaman aracı doğrudan tanımaz
- **Adaptör katmanı** — yeni araç/protokol = yeni adaptör, çekirdek dokunulmaz; mock ↔ gerçek geçişi plugin kodunu değiştirmez
- **Deklaratif test modülleri** — YAML profiller, kod değişmeden genişler
- **Taksonomiye bağlı bulgular** — her bulgu R155 vektörüne çapalı, rapor otomatik

---

## Kapsam Durumu

**19 / 69 R155 Annex 5 vektörü** kapsanıyor; **7 kategorinin tamamı** en az bir
vektörle temsil ediliyor. Kalan vektörlerin yazılımla ilerletilebilir olanları
ile gerçek donanım/lab (osiloskop, SDR, chip-off vb.) gerektirenlerin tam
dökümü için:

**Docs:** [Kapsam Yol Haritası →](docs/coverage_roadmap.md) · [TARA Belgesi →](docs/tara.md) · [Saha Araştırması →](docs/saha-arastirmasi.md)

---

## Katkı

| Rol | Sorumluluk |
|-----|-----------|
| Güvenlik | Test modülleri, TARA, bulgu analizi, araştırma |
| DevOps | CI/CD, Docker, ortam yönetimi, yedekleme, release |
