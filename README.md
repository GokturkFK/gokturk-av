# 🛡️ GÖKTÜRK-AV — Otonom Araç Siber Test Platformu

Autonomous vehicle cybersecurity testing & reporting platform.
Anchored to UN R155 Annex 5 (69 attack vectors) and ISO/SAE 21434 TARA.

## Hızlı Başlangıç

```bash
# Sanal ortam
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Ortam değişkenleri
cp .env.example .env

# Sanal CAN (Lab için)
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# Streamlit UI
streamlit run ui/app.py
```

## Proje Yapısı

```
GOKTÜRK/
├── core/             → Çekirdek motor (finding store, orchestrator)
├── adapters/         → Araç bağlantı adaptörleri (CAN, ROS2, simülasyon)
├── plugins/          → Test modülleri + YAML manifests
├── taxonomy/         → UN R155 / AV|CAT taksonomi
├── profiles/         → Araç profilleri (YAML)
├── ui/               → Streamlit pano
└── data/             → SQLite DB (runtime)
```

## Mimari Felsefesi

- **Sabit çekirdek** — motor hiçbir zaman aracı doğrudan tanımaz
- **Adaptör katmanı** — yeni otobüs modeli = yeni adaptör, çekirdek dokunulmaz
- **Deklaratif test modülleri** — YAML şablonlar, kod değişmeden genişler
- **Taksonomiye bağlı bulgular** — her bulgu R155 vektörüne çapalı, rapor otomatik

## Faz Planı

| Faz | Hafta | Hedef |
|-----|-------|-------|
| 1 | 1-2 | Domain el deneyi (ICSim + CARLA lab) |
| 2 | 3-5 | Çekirdek motor + şemalar |
| 3 | 6-7 | İlk test modülleri (CAN, ROS2, sensör) |
| 4 | 8-9 | Streamlit UI + raporlama |
| 5 | 10-12 | Bütünleşme + MVP finali |
