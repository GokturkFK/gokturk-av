#!/usr/bin/env bash
# GÖKTÜRK — Faz 1 Lab Kurulumu
# Sanal CAN + ICSim (donanımsız CAN testi)

set -e

echo "=== GÖKTÜRK Lab Kurulumu ==="

# 1. Sanal CAN arayüzü
echo "[1/4] Sanal CAN yükleniyor..."
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan 2>/dev/null || true
sudo ip link set up vcan0
echo "  ✓ vcan0 hazır"

# 2. can-utils
echo "[2/4] can-utils kuruluyor..."
sudo apt-get install -y can-utils libsdl2-dev libsdl2-image-dev > /dev/null
echo "  ✓ can-utils hazır"

# 3. ICSim (enstrüman kümesi simülatörü)
echo "[3/4] ICSim kuruluyor..."
if [ ! -d "ICSim" ]; then
  git clone https://github.com/zombieCraig/ICSim.git
fi
cd ICSim
sudo apt-get install -y meson ninja-build > /dev/null
meson setup builddir --wipe > /dev/null 2>&1 || true
cd builddir && meson compile > /dev/null 2>&1
cd ../..
echo "  ✓ ICSim derlendi"

# 4. Python bağımlılıkları
echo "[4/4] Python bağımlılıkları..."
pip install -r requirements.txt -q
echo "  ✓ Python paketleri hazır"

echo ""
echo "=== Lab Hazır! ==="
echo ""
echo "ICSim başlatma (3 ayrı terminal):"
echo "  Terminal 1: cd ICSim && ./builddir/icsim vcan0"
echo "  Terminal 2: cd ICSim && ./builddir/controls vcan0"
echo "  Terminal 3: candump vcan0  # veya python3 -m pytest"
echo ""
echo "GÖKTÜRK UI:"
echo "  cp .env.example .env"
echo "  streamlit run ui/app.py"
