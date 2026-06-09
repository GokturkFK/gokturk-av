#!/usr/bin/env bash
# Bulgu DB + kanıt klasörünü tarihli zip olarak yedekler.
# Kullanım: ./scripts/backup.sh [hedef_klasör]
# Varsayılan hedef: backups/

set -euo pipefail

DEST="${1:-backups}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
ARCHIVE="${DEST}/goktürk-av_backup_${TIMESTAMP}.tar.gz"

mkdir -p "$DEST"

# Yedeklenecek kaynaklar (varsa)
SOURCES=()
[[ -d "data"     ]] && SOURCES+=("data")
[[ -d "evidence" ]] && SOURCES+=("evidence")
[[ -d "reports"  ]] && SOURCES+=("reports")

if [[ ${#SOURCES[@]} -eq 0 ]]; then
  echo "Yedeklenecek veri klasörü bulunamadı (data/, evidence/, reports/)."
  exit 0
fi

tar -czf "$ARCHIVE" "${SOURCES[@]}"
echo "Yedek oluşturuldu: $ARCHIVE"

# 30 günden eski yedekleri temizle
find "$DEST" -name "goktürk-av_backup_*.tar.gz" -mtime +30 -delete
echo "30 günden eski yedekler temizlendi."
