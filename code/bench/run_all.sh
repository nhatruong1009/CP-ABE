#!/usr/bin/env bash
# C1: chạy toàn bộ phép đo trên Docker, mỗi lần chạy reset dữ liệu (docker compose down -v) của project cpabe-bench.
# Dùng: cd code && bash bench/run_all.sh > ../docs/bench-ket-qua.md
set -euo pipefail
cd "$(dirname "$0")/.."
# Chạy trên project riêng "cpabe-bench" để không xóa dữ liệu của stack demo.
export COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-cpabe-bench}
export APP_PORT=${APP_PORT:-8098} ADMINER_PORT=${ADMINER_PORT:-8099}

fresh() { # $1 = CLOUD_ENFORCE_READ
  docker compose down -v >/dev/null 2>&1
  CLOUD_ENFORCE_READ=$1 docker compose up -d >/dev/null 2>&1
  for _ in $(seq 60); do
    curl -fs "http://localhost:$APP_PORT/" >/dev/null 2>&1 && return
    sleep 1
  done
  echo "stack không lên" >&2; exit 1
}
bench() { docker compose run --rm bench "$@" 2>/dev/null; }

echo "# Kết quả đo C1 ($(date '+%d/%m/%Y %H:%M'), $(nproc) nhân CPU)"
echo
bench micro -reps 30 2>/dev/null || docker run --rm --entrypoint bench cpabe-demo:latest micro -reps 30

echo
echo "## Thu hồi dept_finance của Bình trên stack Docker (gồm mạng + PostgreSQL, ms)"
echo
echo "Tài liệu thêm vào đều dùng chính sách của Báo cáo Q3. Pha 2 tính từ lúc gửi yêu cầu thu hồi tới lúc pha 2 ghi audit."
echo
echo "| Tổng tài liệu | Chế độ | Trả lời thu hồi (pha 1) | Xong pha 2 |"
echo "|---|---|---|---|"
for d in 0 100 1000; do
  for m in lazy eager twophase rekey; do
    fresh false
    bench e2e -docs "$d" -mode "$m"
  done
done

echo
echo "## Kịch bản DEK đã lưu: Bình đọc Báo cáo Q3, lưu DEK + private Policy Key + bản mã, rồi bị thu hồi dept_finance"
echo
for enf in false true; do
  echo "### CLOUD_ENFORCE_READ=$enf"
  echo
  echo "| Chế độ | (1) DEK đã lưu + bản mã đã tải | (2) Tải lại từ cloud | (3) DEK đã lưu + bản mã tải lại | (4) Policy Key cũ + wrapped_dek tải lại |"
  echo "|---|---|---|---|---|"
  for m in lazy eager twophase rekey; do
    fresh "$enf"
    bench dek -mode "$m"
  done
  echo
done
docker compose down -v >/dev/null 2>&1
