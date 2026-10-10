#!/usr/bin/env bash
# Kịch bản demo PoC end-to-end. Yêu cầu stack đã chạy: docker compose up -d
set -euo pipefail
cd "$(dirname "$0")/.."
cli() { docker compose run --rm -T client "$@"; }
step() { printf '\n==== %s ====\n' "$*"; }
expect_fail() { if "$@"; then echo "!! LẼ RA PHẢI THẤT BẠI"; exit 1; else echo "(thất bại đúng như kỳ vọng)"; fi; }

step "1. Đăng nhập (auth) và nhận khóa CP-ABE (KGC)"
for u in alice:alice123 bob:bob123 carol:carol123 dave:dave123 erin:erin123 admin:admin123; do
  cli login "${u%%:*}" "${u##*:}"
done
for u in bob carol dave erin; do cli fetch-key "$u"; done

step "2. Owner tạo bản ghi (mã hóa tại client, APP chỉ nhận ciphertext)"
cli put alice BA-0001 --policy "(Dept:Cardiology AND Role:Doctor) OR Role:Director" \
    --text "Chẩn đoán: rung nhĩ. Điều trị: kháng đông."
cli put alice BA-0002 --policy "Dept:Cardiology AND (Role:Doctor OR Role:Nurse)" \
    --text "Sinh hiệu: HA 130/85, nhịp 92. Thuốc: apixaban 5mg."
cli put alice BL-0001 --policy "Dept:Finance AND Role:Cashier" --text "BHYT 80%, tạm ứng 2.000.000đ"
cli list alice

step "3. Kịch bản A — DBA của cloud đọc trực tiếp outsource-db"
docker compose exec -T outsource-db psql -U cloud -d cloud -c \
  "SELECT record_id, version, left(doc->>'ciphertext', 40) AS ciphertext, doc->>'policy_abe' AS policy FROM encrypted_records;"

step "4. Đọc theo thuộc tính (kịch bản B)"
cli get bob BA-0001
cli get carol BA-0002
expect_fail cli get carol BA-0001
expect_fail cli get erin BA-0001
cli get dave BL-0001
expect_fail cli get dave BA-0002

step "5. Đổi policy BA-0001 cho cả y tá (chỉ bọc lại header, ciphertext giữ nguyên)"
cli set-policy alice BA-0001 --policy "Dept:Cardiology AND (Role:Doctor OR Role:Nurse)"
cli get carol BA-0001

step "6. Update nội dung (CEK mới)"
cli put alice BA-0002 --policy "Dept:Cardiology AND (Role:Doctor OR Role:Nurse)" \
    --text "Sinh hiệu: HA 120/80, nhịp 76. Thuốc: apixaban 5mg."
cli get bob BA-0002

step "7. Thu hồi carol (kịch bản C)"
cli revoke admin carol
sleep 3   # chờ cache revocation của APP (REVOCATION_TTL=2s)
expect_fail cli get carol BA-0002          # bị APP chặn (lớp vận hành)
expect_fail cli fetch-key carol            # KGC không cấp khóa mới
docker compose run --rm -T client worker-rewrap
expect_fail cli get bob BA-0002            # khóa epoch cũ hết hiệu lực
cli fetch-key bob
cli get bob BA-0002

step "8. Xóa"
cli delete alice BL-0001
cli list alice

echo; echo "DEMO HOÀN TẤT"
