#!/usr/bin/env bash
# Kiểm thử tự động các kịch bản demo qua Web UI (curl), trên một stack Docker riêng.
# Dùng: cd code && bash test/e2e.sh
# Chạy trên project "cpabe-test" (cổng 8098/8099) và xóa sạch khi xong, không đụng stack demo "cpabe-demo".
set -uo pipefail
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-cpabe-test}
export APP_PORT=${APP_PORT:-8098} ADMINER_PORT=${ADMINER_PORT:-8099}
APP="http://localhost:$APP_PORT"
PASS=0 FAIL=0

check() { # $1 = tên kịch bản, $2 = điều kiện (lệnh trả 0 nếu đạt)
  if eval "$2"; then echo "  ✔ $1"; PASS=$((PASS + 1)); else echo "  ✖ $1"; FAIL=$((FAIL + 1)); fi
}
page() { curl -s -L -b "as=$1${3:+; epoch=$3}" "$APP$2"; }                         # $1 user, $2 path, $3 epoch
post() { curl -s -L -b "as=$1" -X POST "$APP$2" "${@:3}"; }                        # $1 user, $2 path, data...
docid() { page "$1" / | grep -oE "/doc/[0-9a-f]{16}\"><b>$2" | grep -oE '[0-9a-f]{16}' | head -1; }
unlocked() { page "$1" / | grep -c '🔓'; }

fresh() { # $1 = CLOUD_ENFORCE_READ
  docker compose down -v >/dev/null 2>&1
  CLOUD_ENFORCE_READ=$1 docker compose up -d >/dev/null 2>&1 || { echo "không bật được stack"; exit 1; }
  for _ in $(seq 90); do curl -fs "$APP/" >/dev/null 2>&1 && return; sleep 1; done
  echo "app không lên ở $APP"; exit 1
}

echo "Build image..."
docker compose build -q || exit 1

echo "== Chế độ mặc định (CLOUD_ENFORCE_READ=false)"
fresh false
Q3=$(docid an "Báo cáo tài chính Q3"); BUDGET=$(docid an "Đề xuất ngân sách"); ALPHA=$(docid dung "Đặc tả dự án Alpha")
check "seed: 4 tài liệu, Hà (Giám đốc) đọc được 3" '[ "$(unlocked ha)" = 3 ] && [ -n "$Q3" ] && [ -n "$BUDGET" ] && [ -n "$ALPHA" ]'
check "A · Góc nhìn Cloud không có plaintext" '! page an /cloud | grep -q "Doanh thu"'
check "B · Dũng chỉ đọc được Đặc tả Alpha" '[ "$(unlocked dung)" = 1 ] && page dung / | grep -q "<b>Đặc tả dự án Alpha"'
check "I · Dũng ghi được Đề xuất ngân sách" 'post dung /doc/$BUDGET/edit -d base_version=1 -d title=T -d body=B | grep -q "Đã lưu phiên bản 2"'
check "I · …nhưng Dũng vẫn không đọc được" 'page dung /doc/$BUDGET | grep -q "Không đủ thuộc tính"'
check "D · Bình ghi trái phép → cloud trả 403" 'post binh /doc/$Q3/forge | grep -q "403"'
post an /admin/revoke -d user=binh -d attr=dept_finance -d mode=lazy >/dev/null
post an /doc/$Q3/edit -d base_version=1 -d title=Q3 -d body=v2 >/dev/null
check "C · Sau thu hồi dept_finance, Bình không đọc được Q3" 'page binh /doc/$Q3 | grep -q "Không đủ thuộc tính"'
check "H · Bình dùng khóa epoch cũ vẫn không đọc được" 'page binh /doc/$Q3 1 | grep -q "Không đủ thuộc tính"'
check "C · An vẫn đọc được Q3 v2" 'page an /doc/$Q3 | grep -q "🔓"'
post an /cloud/tamper -d doc=$Q3 -d version=2 >/dev/null
check "E · Cloud sửa 1 bit → app phát hiện" 'page an /doc/$Q3 | grep -q "bị sửa đổi"'
post an /admin/grant -d user=binh -d attr=proj_alpha >/dev/null
check "F · Cấp proj_alpha, Bình đọc ngay Đặc tả Alpha" 'page binh /doc/$ALPHA | grep -q "🔓"'
check "G · Bình và Chi đều không đọc được Đề xuất ngân sách" 'page binh /doc/$BUDGET | grep -q "Không đủ thuộc tính" && page chi /doc/$BUDGET | grep -q "Không đủ thuộc tính"'
post an /admin/revoke -d user=dung -d attr=proj_alpha -d mode=eager >/dev/null
check "J · Eager: thế hệ cũ của chính sách Alpha đã hủy" 'page an /cloud | grep -q "đã hủy" || page an /admin | grep -q "EAGER"'

echo "== C7 bật (CLOUD_ENFORCE_READ=true), kịch bản K"
fresh true
Q3=$(docid an "Báo cáo tài chính Q3")
check "K · Trước thu hồi, Bình đọc được Q3" 'page binh /doc/$Q3 | grep -q "🔓"'
post an /admin/revoke -d user=binh -d attr=dept_finance -d mode=rekey >/dev/null
for _ in $(seq 50); do page an /admin | grep -q "Pha 2" && break; sleep 0.2; done
check "K · Pha 2 (re-key) chạy xong, có trong nhật ký" 'page an /admin | grep -q "Pha 2: mã hóa lại nội dung"'
check "K · Cloud không trả bản mã cho Bình" 'page binh /doc/$Q3 | grep -q "Cloud không trả bản mã"'
check "K · An vẫn đọc được Q3 sau re-key" 'page an /doc/$Q3 | grep -q "🔓"'
check "K · Dũng vẫn ghi mà không đọc (C7 bật)" 'post dung /doc/$(docid an "Đề xuất ngân sách")/edit -d base_version=1 -d title=T -d body=B | grep -q "Đã lưu phiên bản 2"'

echo "== bench dek (user đã lưu DEK), C7 tắt, chế độ re-key"
fresh false
check "dek · re-key: DEK cũ không mở được bản mã tải lại" 'docker compose run --rm bench dek -mode rekey 2>/dev/null | grep -q "không (bản mã đã đổi)"'

docker compose down -v >/dev/null 2>&1
echo "Kết quả: $PASS đạt, $FAIL lỗi"
[ "$FAIL" = 0 ]
