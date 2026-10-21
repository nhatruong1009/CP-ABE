# Kho tài liệu CP-ABE: PoC cho Outsourced Storage

```
CP_ABE_1/
├── code/        # mã nguồn Go + Dockerfile + docker-compose.yml
│   ├── authority/ app/ cloudapi/ shared/   # 3 service + phần dùng chung
│   ├── bench/   # công cụ đo (C1) + run_all.sh
│   └── test/    # e2e.sh: kiểm thử tự động các kịch bản demo
├── docs/        # thiết kế, sổ nguồn tham khảo, bench-ket-qua.md
├── ref/         # tài liệu gốc, bản lưu mã nguồn thư viện đã đối chiếu
├── tools/
└── CHANGELOG.md
```

Đồ án môn An toàn và bảo mật trong HTTT (Nhóm 06). Thiết kế chi tiết: [docs/01-de-xuat-cai-tien.md](docs/01-de-xuat-cai-tien.md).

## Chạy

Yêu cầu: Docker và Docker Compose. Không cần cài Go, vì code được biên dịch trong Docker.

Toàn bộ mã nguồn nằm trong [code/](code/):

```bash
cd code
docker compose up -d --build     # lần đầu tải thư viện + build, mất vài phút
docker compose logs -f authority # chờ dòng "authority lắng nghe :8081"
```

| URL | Thành phần |
|---|---|
| http://localhost:8088 | **app**: Web UI (vùng tin cậy). Đổi cổng: `APP_PORT=9000 docker compose up -d` |
| http://localhost:8090 | **Adminer** (đổi bằng `ADMINER_PORT`): góc nhìn DBA của cloud (System: PostgreSQL, server `cloud-db`, user/pass/db `cloud`) |

Dừng: `docker compose down`. Xóa sạch dữ liệu (Master Key, khóa, DB) để chạy lại từ đầu: `docker compose down -v`.

Cổng 8088 / 8090 đã có chương trình khác dùng thì đổi: `APP_PORT=8098 ADMINER_PORT=8099 docker compose up -d`.

### Chế độ thu hồi (trang Quản trị → ô "Chế độ xử lý tài liệu cũ")

| Chế độ | `mode` | Làm gì | Chặn được |
|---|---|---|---|
| Lazy | `lazy` | Tăng version, KeyGen lại, chính sách sang thế hệ mới. Phiên bản cũ giữ thế hệ cũ | Khóa ABE cũ, Write Key |
| Eager | `eager` | Như Lazy + bọc lại ngay (đồng bộ) cùng DEK sang thế hệ mới, hủy thế hệ cũ | + Policy Key đã lưu |
| Hai pha (C8) | `twophase` | Pha 1 như Lazy, trả lời ngay; pha 2 bọc lại DEK chạy nền | + Policy Key đã lưu (sau pha 2) |
| Hai pha + re-key (C9) | `rekey` | Pha 2 giải mã, mã hóa lại nội dung bằng DEK mới, ký lại | + DEK đã lưu (với bản mã tải lại) |

Pha 2 xong thì trang Quản trị có dòng nhật ký `Pha 2: …`.

### Bật C7: cloud kiểm access token

Mặc định tắt để giữ nguyên các kịch bản demo. Khi bật, `cloud-api` chỉ trả `wrapped_dek` / `nonce` / `ciphertext` cho người có access token thỏa chính sách đọc. Người đã bị thu hồi thấy "Cloud không trả bản mã…".

```bash
cd code
CLOUD_ENFORCE_READ=true docker compose up -d
# hoặc chạy song song với stack demo, project riêng, cổng riêng:
CLOUD_ENFORCE_READ=true APP_PORT=8098 ADMINER_PORT=8099 docker compose -p cpabe-v4 up -d
docker compose -p cpabe-v4 down -v   # xóa khi xong
```

## Kiểm thử tự động

```bash
cd code
bash test/e2e.sh      # khoảng 2 phút
```

Script build image, bật một stack riêng (project `cpabe-test`, cổng 8098/8099), chạy các kịch bản A–K dưới đây qua Web UI rồi xóa stack. Stack demo của bạn (`cpabe-demo`) không bị đụng tới. Kết quả cuối: `Kết quả: 19 đạt, 0 lỗi`.

## Đo hiệu năng (C1)

```bash
cd code
docker compose build
docker run --rm --entrypoint bench cpabe-demo:latest micro      # chỉ đo thao tác mật mã, không cần bật stack
bash bench/run_all.sh > ../docs/bench-ket-qua.md                # đo đầy đủ, khoảng 5–10 phút (project riêng cpabe-bench)
```

Các lệnh con của `bench` (chạy trong stack đang bật: `docker compose run --rm bench <lệnh>`):

| Lệnh | Đo / kiểm gì |
|---|---|
| `micro -reps 30` | Chi phí từng thao tác (CP-ABE, X25519, AES-GCM, Ed25519), thu hồi theo số tài liệu D, đọc có / không cache |
| `e2e -docs 1000 -mode lazy` | Thêm D tài liệu rồi thu hồi `dept_finance` của Bình, đo thời gian trả lời và pha 2 |
| `dek -mode rekey` | Bình lưu DEK + Policy Key, bị thu hồi, thử đọc lại. Chạy trên stack mới (`down -v` trước) |

Kết quả lần đo gần nhất: [docs/bench-ket-qua.md](docs/bench-ket-qua.md).

## Thành phần

| Container | Vùng | Vai trò |
|---|---|---|
| `authority` | Tin cậy | Key Authority: Master Key, thuộc tính có version, chính sách, Policy Key theo thế hệ, cấp/thu hồi |
| `app` | Tin cậy | Web UI. Mã hóa/giải mã/ký tại chỗ. `keystore` mô phỏng thiết bị của user |
| `cloud-api` | Cloud | Lưu bản mã, kiểm chữ ký ghi. **Không có khóa bí mật**. Lưu ý: `authority` cũng nằm trong `cloud_net` và API chưa xác thực, nên `cloud-api` vẫn gọi được `authority` (hạn chế đã biết) |
| `cloud-db` | Cloud | PostgreSQL |
| `cloud-admin` | Cloud | Adminer |

## Người dùng & tài liệu mẫu

| User | Thuộc tính |
|---|---|
| An | `dept_finance`, `role_manager` |
| Bình | `dept_finance`, `role_staff` |
| Chi | `dept_hr`, `role_manager` |
| Dũng | `dept_eng`, `role_staff`, `proj_alpha` |
| Hà (Giám đốc) | `role_director` |

| Tài liệu | Đọc | Sửa |
|---|---|---|
| Bảng lương tháng 10 | `(dept_hr and role_manager) or role_director` | `dept_hr and role_manager` |
| Báo cáo tài chính Q3 | `dept_finance or role_director` | `dept_finance and role_manager` |
| Đặc tả dự án Alpha | `proj_alpha or role_director` | `proj_alpha` |
| Đề xuất ngân sách phòng Kỹ thuật | `dept_finance and role_manager` | `role_staff or role_manager` |

## Kịch bản demo

| # | Thao tác trên UI | Kỳ vọng |
|---|---|---|
| A | Mở **Góc nhìn Cloud** hoặc Adminer | Chỉ thấy byte mã hóa, không có tiêu đề/nội dung |
| B | Đóng vai **Dũng** → Kho tài liệu | Bảng lương, Báo cáo Q3, Đề xuất ngân sách: 🔒. Đặc tả Alpha: 🔓 |
| C | **Quản trị** → thu hồi `dept_finance` của **Bình** (Lazy) → đóng vai **An**, sửa Báo cáo Q3 → đóng vai **Bình** | Bình không đọc được tài liệu nào của Finance (khóa mới không còn `dept_finance`) |
| D | Đóng vai **Bình**, mở Báo cáo Q3 → **Thử ghi trái phép** | Cloud trả 403 |
| E | **Góc nhìn Cloud** → **Sửa 1 bit** một phiên bản | App báo "Bản mã bị sửa đổi", chữ ký ✖ |
| F | **Quản trị** → cấp `proj_alpha` cho **Bình** | Bình đọc được ngay Đặc tả Alpha (tài liệu cũ), không cần mã hóa lại |
| G | Đóng vai **Bình**, rồi **Chi** → Đề xuất ngân sách (cần `dept_finance and role_manager`) | Cả hai đều 🔒. Gộp hai người cũng không có một khóa thỏa chính sách |
| H | Sau bước C, đóng vai **Bình** → ô **Khóa** chọn epoch cũ | Vẫn 🔒: bản mã CP-ABE trên cloud đã chuyển sang version mới |
| I | Đóng vai **Dũng** (`role_staff`) → sửa Đề xuất ngân sách | Ghi được nhưng không đọc được ("ghi mà không đọc") |
| J | Thu hồi ở chế độ **Eager** → Góc nhìn Cloud | Mọi phiên bản chuyển sang Policy Key thế hệ mới, thế hệ cũ "đã hủy" |
| K | Stack bật C7 → đóng vai **Bình** đọc Báo cáo Q3 → **Quản trị** → chế độ **Hai pha + re-key** → thu hồi `dept_finance` của Bình → đóng vai **Bình** | Thu hồi trả lời ngay; nhật ký có "Pha 2: mã hóa lại nội dung…"; Bình thấy "Cloud không trả bản mã…" |
