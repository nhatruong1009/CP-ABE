# Kho tài liệu CP-ABE: PoC cho Outsourced Storage

```
CP_ABE_1/
├── code/        # mã nguồn Go + Dockerfile + docker-compose.yml
├── docs/        # thiết kế, sổ nguồn tham khảo
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
| http://localhost:8080 | **app**: Web UI (vùng tin cậy) |
| http://localhost:8090 | **Adminer**: góc nhìn DBA của cloud (System: PostgreSQL, server `cloud-db`, user/pass/db `cloud`) |

Dừng: `docker compose down`. Xóa sạch dữ liệu (Master Key, khóa, DB) để chạy lại từ đầu: `docker compose down -v`.

## Thành phần

| Container | Vùng | Vai trò |
|---|---|---|
| `authority` | Tin cậy | Key Authority: Master Key, thuộc tính có version, chính sách, Policy Key theo thế hệ, cấp/thu hồi |
| `app` | Tin cậy | Web UI. Mã hóa/giải mã/ký tại chỗ. `keystore` mô phỏng thiết bị của user |
| `cloud-api` | Cloud | Lưu bản mã, kiểm chữ ký ghi. **Không có khóa bí mật** và không gọi được `authority` |
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
