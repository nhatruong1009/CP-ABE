# Kế hoạch cải thiện đồ án — 1 tuần, tập trung 3 trục

> **Phiên bản 3 (2026-10-10).** Phạm vi thu gọn còn **(1) CP-ABE · (2) Thao tác trên dữ liệu mã hóa · (3) Thu hồi khóa.**
> Đã bỏ: hậu lượng tử, break-glass, audit log, giả danh thuộc tính, manifest/Merkle, multi-authority, searchable encryption, blockchain. Các mục này chuyển sang "Hướng phát triển".
> Sơ đồ: [`diagrams/kien-truc-va-luong-du-lieu.md`](../diagrams/kien-truc-va-luong-du-lieu.md) (xem bằng trình duyệt: file `.html` cùng tên).

---

## 1. Use case (tối giản)

Tổ chức lưu **tài liệu/bản ghi nhạy cảm** lên cloud không tin cậy. Mỗi bản ghi mang một **policy** gồm 2 loại thuộc tính:

- `Dept`: Cardiology, Finance…
- `Role`: Doctor, Nurse, Cashier…

Ví dụ policy: `(Dept:Cardiology AND Role:Doctor) OR Role:Director`

Ba nhân vật đủ để demo:

| User | Thuộc tính |
|---|---|
| Bác sĩ | `Dept:Cardiology, Role:Doctor` |
| Y tá | `Dept:Cardiology, Role:Nurse` |
| Thu ngân | `Dept:Finance, Role:Cashier` |

---

## 2. Trục 1 — CP-ABE (lõi)

| Hạng mục | Quyết định |
|---|---|
| Thư viện | **Charm-crypto** (Python) chạy trong Docker. Lược đồ `bsw07` hoặc `ac17` (FAME). Nhóm pairing BN254. *Dự phòng:* `rabe` (Rust). |
| Mô hình mã hóa | **Lai (KEM–DEM):** dữ liệu được mã hóa bằng AES-256-GCM với khóa CEK ngẫu nhiên. CEK được bọc bằng CP-ABE theo policy. |
| Bọc kép CEK | CEK còn được bọc thêm bằng **KEK của tổ chức** (giữ trong vùng tin cậy). Nhờ đó, khi đổi policy hoặc thu hồi, chỉ cần **bọc lại CEK** mà không phải giải mã CP-ABE. |
| Threat model | Cloud là *honest-but-curious*. KGC và KEK được tin cậy. Chống thông đồng (collusion) là **tính chất được bảo đảm**, không phải ngoài phạm vi. |
| Giới hạn ghi nhận | Không bảo vệ toàn vẹn (MPK công khai nên ai cũng tạo được bản ghi hợp lệ). KGC giữ khóa vạn năng (escrow). Cloud vẫn thấy mẫu truy cập. BN254 chỉ còn khoảng 100-bit an toàn. |

Cấu trúc một bản ghi trên cloud:

```
EncryptedRecord {
  record_id, version, policy, policy_version
  abe_header = CPABE.Encrypt(MPK, CEK, policy)   // cho user
  kek_header = Wrap(KEK, CEK)                    // cho hệ thống: re-wrap / đổi policy
  nonce, ciphertext = AES-GCM(CEK, data, AAD = record_id || version)
}
```

---

## 3. Trục 2 — Thao tác trên dữ liệu mã hóa

| Thao tác | Ai thực hiện | Cách làm | Chi phí chính |
|---|---|---|---|
| **Create** | Data Owner | Sinh CEK, mã hóa dữ liệu, `CPABE.Encrypt(CEK, policy)`, `Wrap(KEK, CEK)`, tải lên | 1 lần CP-ABE Encrypt |
| **Read** | User | Tải bản ghi, `CPABE.Decrypt(SK, abe_header)` lấy CEK, giải mã AES-GCM | 1 lần CP-ABE Decrypt |
| **Update nội dung** | Data Owner | **Sinh CEK mới** (không tái sử dụng CEK/nonce), mã hóa lại dữ liệu, bọc lại cả hai header, `version+1` | 1 lần CP-ABE Encrypt |
| **Đổi policy** | Data Owner | `Unwrap(KEK)` lấy CEK, `CPABE.Encrypt(CEK, policy mới)`. **Dữ liệu giữ nguyên**, `policy_version+1` | Chỉ bọc lại header (vài trăm byte) |
| **Delete** | Data Owner | Xóa bản ghi trên cloud và hủy `kek_header` | Không đáng kể |

> Ghi chú khi **thu hẹp** policy: user cũ có thể đã lưu CEK trong cache. Nếu cần chặn hoàn toàn thì phải dùng **Update** (CEK mới) thay cho Đổi policy.

---

## 4. Trục 3 — Thu hồi khóa (trọng tâm, trả lời RQ2)

### 4.1 Hai cơ chế được hiện thực

| | **R1. Epoch toàn cục** (time-bound keys) | **R2. Attribute versioning** |
|---|---|---|
| Ý tưởng | Mọi policy được ghép thêm `AND Epoch:e`, mọi SK đều chứa `Epoch:e` | Mỗi thuộc tính có phiên bản: `Dept:Cardiology@v2` |
| Khi nào dùng | **Thu hồi một user** (nghỉ việc) | **Thu hồi một thuộc tính** của user (chuyển khoa, đổi vai trò) |
| Khi thu hồi | `e → e+1`. Cấp lại SK cho **mọi user còn hợp lệ**. Bọc lại header của **mọi bản ghi** | Tăng version của **đúng thuộc tính đó**. Chỉ cấp lại SK cho **user có thuộc tính đó**. Chỉ bọc lại header của **bản ghi có thuộc tính đó trong policy** |
| Chi phí | O(số user + số bản ghi) | O(số user có thuộc tính + số bản ghi liên quan) |
| Ưu điểm | Đơn giản. Khóa tự hết hạn theo kỳ, kể cả khi quên thu hồi | Rẻ hơn nhiều khi chỉ một thuộc tính bị ảnh hưởng |

**Lớp vận hành đi kèm** (cả hai cơ chế): App Server **chặn ngay** user bị thu hồi bằng revocation list. Lớp mật mã bảo đảm an toàn ngay cả khi lớp vận hành bị vượt qua.

### 4.2 Ba mức xử lý dữ liệu sau thu hồi (để so sánh)

| Mức | Làm gì | Chặn được user đã cache CEK cũ? | Chi phí |
|---|---|---|---|
| **L0** Re-encrypt toàn bộ (baseline) | CEK mới + mã hóa lại dữ liệu ngay | ✅ | Cao nhất |
| **L1** Chỉ bọc lại header | Giữ CEK, chỉ thay `abe_header` | ❌ (CEK cũ vẫn mở được ciphertext cũ nếu lấy được) | Thấp nhất |
| **L2** Bọc lại header + **lazy re-encryption** | Như L1, sau đó thay CEK ở lần **Update** kế tiếp hoặc bằng job chạy nền | ✅ sau khi job hoàn tất | Trung bình, chia ra theo thời gian |

### 4.3 Thí nghiệm
- **Biến thay đổi:** số bản ghi (100 / 1.000 / 10.000), số user (10 / 100), kích thước bản ghi (1 KB / 1 MB), số thuộc tính trong policy (2 / 5 / 10).
- **Chỉ số đo:**
  - Thời gian thu hồi theo từng tổ hợp {R1, R2} × {L0, L1, L2}.
  - **Cửa sổ thu hồi**: thời gian từ lúc yêu cầu thu hồi đến lúc SK cũ không mở được bản ghi nào nữa.
  - Số SK phải cấp lại và số header phải bọc lại.
  - Thời gian Encrypt/Decrypt và kích thước ciphertext theo số thuộc tính.

---

## 5. Kịch bản kiểm chứng (tiêu chí nghiệm thu)

| KB | Tình huống | Kỳ vọng |
|---|---|---|
| A | DBA của cloud đọc DB | Chỉ thấy ciphertext |
| B | Y tá đọc bản ghi chỉ dành cho bác sĩ | Decrypt thất bại |
| F | Y tá + thu ngân ghép khóa | Thất bại (collusion resistance) |
| U | Update rồi đọc lại | Đọc được nội dung mới. CEK cũ không mở được nội dung mới |
| P | Đổi policy (thêm Y tá, rồi bỏ Y tá) | Y tá đọc được, rồi không đọc được (khi kết hợp với Update) |
| D | Delete | Không còn bản ghi để đọc |
| C1 | User nghỉ việc (R1) | SK cũ thất bại trên mọi bản ghi sau rollover. User khác vẫn đọc bình thường |
| C2 | Y tá chuyển từ Cardiology sang Finance (R2) | Mất quyền với bản ghi Cardiology, có quyền với bản ghi Finance. Bản ghi không liên quan không bị bọc lại |
| C3 | User bị thu hồi đã cache CEK | L1: vẫn đọc được bản cũ (lỗ hổng được ghi nhận). L0/L2: thất bại |

---

## 6. RQ sửa lại

- **RQ1**: Ma trận quyền "vai trò × loại bản ghi" có ánh xạ đúng sang policy CP-ABE không? Kiểm tra tự động mọi ô của ma trận.
- **RQ2**: Với R1/R2 × L0/L1/L2, chi phí và cửa sổ thu hồi bao nhiêu so với baseline mã hóa lại toàn bộ?
- **RQ3**: Chi phí Encrypt/Decrypt và kích thước ciphertext tăng thế nào theo số thuộc tính và kích thước dữ liệu?

---

## 7. Kế hoạch 7 ngày (4 người + AI)

| Ngày | Việc | Đầu ra kiểm được |
|---|---|---|
| 1 | Dựng Charm trong Docker. Viết `abe_core` (Setup/KeyGen/Encrypt/Decrypt) và `hybrid` (AES-GCM + bọc CEK kép) | KB A, B, F pass |
| 2 | App Server (FastAPI) + Storage (PostgreSQL) + Client CLI: **Create/Read** | Demo 3 user đọc đúng quyền |
| 3 | **Update / Đổi policy / Delete** | KB U, P, D pass |
| 4 | **R1 Epoch**: revocation list, epoch rollover, cấp lại SK, job bọc lại header (L1) | KB C1 pass |
| 5 | **R2 Attribute versioning** + **L0/L2** (lazy re-encryption job) | KB C2, C3 pass |
| 6 | Benchmark RQ2, RQ3 + gom toàn bộ KB vào `pytest` | Bảng và biểu đồ |
| 7 | Báo cáo, slide, video demo | Nộp bài |

> Code crypto do AI sinh ra cần người review và **test âm**: không được tái sử dụng nonce GCM, CEK phải được sinh mới khi Update, ciphertext bị sửa thì giải mã phải thất bại.

## 8. Đưa sang "Hướng phát triển" trong báo cáo
- Toàn vẹn dữ liệu: chữ ký của Data Owner, manifest/Merkle root (Dang & Son 2006, Nguyen & Dang 2008).
- Audit log và break-glass.
- Ẩn policy (policy-hiding).
- Multi-authority / registered ABE để bỏ key escrow.
- Searchable encryption.
- Hậu lượng tử.
