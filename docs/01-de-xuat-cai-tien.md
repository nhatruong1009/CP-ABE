# Đề xuất cải tiến mô hình CP-ABE cho Outsourced Storage

> Nhóm 06 · An toàn và bảo mật trong HTTT · HP3-K35
> Tài liệu này rà soát đề xuất hiện tại ([ref/proposal.pdf](../ref/proposal.pdf)), chọn các cải tiến **áp dụng được ngay**, và mô tả thiết kế chi tiết để triển khai trên Docker.
> Định hướng: **ứng dụng**, không chứng minh toán học, không đưa công thức thuật toán.

---

## 0. Tóm tắt nhanh (dùng cho slide "Điểm mới")

| # | Hạn chế trong đề xuất hiện tại | Cải tiến | Nguồn / tính mới |
|---|---|---|---|
| C1 | Dùng lược đồ gốc BSW07 (2007), chỉ AND/OR, chỉ an toàn CPA | Dùng lược đồ **TKN20** qua thư viện **Cloudflare CIRCL**: hỗ trợ AND/OR/NOT, an toàn CCA, đã được chạy thực tế | TKN20 (PKC 2020); triển khai thực tế ở Cloudflare Geo Key Manager v2 (2023) |
| C2 | Mỗi bản ghi tự gói khóa bằng CP-ABE, nên thu hồi một thuộc tính kéo theo mã hóa lại toàn bộ dữ liệu (chi phí "Cao" ở slide 5) | **Phân cấp khóa 3 tầng** (Policy Key): CP-ABE chỉ bảo vệ một khóa cho mỗi chính sách, không cho mỗi tài liệu | Kiến trúc Cloudflare Geo Key Manager v2 / Portunus (2023) |
| C3 | Chỉ có quyền **đọc**. Ai có MPK cũng ghi đè được, Integrity nằm ngoài phạm vi | **Tách quyền Đọc và Ghi**: mỗi tài liệu có thêm *write policy*, bản cập nhật phải được ký bằng khóa ký mà chỉ người thỏa write policy mới mở được. Cloud kiểm chữ ký trước khi nhận | Mở rộng mẫu Policy Key của C2 cho chữ ký số (ý tưởng tách đọc/ghi: Zhao et al. 2011) |
| C4 | Thu hồi mới dừng ở mức liệt kê 3 kỹ thuật | **Thu hồi/cấp thuộc tính theo phiên bản** + **mã hóa lại lười (lazy) khi chỉnh sửa**. Chi phí thu hồi tỉ lệ với *số chính sách liên quan*, không tỉ lệ với *số tài liệu* | Kết hợp C1 + C2 |
| C5 | Policy lưu dạng rõ trên cloud, lộ thông tin nghiệp vụ (vd. tên dự án mật) | (Tùy chọn) **Ẩn tên thuộc tính** bằng bí danh, cloud chỉ thấy mã vô nghĩa | Kỹ thuật "partially hidden policy" ở mức đơn giản |
| C6 | Use case bệnh viện, một người ghi | Use case **doanh nghiệp**, **nhiều người ghi, nhiều người đọc**, chỉnh sửa có phiên bản | — |

**Sửa một chỗ trong slide 7:** *Collusion* (nhiều user gộp khóa để giải mã) **không phải "ngoài phạm vi"**. Chống collusion là tính chất có sẵn của mọi lược đồ CP-ABE chuẩn: khóa của mỗi user được "trộn" ngẫu nhiên riêng nên không ghép được với nhau. Nên chuyển mục này sang "Được bảo vệ" và thêm một kịch bản demo (xem §7).

---

## 1. Rà soát đề xuất hiện tại

| Hạng mục trong slide | Nhận xét | Hướng xử lý |
|---|---|---|
| Kiến trúc hybrid (CEK + CP-ABE) – slide 10 | Đúng hướng | Giữ, mở rộng thành 3 tầng (C2) |
| BSW07 | Cũ (2007), chỉ an toàn CPA, ít thư viện còn bảo trì cho Python mới (Charm-crypto rất khó cài trên Python ≥ 3.10) | Thay bằng TKN20/CIRCL (C1) |
| Một Master Key, một KGC | Chấp nhận được cho đồ án | Giữ. Multi-authority để ở "hướng phát triển" |
| Thu hồi (slide 13) | Mới liệt kê, chưa chọn và chưa có luồng cụ thể | Chọn Versioning + Lazy re-encryption trên nền Policy Key (C4) |
| Integrity ngoài phạm vi | Với mô hình *nhiều người ghi*, đây là lỗ hổng lớn: bất kỳ ai cũng có thể mã hóa rồi ghi đè | Thêm quyền Ghi bằng chữ ký (C3) |
| "Chi phí thu hồi quyền: Cao" | Đúng với CP-ABE thuần | Sau C2 + C4 giảm còn "Trung bình/Thấp", nêu trong slide so sánh |
| Kịch bản C "Thu hồi trễ: cần đánh giá" | Chưa có đáp án | Có đáp án cụ thể sau C4 (xem §7) |

---

## 2. Bối cảnh doanh nghiệp (use case mới)

**Công ty ABC** thuê cloud để lưu **Kho tài liệu nội bộ** (báo cáo tài chính, bảng lương, tài liệu dự án). Nhà cung cấp cloud là bên *honest-but-curious*: làm đúng giao thức nhưng có thể tò mò đọc dữ liệu.

### 2.1 Thuộc tính

Thuộc tính có dạng `tên: phiên_bản`. Người dùng chỉ thấy *tên*; *phiên bản* do hệ thống tự quản lý (xem C4).

| Nhóm | Thuộc tính |
|---|---|
| Phòng ban | `dept_hr`, `dept_finance`, `dept_sales`, `dept_eng` |
| Vai trò | `role_staff`, `role_manager`, `role_director` |
| Dự án | `proj_alpha`, `proj_beta` |

### 2.2 Người dùng mẫu

| User | Thuộc tính |
|---|---|
| An | `dept_finance`, `role_manager` |
| Bình | `dept_finance`, `role_staff` |
| Chi | `dept_hr`, `role_manager` |
| Dũng | `dept_eng`, `role_staff`, `proj_alpha` |
| Hà (Giám đốc) | `role_director` |

### 2.3 Tài liệu mẫu: mỗi tài liệu có 2 chính sách

| Tài liệu | Read policy (ai được ĐỌC) | Write policy (ai được SỬA) |
|---|---|---|
| Bảng lương T10 | `(dept_hr and role_manager) or role_director` | `dept_hr and role_manager` |
| Báo cáo tài chính Q3 | `dept_finance or role_director` | `dept_finance and role_manager` |
| Đặc tả dự án Alpha | `proj_alpha or role_director` | `proj_alpha` |
| Đề xuất ngân sách (nộp lên tài chính) | `dept_finance and role_manager` | `role_staff or role_manager` |

Dòng cuối cho thấy **ghi mà không đọc được**: nhân viên nộp đề xuất nhưng không đọc được đề xuất của người khác. Thiết kế C2 hỗ trợ trường hợp này (xem §4.2).

### 2.4 Use case cần hỗ trợ

| UC | Mô tả | Ai thực hiện |
|---|---|---|
| UC1 – Viết | Tạo tài liệu mới, chọn read/write policy | User thỏa write policy |
| UC2 – Đọc | Xem nội dung tài liệu | User thỏa read policy |
| UC3 – Sửa | Tạo phiên bản mới của tài liệu | User thỏa write policy |
| UC4 – Cấp thêm thuộc tính | Bình được thêm `proj_alpha` | Quản trị (Key Authority) |
| UC5 – Thu hồi thuộc tính | Bình chuyển phòng, mất `dept_finance` (tài khoản vẫn còn) | Quản trị (Key Authority) |

Không xử lý: thu hồi *tài khoản*, đăng nhập/xác thực. UI chỉ có ô chọn "Đang đóng vai: An/Bình/…" để tập trung vào **authorization**.

---

## 3. Mô hình cấu trúc tổng thể

### 3.1 Sơ đồ thành phần & vùng tin cậy

```mermaid
flowchart LR
  subgraph TRUSTED["VÙNG TIN CẬY - nội bộ Công ty ABC (docker network: trusted_net)"]
    UI["Trình duyệt<br/>Web UI"]
    APP["app<br/>Client App + Web UI<br/>Encrypt / Decrypt / Ký"]
    KS[("keystore<br/>khóa ABE của từng user")]
    KA["authority<br/>Key Authority<br/>Setup · KeyGen · Policy Registry · Thu hồi"]
    KADB[("authority-db (SQLite)<br/>MSK · users · thuộc tính+version<br/>khóa riêng của Policy")]
  end
  subgraph UNTRUSTED["VÙNG KHÔNG TIN CẬY - Cloud (docker network: cloud_net)"]
    API["cloud-api<br/>Storage Gateway<br/>KHÔNG giữ khóa<br/>chỉ kiểm chữ ký ghi"]
    DB[("cloud-db (PostgreSQL)<br/>ciphertext · policy key đã mã hóa<br/>public key")]
    ADM["cloud-admin (Adminer)<br/>góc nhìn của DBA cloud"]
  end
  UI --> APP
  APP --- KS
  APP -- "xin/cập nhật khóa ABE" --> KA
  KA --- KADB
  APP -- "đọc/ghi ciphertext" --> API
  KA -- "đăng Policy Key đã mã hóa" --> API
  API --- DB
  ADM --- DB
```

**Nguyên tắc ranh giới:** `cloud-api` và `cloud-db` chỉ nằm trong `cloud_net`, nên **không gọi được** `authority`. `app` và `authority` nằm ở cả hai mạng. Docker network thể hiện trực tiếp ranh giới tin cậy của slide 11.

### 3.2 Vai trò từng container

| Container | Vùng | Giữ gì | Làm gì | Công nghệ gợi ý |
|---|---|---|---|---|
| `authority` | Tin cậy | Master Secret Key, danh sách thuộc tính + version, gán thuộc tính cho user, khóa riêng của các Policy Key | Setup, KeyGen, đăng ký policy, cấp/thu hồi thuộc tính, mã hóa lại (eager) | Go + CIRCL, SQLite |
| `app` | Tin cậy | Khóa ABE của user (mô phỏng "thiết bị của user") | Web UI. Mã hóa/giải mã/ký **tại chỗ**. Không bao giờ gửi plaintext ra cloud | Go + CIRCL, HTML template |
| `cloud-api` | Không tin cậy | Không giữ khóa bí mật nào | REST lưu/trả ciphertext, **kiểm chữ ký trước khi nhận bản ghi**, kiểm số phiên bản | Go (chỉ cần `crypto/ed25519`) |
| `cloud-db` | Không tin cậy | Ciphertext, Policy Key đã mã hóa, public key | Lưu trữ | PostgreSQL 16 |
| `cloud-admin` | Không tin cậy | — | Cho xem DB như một DBA tò mò (kịch bản A) | Adminer |

> **Vì sao chọn Go cho cả 3 service?** CIRCL là thư viện Go, cài bằng một lệnh `go get`, không cần biên dịch PBC/GMP như Charm-crypto. Dùng một ngôn ngữ thì cả nhóm đọc được code của nhau.
> **Phương án dự phòng:** Python + Charm-crypto (lược đồ BSW07/Waters11) chạy trên image `python:3.9`. Phần kiến trúc C2–C5 giữ nguyên, chỉ thay lớp mã hóa ABE.

---

## 4. Chi tiết các cải tiến

### C1. Lược đồ TKN20 qua thư viện CIRCL

- **Là gì:** Lược đồ CP-ABE của Tomida–Kawahara–Nishimaki (PKC 2020), được Cloudflare cài đặt trong thư viện mã nguồn mở **CIRCL** (gói `abe/cpabe/tkn20`, vẫn được cập nhật đến 2026) và dùng thật cho **Geo Key Manager v2** (2023). Đây là hệ thống kiểm soát truy cập bằng ABE quy mô lớn đầu tiên được công bố.
- **Khác BSW07:**
  - Chính sách viết dạng chữ, có `and`, `or`, `not`, ví dụ `(dept_finance: v3) or (role_director: v1)`.
  - Phiên bản an toàn CCA (chống sửa ciphertext để dò). BSW07 gốc chỉ an toàn CPA.
  - Thuộc tính có dạng *tên: giá trị*, rất hợp để gắn phiên bản (C4).
- **API cần dùng (5 hàm):**

  | Việc | Hàm CIRCL |
  |---|---|
  | Khởi tạo hệ thống | `tkn20.Setup` → `PublicKey`, `SystemSecretKey` |
  | Cấp khóa user | `msk.KeyGen(attrs)` với `attrs.FromMap({"dept_finance":"v3", ...})` |
  | Mã hóa | `pk.Encrypt(policy, msg)` với `policy.FromString("...")` |
  | Giải mã | `userKey.Decrypt(ct)` |
  | Kiểm tra trước, không cần giải mã | `attrs.CouldDecrypt(ct)`: UI dùng để hiện 🔒/🔓 |

- **Lưu ý:** Tên thuộc tính chỉ gồm chữ, số và `_`. **Không dùng `not` trong đồ án**, vì khi kết hợp với cơ chế phiên bản, `not` cho kết quả khó lường (user bị thu hồi có thể "thỏa" `not`).
- **Chuẩn hóa:** ABE cho kiểm soát truy cập đã có chuẩn ETSI **TS 103 532 V1.2.1 (05/2021)**, dùng làm căn cứ trong slide rằng hướng này là chuẩn công nghiệp chứ không chỉ học thuật.

### C2. Phân cấp khóa 3 tầng (Policy Key)

**Vấn đề:** Ở thiết kế hiện tại, *mỗi tài liệu* có CEK được bọc bằng CP-ABE. Có 10.000 tài liệu thì có 10.000 bản mã CP-ABE. Thu hồi một thuộc tính thì phải xử lý lại tất cả.

**Giải pháp (theo Cloudflare Geo Key Manager v2):** chèn thêm một tầng ở giữa.

```mermaid
flowchart TB
  subgraph T1["Tầng 1 - CP-ABE (chậm, ít)"]
    P["Khóa riêng của Policy 'Finance-Read' (thế hệ 2)<br/>được mã hóa CP-ABE theo<br/>(dept_finance: v3) or (role_director: v1)"]
  end
  subgraph T2["Tầng 2 - Policy Key (1 cặp khóa cho mỗi chính sách)"]
    PK["Policy Key 'Finance-Read' gen 2<br/>public key: công khai trên cloud<br/>private key: chỉ mở được qua Tầng 1"]
  end
  subgraph T3["Tầng 3 - DEK (nhanh, nhiều: mỗi phiên bản tài liệu 1 khóa)"]
    D1["DEK tài liệu #1 v1<br/>bọc bằng public key Policy"]
    D2["DEK tài liệu #7 v3"]
    D3["DEK tài liệu #42 v1"]
  end
  P --> PK
  PK --> D1 & D2 & D3
  D1 --> C1["Nội dung #1<br/>AES-256-GCM"]
  D2 --> C2["Nội dung #7"]
  D3 --> C3["Nội dung #42"]
```

| Tầng | Khóa | Số lượng | Mã hóa bằng | Lưu ở |
|---|---|---|---|---|
| 1 | Khóa ABE của user | 1 / user | — | `app` keystore |
| 2 | Policy Key (cặp X25519) | 1 / (chính sách × thế hệ) | Private key được mã hóa **CP-ABE** theo chính sách | cloud-db (`policy_keys`) |
| 3 | DEK (AES-256) | 1 / phiên bản tài liệu | **Public key** của Policy Key (sealed box) | cloud-db (`document_versions`) |
| — | Nội dung | — | DEK, AES-256-GCM | cloud-db |

**Lợi ích:**

1. **Thu hồi rẻ:** chỉ cần xử lý lại *Tầng 1* của các chính sách có chứa thuộc tính bị thu hồi. Một công ty có hàng nghìn tài liệu nhưng thường chỉ vài chục chính sách.
2. **Ghi mà không cần đọc:** Policy Key là cặp khóa bất đối xứng. Ai cũng bọc được DEK bằng *public key*, nhưng chỉ người thỏa chính sách mới mở được *private key*. Đây là trường hợp "Đề xuất ngân sách" ở §2.3.
3. **Nhanh hơn:** Giải mã CP-ABE (bước chậm) chỉ chạy **một lần cho mỗi chính sách**, sau đó `app` giữ private key của Policy trong bộ nhớ phiên. Đọc 100 tài liệu cùng chính sách thì chỉ tốn 1 lần giải mã CP-ABE.
4. AES-GCM cho Tầng 3 phát hiện được nếu ciphertext bị sửa.

**Thư viện:** X25519 sealed box có sẵn trong `golang.org/x/crypto/nacl/box` (`SealAnonymous` / `OpenAnonymous`). AES-GCM có sẵn trong `crypto/aes` + `crypto/cipher`.

### C3. Tách quyền Đọc / Ghi (multi-writer an toàn)

**Vấn đề:** Trong CP-ABE, ai có Public Key cũng *mã hóa* được. Không có lớp kiểm soát nào thì nhân viên bất kỳ (hoặc chính cloud) có thể ghi đè "Báo cáo tài chính Q3" bằng nội dung giả.

**Giải pháp:** áp dụng lại đúng mẫu Policy Key cho **chữ ký số**.

- Mỗi *write policy* có một **Write Key** = cặp khóa chữ ký **Ed25519**.
  - *Public key* để công khai trên cloud.
  - *Private key* được mã hóa CP-ABE theo write policy.
- Muốn tạo/sửa tài liệu, `app` mở private Write Key (chỉ được nếu user thỏa write policy), rồi **ký** lên gói: `doc_id + số phiên bản + hash(ciphertext) + read_policy_id + write_policy_id`.
- `cloud-api` **kiểm chữ ký** bằng public key (không cần khóa bí mật nào) và kiểm *số phiên bản = phiên bản cuối + 1*. Sai thì từ chối (HTTP 403/409).
- Khi đọc, `app` cũng kiểm chữ ký. Nếu cloud tự ý sửa dữ liệu thì người đọc phát hiện được.

**Kết quả:** Integrity (một phần) đi vào phạm vi đồ án, và mô hình *nhiều người ghi* có kiểm soát thật sự, không dựa vào việc tin cloud.

| Ai | Có thể | Không thể |
|---|---|---|
| Người thỏa write policy | Tạo phiên bản mới hợp lệ | — |
| Người chỉ thỏa read policy | Đọc, kiểm chữ ký | Tạo chữ ký hợp lệ → cloud từ chối |
| Cloud (tò mò) | Thấy ciphertext, public key | Đọc nội dung. Nếu tự sửa thì bị người đọc phát hiện |

> **Tùy chọn mở rộng (audit):** ký thêm bằng khóa cá nhân của user để biết *ai* đã sửa. Write Key chỉ chứng minh "người sửa có quyền", không cho biết là ai.

### C4. Cấp / thu hồi **thuộc tính** theo phiên bản + mã hóa lại lười

#### Ý tưởng

- Mỗi thuộc tính có **phiên bản hiện hành**, ví dụ `dept_finance` đang ở `v3`.
- User nhập chính sách *logic* như `dept_finance or role_director`. `authority` **biên dịch** thành chính sách thật: `(dept_finance: v3) or (role_director: v1)`.
- Khóa ABE của user chứa thuộc tính kèm phiên bản: `{dept_finance: v3, role_manager: v1}`.
- Thu hồi thuộc tính = tăng phiên bản, cấp lại khóa cho người còn giữ thuộc tính, và mã hóa lại *Tầng 1* (ít). Không đụng đến hàng nghìn tài liệu.

#### UC4 – Cấp thêm thuộc tính (Bình được thêm `proj_alpha`)

1. Quản trị chọn Bình và thêm `proj_alpha` trên trang Admin của `authority`.
2. `authority` ghi vào `user_attributes`, rồi chạy **KeyGen mới** cho Bình với *toàn bộ* thuộc tính ở phiên bản hiện hành.
3. `app` đồng bộ khóa mới vào keystore (khóa có số `key_epoch` tăng dần, `app` so sánh trước mỗi thao tác).
4. **Kết quả:** Bình đọc được **ngay cả các tài liệu Alpha cũ**, vì Tầng 1 luôn mã hóa theo phiên bản hiện hành. Không cần mã hóa lại gì cả.

Chi phí: 1 lần KeyGen.

#### UC5 – Thu hồi thuộc tính (Bình mất `dept_finance`, `v3` lên `v4`)

```mermaid
sequenceDiagram
  autonumber
  actor Admin as Quản trị
  participant KA as authority
  participant Cloud as cloud-api / cloud-db
  participant App as app (các user)
  Admin->>KA: Thu hồi dept_finance của Bình
  KA->>KA: Xóa dept_finance khỏi Bình<br/>Tăng version dept_finance: v3 → v4
  KA->>KA: KeyGen lại cho Bình (không còn dept_finance)<br/>và cho mọi user còn dept_finance (An...) với v4
  loop Mỗi chính sách có chứa dept_finance (đọc & ghi)
    KA->>KA: Biên dịch lại chính sách với v4
    KA->>KA: Tạo Policy Key / Write Key THẾ HỆ MỚI
    KA->>Cloud: Đăng thế hệ mới (public key + private key mã hóa CP-ABE theo v4)
    KA->>Cloud: Mã hóa lại các thế hệ CŨ theo v4, xóa bản cũ mã theo v3
    KA->>Cloud: Đánh dấu thế hệ mới là "hiện hành"
  end
  App->>KA: Đồng bộ khóa (key_epoch mới)
  Note over Cloud: cloud-api từ chối mọi chữ ký ghi bằng Write Key thế hệ cũ
```

**Sau thu hồi:**

| Câu hỏi | Trả lời |
|---|---|
| Bình còn đọc được tài liệu Finance **mới hoặc vừa sửa** không? | **Không.** DEK mới được bọc bằng Policy Key thế hệ mới, mà thế hệ mới chỉ mở được bằng `dept_finance: v4` |
| Bình còn **sửa** được tài liệu Finance không? | **Không, có hiệu lực ngay.** `cloud-api` chỉ nhận chữ ký của Write Key thế hệ hiện hành |
| Khóa cũ của Bình (`v3`) còn mở được gì trên cloud? | Không. Mọi bản mã CP-ABE theo `v3` đã được thay bằng `v4` |
| Nếu trước đây Bình đã *lưu lén* private Policy Key cũ? | Bình vẫn mở được **các phiên bản cũ** (vốn đã được phép đọc trước đó). Đây là giới hạn chung của mọi hệ thống mã hóa, xử lý bằng chế độ Eager bên dưới |
| An (vẫn còn `dept_finance`) có bị ảnh hưởng? | Chỉ cần đồng bộ khóa mới, đọc/ghi bình thường |

**Hai chế độ xử lý tài liệu cũ** (cấu hình được, demo được cả hai):

| Chế độ | Làm gì | Ưu | Nhược |
|---|---|---|---|
| **Lazy** (mặc định) | Không đụng tài liệu cũ. Lần **sửa** tiếp theo tự sinh DEK mới và bọc bằng thế hệ mới | Thu hồi tức thì, gần như không tốn chi phí | Phiên bản cũ vẫn bọc bằng thế hệ cũ |
| **Eager** | `authority` chạy job nền: với mỗi tài liệu thuộc chính sách bị ảnh hưởng, giải mã → DEK mới → mã hóa lại → đăng bản mới | Đóng hẳn rủi ro "lưu lén khóa cũ" | Tốn chi phí, tỉ lệ với số tài liệu |

**So sánh chi phí thu hồi** (trả lời RQ2):

| Thao tác khi thu hồi 1 thuộc tính | Thiết kế cũ (mỗi tài liệu 1 bản mã CP-ABE) | Thiết kế mới (C2 + C4, Lazy) |
|---|---|---|
| Mã hóa CP-ABE lại | = số **tài liệu** có chứa thuộc tính | = số **chính sách** có chứa thuộc tính × số thế hệ |
| Mã hóa lại nội dung | Có (để chặn khóa cũ) | Không (Lazy) / tùy chọn (Eager) |
| Cấp lại khóa user | = số user giữ thuộc tính | = số user giữ thuộc tính |
| Thu hồi quyền ghi | Không có cơ chế | Có hiệu lực ngay |

> **Trust note:** Ở chế độ Eager, `authority` giải mã được dữ liệu. Điều này **không thêm giả định tin cậy mới**, vì `authority` giữ Master Key nên vốn đã có thể tự sinh khóa bất kỳ (slide 7 đã giả định Key Authority trung thực).

### C5. (Tùy chọn) Ẩn tên thuộc tính trong chính sách

- **Vấn đề:** Chính sách nằm dạng rõ trong ciphertext. DBA cloud nhìn thấy `proj_alpha` là biết có một dự án tên Alpha và ai liên quan.
- **Giải pháp đơn giản:** `authority` đổi mỗi tên thuộc tính thành bí danh ngẫu nhiên (`proj_alpha` → `a_7f3k9q`). Bảng tra cứu chỉ nằm trong vùng tin cậy, cloud chỉ thấy `(a_7f3k9q: v2) or (a_x81mzd: v1)`.
- **Giới hạn:** Cloud vẫn thấy *cấu trúc* (bao nhiêu thuộc tính, AND hay OR) và đếm được tần suất. Che giấu hoàn toàn (fully hidden policy) cần lược đồ khác, nằm ngoài phạm vi đồ án.

---

## 5. Luồng xử lý chi tiết

### 5.0 Khởi tạo hệ thống (một lần)

1. `authority` khởi động lần đầu, chạy `Setup`, lưu MSK vào volume `authority-data` và đăng Public Key lên `cloud-api`.
2. Nạp seed: 5 user, 9 thuộc tính (đều `v1`), gán thuộc tính như §2.2.
3. KeyGen cho từng user, rồi `app` tải về keystore.

### 5.1 UC1 – Viết tài liệu mới

```mermaid
sequenceDiagram
  autonumber
  actor U as An (UI)
  participant App as app
  participant KA as authority
  participant Cloud as cloud-api
  U->>App: Tạo "Báo cáo Q3", chọn Read = "dept_finance or role_director",<br/>Write = "dept_finance and role_manager"
  App->>KA: Lấy/đăng ký policy (nếu chưa có)
  KA-->>Cloud: (lần đầu) đăng Policy Key + Write Key thế hệ 1
  App->>Cloud: Tải Policy Key (public) + Write Key (bản mã CP-ABE)
  App->>App: Mở private Write Key bằng khóa ABE của An (An thỏa write policy)
  App->>App: Sinh DEK ngẫu nhiên → AES-GCM mã hóa nội dung + tiêu đề
  App->>App: Bọc DEK bằng public Policy Key
  App->>App: Ký (doc_id, v1, hash, read_policy, write_policy)
  App->>Cloud: POST /documents (chỉ ciphertext + chữ ký)
  Cloud->>Cloud: Kiểm chữ ký bằng public Write Key (thế hệ hiện hành) → lưu
```

### 5.2 UC2 – Đọc

1. `app` tải danh sách tài liệu. Mỗi dòng gồm `read_policy_id`, thế hệ, ciphertext.
2. Với mỗi Policy Key chưa có trong bộ nhớ phiên: tải bản mã CP-ABE của private key, kiểm `CouldDecrypt`, rồi `Decrypt`.
   - Thất bại thì UI hiển thị 🔒 "Không đủ thuộc tính", **kèm chính sách cần có**. Đây là điểm sáng khi demo.
3. Mở DEK bằng private Policy Key → giải mã AES-GCM → **kiểm chữ ký** → hiển thị.

### 5.3 UC3 – Sửa (tạo phiên bản mới)

Giống UC1, khác ở các điểm:

- Luôn sinh **DEK mới** và bọc bằng Policy Key **thế hệ hiện hành**. Đây chính là bước "lazy re-encryption" tự động.
- Gửi kèm `version = phiên bản đang xem + 1`. Nếu người khác đã sửa trước, `cloud-api` trả **409 Conflict** và UI báo "Có phiên bản mới hơn, hãy tải lại" (optimistic locking).
- Các phiên bản cũ được giữ lại (append-only), UI có tab "Lịch sử".
- Tùy chọn: người có quyền ghi đổi read/write policy của tài liệu. Bản ghi đổi policy phải được ký bằng Write Key **cũ**.

### 5.4 UC4 / UC5

Xem §C4.

---

## 6. Thiết kế dữ liệu & API

### 6.1 `cloud-db` (PostgreSQL, vùng không tin cậy)

```sql
-- Public Key của hệ thống ABE
CREATE TABLE system_params (
  id            INT PRIMARY KEY DEFAULT 1,
  abe_public_key BYTEA NOT NULL
);

-- Một dòng cho mỗi chính sách (đọc hoặc ghi)
CREATE TABLE policies (
  policy_id     TEXT PRIMARY KEY,            -- vd. 'pol_finance_read'
  kind          TEXT NOT NULL CHECK (kind IN ('read','write')),
  compiled_expr TEXT NOT NULL,               -- '(dept_finance: v4) or (role_director: v1)' (hoặc bí danh nếu bật C5)
  current_gen   INT  NOT NULL
);

-- Mỗi thế hệ của Policy Key / Write Key
CREATE TABLE policy_keys (
  policy_id        TEXT REFERENCES policies,
  gen              INT,
  public_key       BYTEA NOT NULL,           -- X25519 (read) hoặc Ed25519 (write)
  abe_wrapped_priv BYTEA NOT NULL,           -- private key, mã hóa CP-ABE
  created_at       TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (policy_id, gen)
);

CREATE TABLE documents (
  doc_id          UUID PRIMARY KEY,
  latest_version  INT NOT NULL
);

CREATE TABLE document_versions (
  doc_id          UUID REFERENCES documents,
  version         INT,
  read_policy_id  TEXT NOT NULL,
  read_gen        INT  NOT NULL,
  wrapped_dek     BYTEA NOT NULL,            -- DEK bọc bằng Policy Key
  nonce           BYTEA NOT NULL,
  ciphertext      BYTEA NOT NULL,            -- {tiêu đề, nội dung} AES-GCM
  write_policy_id TEXT NOT NULL,
  write_gen       INT  NOT NULL,
  signature       BYTEA NOT NULL,            -- Ed25519
  created_at      TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (doc_id, version)
);
```

Khi mở bằng Adminer, DBA chỉ thấy BYTEA và tên chính sách. Không có tiêu đề, không có nội dung.

### 6.2 `authority-db` (SQLite, vùng tin cậy)

| Bảng | Cột chính |
|---|---|
| `master` | `msk` (Master Secret Key) |
| `users` | `user_id`, `display_name`, `key_epoch` |
| `attributes` | `name`, `current_version`, `alias` (C5), `description` |
| `user_attributes` | `user_id`, `attr_name` |
| `policy_defs` | `policy_id`, `kind`, `logical_expr` (`dept_finance or role_director`) |
| `policy_secrets` | `policy_id`, `gen`, `private_key` (phục vụ chế độ Eager) |
| `audit_log` | thời điểm, hành động (grant/revoke/keygen), đối tượng |

### 6.3 REST API

**`authority` (chỉ `app` và màn hình Admin gọi):**

| Method | Path | Mục đích |
|---|---|---|
| GET | `/users` | Danh sách user + thuộc tính (cho ô chọn vai) |
| GET | `/users/{id}/key` | Trả khóa ABE hiện hành + `key_epoch` |
| POST | `/users/{id}/attributes` `{attr}` | **UC4** cấp thuộc tính |
| DELETE | `/users/{id}/attributes/{attr}` `?mode=lazy\|eager` | **UC5** thu hồi thuộc tính |
| POST | `/policies` `{kind, logical_expr}` | Đăng ký chính sách, trả `policy_id` |
| GET | `/attributes` | Danh sách thuộc tính + version |

**`cloud-api` (không tin cậy):**

| Method | Path | Mục đích |
|---|---|---|
| GET | `/params` | Public Key hệ thống |
| GET | `/policies/{id}/keys/{gen}` | Policy Key / Write Key (bản mã CP-ABE + public) |
| PUT | `/policies/{id}` | (chỉ `authority`) đăng thế hệ mới. Kiểm bằng khóa ký của authority |
| GET | `/documents` | Danh sách (ciphertext) |
| GET | `/documents/{id}/versions[/{v}]` | Lịch sử / một phiên bản |
| POST | `/documents` | Tạo. **Kiểm chữ ký** |
| POST | `/documents/{id}/versions` | Sửa. **Kiểm chữ ký + version** |

### 6.4 Màn hình UI (`app`)

| Màn hình | Nội dung |
|---|---|
| Thanh trên cùng | Ô chọn **"Đang đóng vai: [An ▾]"** + các thẻ thuộc tính hiện tại + `key_epoch` |
| Kho tài liệu | Bảng: tiêu đề (hoặc 🔒), read policy, write policy, phiên bản, nút Xem/Sửa (bị mờ nếu không đủ quyền ghi) |
| Soạn/Sửa | Ô tiêu đề, nội dung; 2 ô chọn chính sách (dropdown template + ô tự viết) |
| Lịch sử | Các phiên bản, ✔ chữ ký hợp lệ / ✖ bị sửa |
| Admin – Thuộc tính | Ma trận user × thuộc tính, nút Cấp/Thu hồi, chọn Lazy/Eager, nhật ký |
| "Góc nhìn Cloud" | Link sang Adminer, hoặc trang hiện raw row từ `cloud-api` |

---

## 7. Kịch bản demo (thay slide 14)

| # | Kịch bản | Thao tác | Kỳ vọng |
|---|---|---|---|
| A | DBA cloud tò mò | Mở Adminer, xem `document_versions` | Chỉ thấy BYTEA, không có tiêu đề/nội dung |
| B | Vượt quyền đọc | Đóng vai Dũng, mở "Bảng lương" | 🔒 Không đủ thuộc tính, hiện chính sách cần có |
| C | Thu hồi thuộc tính | Thu hồi `dept_finance` của Bình → An sửa Báo cáo Q3 → đóng vai Bình mở lại | Bình không đọc được phiên bản mới, nút Sửa bị khóa |
| D | Ghi trái phép / giả mạo | Bình (staff) cố sửa Báo cáo Q3 (write cần manager). Dùng `curl` gửi bản ghi tự ký sai | `cloud-api` trả 403 |
| E | Cloud tự sửa dữ liệu | Dùng Adminer sửa 1 byte `ciphertext` | Khi đọc, `app` báo ✖ chữ ký/ AES-GCM không hợp lệ |
| F | Cấp thêm thuộc tính | Cấp `proj_alpha` cho Bình | Bình đọc được ngay cả tài liệu Alpha cũ |
| G | Collusion | Bình (`dept_finance`, `role_staff`) và Chi (`dept_hr`, `role_manager`) cùng thử mở "Đề xuất ngân sách" (cần `dept_finance and role_manager`) | Mỗi khóa riêng lẻ đều thất bại; hai người gộp lại cũng không có một khóa thỏa chính sách |
| H | Khóa cũ sau thu hồi | Dùng file khóa ABE cũ của Bình (đã sao lưu trước khi thu hồi) | Không mở được Policy Key thế hệ nào trên cloud |

> Với kịch bản G: CIRCL không có API "ghép khóa", nên chỉ cần minh họa là hai khóa riêng lẻ không giải mã được và ghi chú tính chất chống collusion. Không cần tự viết tấn công.

---

## 8. Docker Compose (khung)

```yaml
services:
  authority:
    build: ./authority
    volumes: [authority-data:/data]
    networks: [trusted_net, cloud_net]
    ports: ["8081:8081"]          # trang Admin
    depends_on: [cloud-api]

  app:
    build: ./app
    volumes: [keystore:/keystore]
    networks: [trusted_net, cloud_net]
    ports: ["8080:8080"]          # Web UI chính
    depends_on: [authority, cloud-api]

  cloud-api:
    build: ./cloud-api
    environment:
      DATABASE_URL: postgres://cloud:cloud@cloud-db:5432/cloud?sslmode=disable
    networks: [cloud_net]         # KHÔNG ở trusted_net → không gọi được authority
    depends_on: [cloud-db]

  cloud-db:
    image: postgres:16
    environment: { POSTGRES_USER: cloud, POSTGRES_PASSWORD: cloud, POSTGRES_DB: cloud }
    volumes: [cloud-data:/var/lib/postgresql/data, ./cloud-api/schema.sql:/docker-entrypoint-initdb.d/01.sql]
    networks: [cloud_net]

  cloud-admin:
    image: adminer:4
    networks: [cloud_net]
    ports: ["8090:8080"]

networks:
  trusted_net: {}
  cloud_net: {}

volumes:
  authority-data: {}
  keystore: {}
  cloud-data: {}
```

Cấu trúc thư mục đề xuất:

```
CP_ABE_1/
├── docker-compose.yml
├── authority/      # Go: Setup, KeyGen, policy registry, grant/revoke, eager worker, trang Admin
├── app/            # Go: Web UI, encrypt/decrypt/sign, keystore
├── cloud-api/      # Go: REST + kiểm chữ ký, schema.sql
├── shared/         # Go module dùng chung: định dạng gói tin, hàm mã hóa Tầng 2–3, ký/kiểm
└── docs/
```

---

## 9. Đo đạc (trả lời RQ3)

Không dùng số liệu ước đoán. Nhóm **tự đo** trên máy demo, bằng một lệnh `bench` trong `authority`:

| Phép đo | Biến thay đổi |
|---|---|
| Thời gian KeyGen | Số thuộc tính của user: 2, 5, 10, 20 |
| Thời gian Encrypt / Decrypt CP-ABE | Số thuộc tính trong chính sách: 2, 5, 10, 20 |
| Kích thước bản mã CP-ABE | như trên |
| Thời gian thu hồi 1 thuộc tính | Số tài liệu: 100, 1.000, 10.000. **So sánh thiết kế cũ và mới** (đây là biểu đồ chính) |
| Thời gian đọc 100 tài liệu cùng chính sách | Có / không có cache Policy Key |

Tham khảo để đối chiếu: Cloudflare công bố với **50 thuộc tính (trường hợp xấu nhất)** trên laptop Intel i7-10610U, giải mã ABE mất khoảng 62 ms, mã hóa khoảng 704 ms, khóa bí mật khoảng 33 KB. Với 2–5 thuộc tính như đồ án, kết quả sẽ nhỏ hơn nhiều, nhưng phải đo thực tế.

---

## 10. Cập nhật cho slide

| Slide | Thay đổi |
|---|---|
| 5 – So sánh | Thêm cột "CP-ABE cải tiến (nhóm)": chi phí thu hồi **Trung bình/Thấp**, có quyền ghi |
| 7 – Threat model | Integrity: **một phần** (chữ ký ghi + AES-GCM). Collusion chuyển sang "được bảo vệ". Thêm: Rollback, Availability vẫn ngoài phạm vi |
| 8, 9 – Use case | Đổi sang Công ty ABC (§2) |
| 10, 11 – Kiến trúc | Thay bằng sơ đồ §3.1 và §C2 |
| 13 – Thu hồi | Thay bằng luồng §C4 (chọn Versioning + Lazy/Eager) |
| 14 – Kiểm chứng | Bảng §7 |
| 15 – Hướng phát triển | Giữ Multi-Authority, Outsourced Decryption, Searchable Encryption; thêm "giải mã ngay trên trình duyệt (WebAssembly)" |

---

## 11. Những gì KHÔNG làm (và lý do)

| Kỹ thuật | Vì sao để lại "hướng phát triển" |
|---|---|
| Multi-Authority CP-ABE | Cần lược đồ khác, thư viện Go/Python còn hạn chế, phức tạp khi demo |
| Proxy re-encryption phía cloud | Phải sửa bên trong lược đồ (toán), không dùng được thư viện có sẵn. C2 + C4 đạt mục tiêu tương tự ở tầng hệ thống |
| Outsourced decryption | Nhờ C2, CP-ABE chỉ giải mã 1 lần/chính sách, nên lợi ích nhỏ |
| Tìm kiếm trên dữ liệu mã hóa | Ngoài trọng tâm authorization |
| Che giấu chính sách hoàn toàn | Cần lược đồ chuyên biệt; C5 là mức đủ dùng |
| Chống rollback toàn phần | Cần cơ chế ngoài (log công khai/blockchain). Chỉ ghi nhận |

---

## 12. Phân công gợi ý (4 người)

| Thành viên | Phần việc |
|---|---|
| 1 | `authority`: Setup/KeyGen, attribute registry, grant/revoke, biên dịch chính sách, eager worker |
| 2 | `shared` + `cloud-api` + schema: định dạng gói tin, Tầng 2–3, kiểm chữ ký, versioning/409 |
| 3 | `app` UI: chọn vai, kho tài liệu, soạn/sửa, lịch sử, trang Admin |
| 4 | Docker Compose, seed dữ liệu, kịch bản demo §7, đo đạc §9, cập nhật slide |

---

## Tài liệu tham khảo

> Chi tiết từng nguồn, trích dẫn và mức độ đã kiểm chứng: [docs/research/sources.md](research/sources.md).

**Trong 5 năm gần đây (làm căn cứ tính mới):**

1. Cloudflare, *Inside Geo Key Manager v2: re-imagining access control for distributed systems*, 27/01/2023. Nguồn của kiến trúc Policy Key (C2), cách xử lý xoay vòng khóa theo thế hệ, số liệu hiệu năng. https://blog.cloudflare.com/inside-geo-key-manager-v2
2. Cloudflare, *Portunus*: hệ thống RBAC xây trên CP-ABE, trình bày tại Real World Crypto 2023.
3. Cloudflare **CIRCL**, gói `abe/cpabe/tkn20` (v1.6.x, 2025–2026). https://pkg.go.dev/github.com/cloudflare/circl/abe/cpabe/tkn20
4. ETSI **TS 103 532 V1.2.1** (2021-05), *Attribute Based Encryption for Attribute Based Access Control*. https://etsi.org/deliver/etsi_TS/103500_103599/103532/01.02.01_60/ts_103532v010201p.pdf
5. Penuelas-Angulo, Feregrino-Uribe, Morales-Sandoval, *Revocation in attribute-based encryption for fog-enabled internet of things: A systematic survey*, Internet of Things, vol. 23, 2023. Phân loại các kỹ thuật thu hồi.

**Nền tảng (cũ, chỉ để dẫn nguồn ý tưởng):**

6. J. Tomida, Y. Kawahara, R. Nishimaki, lược đồ CP-ABE TKN20, PKC 2020.
7. Bethencourt, Sahai, Waters, *Ciphertext-Policy Attribute-Based Encryption*, IEEE S&P 2007.
8. Kallahalla et al., *Plutus: Scalable Secure File Sharing on Untrusted Storage*, FAST 2003. Nguồn của ý tưởng lazy revocation và tách khóa đọc/ghi.
9. Zhao et al., 2011. Kết hợp CP-ABE với chữ ký thuộc tính để tách quyền đọc/ghi trên cloud.
