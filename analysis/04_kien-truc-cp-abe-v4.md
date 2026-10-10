# Kiến trúc hệ thống CP-ABE v4 — thiết kế mới, tối đa tính mới 2021–2026

> **Không dựa trên proposal gốc.** Thiết kế làm lại từ đầu cho câu hỏi: *"Muốn triển khai cơ chế CP-ABE thì cần cấu trúc thế nào, và có tính mới (10/2021 – 10/2026) trên càng nhiều phương diện càng tốt?"*
> Ràng buộc giữ nguyên: **bỏ hướng hậu lượng tử** · đồ án **ứng dụng**, không trình bày chứng minh toán · làm trong **khoảng 1 tuần** (mục 7 có gói 1 tuần).
> Sơ đồ: [`diagrams/v4-kien-truc-cp-abe.md`](../diagrams/v4-kien-truc-cp-abe.md) (bản xem trình duyệt: `.html` cùng tên). Lịch sử thiết kế: [`logs/design-changelog.md`](../logs/design-changelog.md).

---

## 1. Ý tưởng tổng thể

Một hệ thống CP-ABE dùng được trong thực tế cần nhiều hơn 4 thuật toán Setup/KeyGen/Encrypt/Decrypt. v4 tổ chức hệ thống thành **6 tầng**. Ở mỗi tầng chọn **một kết quả của 5 năm gần đây** làm điểm mới:

| Tầng | Câu hỏi tầng phải trả lời | Điểm mới (2021–2026) |
|---|---|---|
| **T1. Policy** | Viết quyền thế nào để người làm nghiệp vụ hiểu được, rồi biến thành policy CP-ABE? | **Biên dịch Cedar → policy CP-ABE** (Cedar: AWS 2023, OOPSLA 2024) |
| **T2. Crypto core** | Chọn lược đồ nào, có đổi được không, có an toàn không? | **Crypto-agility**: giao diện provider cắm được nhiều lược đồ. Kiểm tra lược đồ bằng **ACABELLA (CCS 2023)**. Backend mở rộng: **TinyABE (2022)**, **Covercrypt ẩn policy (ESORICS 2023 / ETSI TS 104 015, 2025)** |
| **T3. Data encryption** | Mã hóa dữ liệu thế nào cho đúng? | **Key-committing AEAD**, chống partitioning-oracle và tấn công "1 ciphertext → nhiều plaintext" (Len et al. 2021, Bellare–Hoang 2022, IETF CFRG AEGIS 2023–2025) |
| **T4. Key management & trust** | Làm sao tin được KGC, người giữ khóa vạn năng? | **Key-issuance transparency log**: mọi lần cấp khóa đều nằm trong log Merkle append-only mà user và auditor kiểm tra được (Parakeet NDSS 2023, OPTIKS USENIX 2024). Mở rộng: 2 authority (MA-ABE, framework ISABELLA CCS 2024), Registered ABE (2023 → "Towards Practical", 2026) |
| **T5. Data operations & integrity** | CRUD trên dữ liệu đã mã hóa, phát hiện sửa hoặc rollback thế nào? | **Record transparency**: dùng **chung log** với T4 cho version bản ghi, cộng chữ ký của owner |
| **T6. Revocation** | Thu hồi thế nào cho rẻ và an toàn? | **Revocation planner** + 2 chỉ số *revocation window* / *CEK exposure window*. Đối chiếu với ABPRE thu hồi trực tiếp (TDSC 2024) |
| **Ngang tầng: Evaluation** | Đo thế nào cho đáng tin? | Phương pháp **ABE Squared (TCHES 2022) / ABE Cubed (TCHES 2025)** |
| **Ngang tầng: Compliance** | Phù hợp chuẩn và luật nào? | **NIST IR 8450 (2023)**, ETSI TS 103 532 v1.2.1 (2021), ETSI TS 104 015 (2025), Luật BVDLCN 2025 (VN) |

---

## 2. Thành phần hệ thống và vùng tin cậy

| Thành phần | Vùng | Vai trò |
|---|---|---|
| **Policy Studio** | Tin cậy | Viết policy Cedar, biên dịch sang policy ABE, kiểm thử ma trận quyền |
| **KGC** | Tin cậy | Setup, KeyGen, quản lý epoch và attribute version. Ghi mỗi lần cấp khóa vào Transparency Log |
| **Key Vault** | Tin cậy | Giữ MSK, KEK, khóa ký owner (HSM/Vault, hoặc file khóa có bảo vệ cho PoC) |
| **Owner Client** | Tin cậy | Create, Update, Đổi policy, Delete. Mã hóa và ký |
| **User Client** | Thiết bị user | Xác minh, giải mã cục bộ. Tự giám sát khóa của chính mình trong log |
| **Gateway / App Server** | Tin cậy | CRUD API, revocation list, job re-wrap, Revocation Planner |
| **Transparency Log** | **Không tin cậy cũng được** | Log Merkle append-only: cloud lưu, nhưng mọi sửa đổi đều bị phát hiện qua checkpoint đã ký và các bằng chứng |
| **Auditor / Monitor** | Độc lập | Kiểm tra log có nhất quán không (append-only), cảnh báo khi có khóa lạ |
| **Cloud Storage** | Không tin cậy | Chỉ lưu EncryptedRecord |

---

## 3. Chi tiết từng tầng

### T1. Policy — Cedar → CP-ABE
- **Cách viết:** người làm nghiệp vụ viết quyền bằng **Cedar**. Ví dụ: `permit(principal, action == Action::"read", resource) when { principal.dept == resource.dept && principal.role == "Doctor" };`
- **Biên dịch:** lúc mã hóa, `resource.dept` đã biết, chẳng hạn bằng `"Cardiology"`. Thay giá trị này vào policy (**đánh giá cục bộ / partial evaluation**) thì phần còn lại chỉ là một công thức trên thuộc tính của principal, ví dụ `Dept:Cardiology AND Role:Doctor`. Công thức này **chính là policy CP-ABE**.
- **Kiểm tra lúc biên dịch:**
  - CP-ABE chỉ hỗ trợ policy **đơn điệu** (AND/OR), nên bộ biên dịch **từ chối** phủ định (`!`) và `forbid`.
  - So sánh số (`principal.level >= 3`) được mã hóa thành nhiều thuộc tính bit (bag-of-bits), hoặc bị từ chối trong PoC.
- **Kiểm thử ngữ nghĩa:** với mọi cặp (user mẫu, bản ghi mẫu), so kết quả của Cedar authorizer (tham chiếu) với kết quả giải mã ABE. Hai bên phải **giống hệt nhau**.
- **Tại sao mới:** Cedar ra đời năm 2023 và có bài OOPSLA 2024. Chưa thấy công trình nào dùng nó làm ngôn ngữ nguồn cho CP-ABE.
- ⚠️ Cần kiểm tra xem thư viện `cedar-policy` có bật được tính năng partial evaluation (đang ở dạng experimental) không. **Phương án dự phòng:** tự viết bộ biên dịch trên định dạng JSON của Cedar, giới hạn ở `==`, `&&`, `||`, `in`.

### T2. Crypto core — crypto-agility
- **Giao diện provider** (mọi backend đều cài đặt cùng một giao diện):
  ```
  AbeProvider: setup() · keygen(msk, attrs) · encaps(mpk, policy) -> (CEK, header) · decaps(sk, header) -> CEK
  ```
- **Backend:**

| Backend | Lược đồ | Vai trò | Mới? |
|---|---|---|---|
| `fame` | FAME/AC17 (Charm `ac17`) | **Mặc định**, đã được kiểm chứng rộng rãi | Không (2017), nhưng có kết quả benchmark mới trong ABE Squared |
| `tinyabe` | TinyABE (AFRICACRYPT 2022) | Ciphertext nhỏ, phù hợp client yếu | ✅ (nếu có hiện thực; nếu không, chỉ so sánh trên lý thuyết) |
| `covercrypt` | Covercrypt (ESORICS 2023, ETSI TS 104 015) | **Ẩn policy** + truy vết. *Không đánh giá phần hậu lượng tử* | ✅ |

- **Header ghi rõ backend** (`abe_backend`, `version`), nên **đổi lược đồ không phải sửa dữ liệu cũ**.
- **Kiểm tra lược đồ:** không dùng các lược đồ có trong danh sách bị phá (*A Bunch of Broken Schemes*, CT-RSA 2021). Biến thể nào nhóm tự chỉnh thì chạy qua **ACABELLA** (CCS 2023).

### T3. Data encryption — key-committing AEAD
- **Vấn đề:** AES-GCM *không* cam kết khóa. Người tạo bản ghi có ý xấu (hoặc cloud ghép header với ciphertext) có thể tạo ra một ciphertext giải mã ra **nội dung khác nhau với các khóa khác nhau**. Kiểu tấn công này thuộc họ partitioning-oracle / "invisible salamanders".
- **Giải pháp PoC:** `HKDF(CEK)` sinh ra hai khóa `K_enc` và `K_com`. Mã hóa bằng AES-256-GCM với `K_enc`. Lưu thêm `commit = HMAC(K_com, nonce || AAD)` và kiểm tra commit **trước khi** giải mã. Thay thế khác: dùng AEGIS-256 nếu thư viện có.
- **AAD** gồm `record_id || version || abe_backend || policy_hash`. Nhờ vậy cloud không thể tráo header của bản ghi này sang bản ghi khác.

### T4. Key management & trust — key-issuance transparency
- **Mỗi lần KeyGen**, KGC ghi một entry vào log: `{user_pseudonym, H(attrs), epoch, attr_versions, issued_at}`, có chữ ký của KGC. Log trả về *inclusion proof*, được gửi kèm SK cho user.
- **User Client** kiểm tra inclusion proof khi nhận khóa, và định kỳ kiểm tra không có khóa nào được cấp "nhân danh" mình.
- **Auditor** kiểm tra *consistency proof* giữa các checkpoint (log chỉ được nối thêm, không bị viết lại). Auditor cũng cảnh báo khi có thuộc tính bất thường, ví dụ ai đó được cấp `Role:Director`.
- **Tác dụng:** KGC vẫn là bên giữ escrow, nhưng **mọi lần lạm dụng cấp khóa đều để lại dấu vết công khai**. Đây là cách giảm rủi ro "KGC là bên phải tin tuyệt đối" bằng kỹ thuật key transparency 2023–2024, thay vì phải dùng multi-authority.
- **MSK/KEK** để trong Vault. **Mở rộng:**
  - 2 authority với MA-ABE RW15 (Charm, không nằm trong danh sách bị phá), tham khảo ISABELLA (CCS 2024).
  - **Registered ABE** (Eurocrypt 2023, "Towards Practical Registered ABE" 2026), chỉ ở mức hướng phát triển hoặc thí nghiệm.

### T5. Data operations & integrity
- **Định dạng `EncryptedRecord v4`:**
  ```
  record_id, version, policy_ref{cedar_policy_id, policy_hash}, abe_backend,
  abe_header, kek_header, aead{alg, nonce, commit}, ciphertext,
  owner_sig, log_index
  ```
- **CRUD:**
  - **Create:** sinh CEK mới.
  - **Update:** sinh CEK mới, `version+1`.
  - **Đổi policy:** `Unwrap(KEK)` lấy CEK rồi bọc lại `abe_header`, dữ liệu giữ nguyên.
  - **Delete:** ghi một *tombstone* vào log.
- **Record transparency:** mỗi lần ghi, entry `{record_id, version, H(record)}` được thêm vào **cùng log ở T4**. Client đọc xác minh `owner_sig` và inclusion proof, rồi so `version` với checkpoint mới nhất. Cách này **phát hiện được sửa, giả mạo bằng MPK, và rollback**.

### T6. Revocation — planner + chỉ số
- **Hai cơ chế:**
  - **R1 Epoch** dùng khi thu hồi user.
  - **R2 Attribute versioning** dùng khi thu hồi một thuộc tính.
  - Cả hai đều đi kèm **revocation list** ở gateway để chặn tức thì.
- **Ba mức xử lý dữ liệu:**
  - **L0:** re-encrypt toàn bộ.
  - **L1:** chỉ bọc lại header.
  - **L2:** bọc lại header + lazy re-encryption.
- **Revocation Planner:** nhận đầu vào (số user bị ảnh hưởng, số bản ghi liên quan, kích thước dữ liệu, mức nhạy cảm) và **chọn tổ hợp R × L** theo mô hình chi phí. Mô hình được hiệu chỉnh bằng số liệu đo thật.
- **Chỉ số:**
  - *Revocation window*: thời gian đến khi SK cũ vô hiệu.
  - *CEK exposure window*: thời gian đến khi CEK đã bị cache không còn mở được bản ghi.
- **Ghi log:** mỗi lần thu hồi đều được ghi vào transparency log (T4), nên **chứng minh được là đã thu hồi**.

---

## 4. Cấu trúc mã nguồn đề xuất

```
cpabe-v4/
├── policy/                 # T1
│   ├── schema.cedarschema
│   ├── policies/*.cedar
│   ├── compiler.py         # Cedar (JSON) → ABE policy, kiểm tra tính đơn điệu
│   └── equivalence_test.py # Cedar authorizer ≡ ABE decrypt trên ma trận mẫu
├── crypto/                 # T2, T3
│   ├── provider.py         # giao diện AbeProvider
│   ├── backends/{fame.py, tinyabe.py, covercrypt.py}
│   ├── caead.py            # key-committing AEAD (HKDF + AES-GCM + HMAC commit)
│   └── envelope.py         # CEK bọc kép: ABE header + KEK header
├── kgc/                    # T4
│   ├── service.py          # setup / keygen / epoch / attr-version / revoke
│   └── vault.py
├── translog/               # T4 + T5: Merkle log append-only, checkpoint, inclusion/consistency proof
│   ├── log.py
│   └── auditor.py
├── gateway/                # T5, T6: FastAPI CRUD + revocation list + jobs
│   ├── api.py
│   ├── rewrap_job.py
│   └── planner.py
├── client/                 # owner + user CLI (xác minh → giải mã)
├── bench/                  # đo theo ABE Squared: thuộc tính, kích thước, R×L
├── tests/scenarios/        # kịch bản tấn công (mục 6)
└── docs/                   # threat model, ADR, báo cáo
```

---

## 5. Threat model v4 (gọn)

- **Cloud & Transparency Log host:** *malicious*. Có thể đọc, sửa, xóa, rollback, tráo header. Hệ thống **bảo đảm bí mật** và **phát hiện** được mọi sửa đổi, nhưng không ngăn được việc xóa (cần backup).
- **KGC:** *trusted-but-accountable*. Được tin để không làm lộ MSK, nhưng **mọi lần cấp khóa đều bị log**. Nếu KGC cấp khóa lén, việc đó bị phát hiện qua log, với điều kiện auditor hoặc user có giám sát.
- **User:** có thể thông đồng (collusion resistance được bảo đảm), có thể cache CEK (được đo bằng exposure window).
- **Ngoài phạm vi:** ẩn mẫu truy cập (ORAM), tìm kiếm trên dữ liệu mã hóa, hậu lượng tử, DoS.

## 6. Kịch bản kiểm chứng

| KB | Tình huống | Kỳ vọng | Tầng |
|---|---|---|---|
| A | DBA đọc DB | Chỉ thấy ciphertext | T2–T3 |
| B | User không đủ thuộc tính | Decaps thất bại | T2 |
| F | Hai user ghép khóa | Thất bại | T2 |
| P1 | Policy Cedar ↔ kết quả ABE | Khớp 100% trên ma trận mẫu | T1 |
| P2 | Policy có `!`/`forbid` | Bộ biên dịch từ chối, kèm lý do | T1 |
| K1 | Ciphertext "nhiều khóa" (non-committing) | Commit sai, bị từ chối trước khi giải mã | T3 |
| K2 | Tráo header giữa các bản ghi | Sai AAD hoặc commit, bị từ chối | T3 |
| L1 | KGC cấp lén khóa `Role:Director` | Auditor phát hiện entry lạ | T4 |
| L2 | Log host viết lại lịch sử | Consistency proof thất bại | T4 |
| I1 | Cloud giả bản ghi bằng MPK | Sai `owner_sig` hoặc thiếu inclusion proof | T5 |
| I2 | Rollback bản ghi | Version cũ hơn checkpoint, bị phát hiện | T5 |
| C1/C2/C3 | Thu hồi user / thuộc tính / CEK đã cache | Theo R×L, có số đo window | T6 |
| X | Đổi backend `fame` → `covercrypt` | Bản ghi cũ vẫn đọc được, bản ghi mới dùng backend mới | T2 |

---

## 7. Gói 1 tuần (khả thi) và gói mở rộng

| Ngày | Hạng mục | Phương diện mới đạt được |
|---|---|---|
| 1 | Crypto core: `provider` + backend `fame` + `caead` + `envelope`. KB A, B, F, K1, K2 | Key-committing AEAD |
| 2 | Policy: Cedar → ABE compiler + kiểm thử tương đương. KB P1, P2 | Policy engineering |
| 3 | Gateway CRUD + client. EncryptedRecord v4 | — |
| 4 | Transparency log (Merkle, checkpoint, proof) + auditor. Gắn vào KGC và các lần ghi bản ghi. KB L1, L2, I1, I2 | Key & record transparency |
| 5 | Revocation R1/R2 × L0/L1/L2 + planner. KB C1–C3 | Revocation planner + chỉ số |
| 6 | Benchmark theo ABE Squared. Chạy ACABELLA cho lược đồ đã chọn. Gom pytest | Phương pháp đánh giá + kiểm chứng lược đồ |
| 7 | Báo cáo, slide, video demo. Đối chiếu NIST IR 8450 / ETSI | Chuẩn & tuân thủ |

**Mở rộng** (nếu còn thời gian hoặc để ở hướng phát triển): backend `covercrypt` (ẩn policy, KB X) · backend `tinyabe` · 2 authority với MA-ABE · Registered ABE · outsourced decryption có kiểm chứng (2024) · client WASM.

---

## 8. Đánh giá tính mới của v4

| Phương diện | Thành phần | Nguồn 5 năm | Gói 1 tuần? |
|---|---|---|---|
| 1. Ngôn ngữ / kỹ thuật policy | Cedar → CP-ABE + kiểm thử tương đương | Cedar 2023 / OOPSLA 2024 | ✅ |
| 2. Xây dựng mật mã cho dữ liệu | Key-committing AEAD trong mã hóa lai ABE | 2021–2022, IETF AEGIS 2023–25 | ✅ |
| 3. Tin cậy KGC / trách nhiệm | Key-issuance transparency log | Parakeet 2023, OPTIKS 2024 | ✅ |
| 4. Toàn vẹn dữ liệu | Record transparency dùng chung log | (ứng dụng từ 3) | ✅ |
| 5. Thu hồi | Planner + 2 chỉ số window | Khoảng trống so với TDSC 2024 và các bài proxy-based 2024 | ✅ |
| 6. Bảo đảm an toàn lược đồ | ACABELLA / tránh lược đồ bị phá | 2021, 2023, ISABELLA 2024 | ✅ |
| 7. Phương pháp đánh giá | ABE Squared / Cubed | 2022, 2025 | ✅ |
| 8. Chuẩn & tuân thủ | NIST IR 8450, ETSI TS 104 015, Luật BVDLCN 2025 | 2023–2025 | ✅ |
| 9. Lược đồ / ẩn policy | Crypto-agility + Covercrypt / TinyABE | 2022, 2023/2025 | 🟡 mở rộng |
| 10. Phi tập trung KGC | MA-ABE (ISABELLA) / Registered ABE | 2023–2026 | ❌ hướng phát triển |

**Ước lượng:** gói 1 tuần đạt khoảng **7/10** (8 phương diện). Nếu thêm Covercrypt thì lên khoảng **8/10**.

**Điểm "mới" nên nhấn mạnh khi bảo vệ:**
1. **Cedar → CP-ABE.** Đưa ngôn ngữ phân quyền hiện đại vào mã hóa và chứng minh hai bên tương đương bằng kiểm thử.
2. **Transparency log cho cả khóa lẫn dữ liệu.** KGC vẫn giữ escrow nhưng phải chịu trách nhiệm (*accountable*), và cloud không giả mạo hay rollback được mà không bị phát hiện.
3. **Revocation planner.** Đưa ra khuyến nghị chọn chiến lược thu hồi có số liệu kiểm chứng.

**Cần kiểm tra lại trước khi trích dẫn:**
- Tính năng partial evaluation của thư viện Cedar.
- Hiện thực công khai của TinyABE.
- Năm công bố của bài Registered ABE linear-CRS (Stracovsky–Waters–Wu).
- Chi tiết bài Chan–Rogaway (ESORICS 2022) và Bellare–Hoang (Eurocrypt 2022). Hai bài này tôi chưa mở được bản gốc.
