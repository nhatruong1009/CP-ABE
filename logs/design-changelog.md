# Nhật ký thay đổi thiết kế (Design Changelog)

Mỗi mục ghi lại **đổi gì · vì sao · ảnh hưởng tới đâu**. Mục mới nhất đặt ở trên cùng.
Thiết kế hiện hành: **v4.4** (PoC phase 1 + Web UI), xem `analysis/05_dac-ta-kien-truc-v4.1.md` (đặc tả), `analysis/04_kien-truc-cp-abe-v4.md` (ý tưởng 6 tầng) và `diagrams/v4-kien-truc-cp-abe.md`. (v3 vẫn giữ trong `analysis/02_...` để tham khảo.)

---

## v4.4 — 2026-10-10 · Thêm Web UI cho demo

**Lý do:** người dùng cần giao diện để demo thay cho CLI.

| Thay đổi | v4.3 | v4.4 | Lý do |
|---|---|---|---|
| Giao diện | Chỉ có CLI | **Image `cpabe-v4/webui`** (cổng 8080): đóng vai *máy của user* (client agent, vùng tin cậy). Giữ JWT + SK của từng user, mã hóa / giải mã CP-ABE cục bộ. Trình duyệt chỉ hiển thị | Charm không chạy trong trình duyệt. Giữ nguyên nguyên tắc: APP không bao giờ giải mã |
| Thư viện client | Logic nằm trong `cli.py` (dùng `sys.exit`) | Tách thêm `cpabe/client/core.py` (ném exception), webui dùng module này | Dùng lại được cho UI |
| Quyền `GET /records` (danh sách) của APP | owner, admin, service | **Mọi user chưa bị thu hồi** | UI cần cho user thấy danh sách. Danh sách chỉ chứa metadata (id, version, policy), không có nội dung |
| Tab "Góc nhìn cloud / DBA" | `psql` trong demo.sh | Trên UI: liệt kê EncryptedRecord thô (lấy bằng service token) | Minh họa kịch bản A trực quan |

**Hạn chế:** webui là agent dùng chung cho nhiều user (mô phỏng nhiều thiết bị). Đăng nhập nhanh dùng mật khẩu demo trong `DEMO_USERS`. Khi triển khai thật, mỗi user tự chạy client của mình.

---

## v4.3 — 2026-10-10 · Ưu tiên PoC chạy được bằng các docker image

**Lý do:** người dùng cần một PoC tối thiểu gồm các docker image *outsource database, KGC, APP* và dịch vụ *xác thực người dùng*. Thứ tự triển khai vì vậy được đổi: dựng stack chạy end-to-end trước, các tầng nâng cao làm sau.

| Thay đổi | v4.2 | v4.3 (PoC phase 1) | Lý do |
|---|---|---|---|
| Thứ tự triển khai | Crypto, rồi Cedar, rồi service, rồi log, rồi thu hồi | **Crypto, rồi service + thu hồi R1 (PoC chạy được)**, sau đó mới tới Cedar, log, R2, benchmark | Ưu tiên PoC demo được |
| Xác thực (D6) | Token tĩnh trong `users.json` | **Service `auth` riêng**: `/login` phát JWT EdDSA (TTL 1h), `/public-key` cho các service khác kiểm tra, `/internal/attributes/{sub}` cung cấp thuộc tính cho KGC | Người dùng yêu cầu image dịch vụ xác thực; tách nguồn thuộc tính (HR) khỏi KGC |
| Service-to-service | — | Header `X-Service-Token` (PoC) | Đơn giản; bản thật nên dùng mTLS |
| APP | gateway | **image `app`**: CRUD, kiểm version (PUT: version và content_version cùng +1; PATCH header: chỉ version +1, không được đổi ciphertext, aead, kek_header), chặn user bị thu hồi (cache 2s) | Ràng buộc "re-wrap không đụng dữ liệu" được thực thi ở server |
| Outsource DB | PostgreSQL | **image `outsource-db`** (`postgres:16-alpine`), bảng `encrypted_records(record_id, version, content_version, doc JSONB)`, chỉ nằm ở network `cloud` | |
| KGC | Có R1 + R2 | **R1 (epoch) trước**. MSK seal bằng AES-GCM với `KGC_SEAL_KEY` | R2 làm ở phase sau |
| Worker | Container riêng | Lệnh `worker-rewrap` của image `client` (chạy theo yêu cầu) | Giảm số container của PoC |
| Policy | Cedar (T1) | **Bộ dịch tối giản** `Dept:X AND (Role:Y OR ...)` sang token Charm, tự ghép epoch, từ chối NOT. `policy_ref.src` được lưu để worker biên dịch lại khi đổi epoch | Cedar để phase sau |
| Hoãn sang phase sau | — | owner_sig + transparency log + auditor (T4/T5), Cedar (T1), R2, Planner, benchmark | |

**Image của PoC:**
- `outsource-db` (postgres:16-alpine)
- `cpabe-v4/auth`, `cpabe-v4/kgc`, `cpabe-v4/keyvault`, `cpabe-v4/app`
- `cpabe-v4/client` (CLI cho owner, user, admin và worker)

**Hạn chế được chấp nhận ở phase 1:**
- Chưa có owner_sig, nên chưa phát hiện được bản ghi giả tạo bằng MPK.
- Mật khẩu demo để dạng rõ trong `users.json`.
- Bí mật mặc định (`SERVICE_TOKEN`, `KGC_SEAL_KEY`) nằm trong compose.

---

## v4.2 — 2026-10-10 · Sửa thiết kế lõi mật mã khi viết code (bước 1)

**Lý do:** khi hiện thực `cpabe/crypto/` đã lộ ra 4 điểm mà thiết kế v4.1 chưa tính tới.

| Thay đổi | v4.1 | v4.2 | Lý do |
|---|---|---|---|
| Quan hệ giữa CP-ABE và CEK | CP-ABE "bọc CEK" trực tiếp | **KEM 3 lớp**: CP-ABE KEM sinh `k_abe`; `k_abe` bọc một CEK độc lập (`abe_header = {kem, wrap}`) | KEM của CP-ABE tự sinh khóa, nên **không thể bọc lại đúng CEK cũ** theo policy mới. Nếu không sửa, thu hồi L1 / đổi policy "dữ liệu giữ nguyên" là bất khả thi |
| AAD | Một AAD chung `record_id \|\| version \|\| backend \|\| policy_hash` | Tách làm hai: **data_aad** = `record_id \|\| content_version` và **header_aad** = `record_id \|\| version \|\| backend \|\| policy_hash` | AAD chung chứa version/policy, nên mỗi lần re-wrap đều phải mã hóa lại dữ liệu. Tách ra thì L1 chỉ thay vài trăm byte header |
| Phiên bản bản ghi | `version` | `version` (mọi thay đổi) + **`content_version`** (chỉ tăng khi Update nội dung) | Đi kèm thay đổi AAD |
| Định dạng token thuộc tính | `Dept:Cardiology@v1` | **`DEPTXCARDIOLOGYXV1`**, `EPOCHX7`: viết hoa toàn bộ, không có `_`. Backend từ chối token sai định dạng (`check_token`) | **Đã xác nhận trong mã nguồn Charm 0.63**: `node.py` viết hoa thuộc tính trong policy (khóa thì không) và `msp.strip_index` cắt `_<số>` cuối (`EPOCH_7` thành `EPOCH`). Lần chạy đầu với token `DEPTxCARDIOLOGYxV1` làm 6/16 test thất bại vì lệch chữ hoa/thường |
| Serialize khóa/header | Chưa quy định | **JSON an toàn tự viết**, cấm `objectToBytes/bytesToObject` của Charm | Hai hàm đó dựa trên pickle, mà header đọc từ cloud là dữ liệu không tin cậy, nên unpickle có nguy cơ RCE |
| Cây policy trong header | Chưa quy định | **Không lưu**; dựng lại từ `policy_abe` lúc giải mã | `policy_abe` đã được ràng buộc qua `policy_hash` trong header_aad |
| Kiểm tra quyền | Dựa vào `ac17.decrypt` | Gọi `prune()` trước, không thỏa thì `AccessDenied` | Không phụ thuộc cách Charm báo lỗi (in ra màn hình rồi trả None) |
| Re-wrap | — | `unwrap_cek` kiểm tra CEK khớp **commit** của dữ liệu trước khi bọc lại | Phát hiện kek_header bị tráo hoặc hỏng |
| Lỗi từ Charm | — | `InvalidCiphertext`, `ValueError` của `ac17.decrypt` được gộp thành `IntegrityError` | Charm 0.63 tự xác thực ciphertext ac17: khóa ghép (F, F2) và policy bị cloud sửa (K2) bị chặn ngay ở lớp KEM |
| Môi trường | Python 3.9 trên Debian bullseye | `python:3.9-slim-bookworm`, Charm ghim commit `b2db00b` (0.63), PBC 0.5.14 | Kho gói bullseye trả 404 khi build |

**Ảnh hưởng:** sơ đồ §6, §7, §9 được sửa và thêm §10 (cấu trúc bản ghi); đặc tả §3 đã cập nhật. Planner T6 tính chi phí L1 = 1 lần encaps + 1 lần AES-GCM trên 32 byte cho mỗi bản ghi.

---

## v4.1 — 2026-10-10 · Làm rõ kiến trúc để triển khai

**Lý do:** chuẩn bị hiện thực v4. Cần chỉ rõ container, khóa và luồng gọi. Trong lúc làm rõ đã phát hiện các điểm hở trong v4.

| Thay đổi | v4 | v4.1 | Lý do |
|---|---|---|---|
| Nơi giữ khóa ký owner (sk_DO) | Owner Client | **keyvault** (API `sign`) | Re-wrap/re-encrypt làm thay header, nên phải **ký lại** bản ghi. Worker cần ký được mà không phải giữ sk_DO |
| Nơi giữ KEK | "Vault" chung chung | **keyvault** (API `wrap`/`unwrap`, giống Vault Transit) | KEK không bao giờ rời keyvault, mọi lần dùng đều có log |
| Gateway | CRUD + revocation list + re-wrap job + planner, có quyền dùng KEK | **Mỏng**: AuthN, revocation list, CRUD, append RECORD. **Không giữ khóa nào** | Thu hẹp bề mặt tấn công. Gateway bị lộ cũng không lộ dữ liệu |
| Job thu hồi + Planner | Nằm trong gateway | Tách ra container **worker** | Tách trách nhiệm rõ ràng |
| Độ tin cậy của checkpoint | Checkpoint do log ký | Checkpoint phải có **sig_log + sig_witness** (auditor đồng ký) | Log đặt trên cloud không tin cậy. Witness chống viết lại lịch sử và split-view |
| Danh tính trong log | Có user_id | **Pseudonym** `HMAC(k_org, user_id)` | Log có thể công khai mà không lộ danh tính |
| Policy trong bản ghi | Chưa rõ | `policy_abe` lưu dạng rõ + `policy_hash` trong AAD | Giải mã cần biết policy. AAD chống tráo |
| Triển khai | Chưa có | docker compose, 2 network `trusted` / `cloud` + auditor riêng | Mô phỏng vùng tin cậy |
| Kịch bản | 15 KB | Thêm **F2** (ghép khóa cũ với khóa mới của cùng user) | Bổ sung sau khi phân tích collusion |

**Giả định tin cậy được nêu rõ:** kgc, keyvault, worker. Gateway, storage và translog **không cần được tin** về bí mật. Riêng gateway được tin về tính sẵn sàng và việc thực thi revocation list (lớp vận hành).
**Quyết định đã chốt (2026-10-10):** D1 Python + Charm (`ac17`/FAME, BN254, Docker Python 3.9) · D2 PostgreSQL · D3 tự viết Merkle log (kiểu RFC 6962) · D4 tự viết compiler cho tập con Cedar, `cedarpy` làm authorizer tham chiếu · D5 tự viết keyvault · D6 token tĩnh · D7 chỉ backend `fame` (covercrypt để sau) · D8 CLI.

---

## v4 — 2026-10-10 · Thiết kế lại từ đầu, không dựa vào proposal gốc, tối đa tính mới 2021–2026

**Lý do:** người dùng yêu cầu bỏ qua proposal gốc, thiết kế cấu trúc triển khai CP-ABE sao cho có tính mới (5 năm gần đây) trên càng nhiều phương diện càng tốt. Vẫn giữ: bỏ hậu lượng tử, hướng ứng dụng, khoảng 1 tuần.

| Thay đổi | v3 | v4 | Lý do |
|---|---|---|---|
| Tổ chức | 3 trục | **6 tầng** (Policy · Crypto core · Data encryption · Key mgmt & trust · Data ops & integrity · Revocation) + Evaluation + Compliance | Mỗi tầng gắn một điểm mới |
| Policy | Viết tay `Dept/Role` | **Cedar → biên dịch → policy CP-ABE** + kiểm thử tương đương | Phương diện mới: policy engineering (Cedar 2023/OOPSLA 2024) |
| Lược đồ | Cố định `bsw07`/`ac17` | **Giao diện AbeProvider (crypto-agility)**: `fame` mặc định; `covercrypt`, `tinyabe` mở rộng; header ghi `abe_backend` | Đổi lược đồ không phải sửa dữ liệu cũ; Covercrypt (2023/ETSI 2025), TinyABE (2022) |
| AEAD | AES-GCM | **Key-committing AEAD** (HKDF → K_enc, K_com + HMAC commit), AAD gồm backend và policy_hash | Chống partitioning-oracle và tráo header (2021–2022) |
| Tin cậy KGC | Tin tuyệt đối | **Key-issuance transparency log** + auditor | KGC vẫn giữ escrow nhưng phải chịu trách nhiệm (Parakeet 2023, OPTIKS 2024) |
| Toàn vẹn dữ liệu | Không có (đã chuyển ra ngoài phạm vi ở v3) | **Đưa trở lại**: owner_sig + record transparency dùng chung log | Giá trị cao, chỉ tốn thêm ít công vì dùng chung hạ tầng log |
| Thu hồi | R1/R2 × L0/L1/L2 | Giữ nguyên + **Planner** + 2 chỉ số window + ghi thu hồi vào log | Tận dụng khoảng trống thực nghiệm |
| Kiểm chứng lược đồ | Chỉ tránh lược đồ bị phá | + **ACABELLA** cho lược đồ được chọn | 2023 |
| Threat model | Cloud HbC | Cloud **malicious** (phát hiện được), KGC **trusted-but-accountable** | Có transparency log nên mô hình mạnh hơn |
| Thành phần mới | — | Policy Studio, Transparency Log, Auditor | |
| Kịch bản | 9 KB | 15 KB (thêm P1, P2, K1, K2, L1, L2, I1, I2, X) | |

**Vẫn ngoài phạm vi:** hậu lượng tử · ẩn mẫu truy cập (ORAM) · searchable encryption · DoS. MA-ABE và Registered ABE chỉ ở mức hướng phát triển.
**Cần xác minh trước khi hiện thực:**
- Tính năng partial evaluation của thư viện Cedar (dự phòng: tự viết compiler trên Cedar JSON).
- Hiện thực công khai của TinyABE.
- Cách gọi Covercrypt từ Python.

---

## v3 — 2026-10-10 · Thu gọn còn 3 trục: CP-ABE · thao tác dữ liệu · thu hồi khóa

**Lý do:** use case v2 quá chi tiết so với thời gian 1 tuần. Trọng tâm đồ án là CP-ABE, cách thao tác trên dữ liệu đã mã hóa, và thu hồi khóa.

| Thay đổi | Trước (v2) | Sau (v3) | Lý do |
|---|---|---|---|
| Use case | Bệnh án tách 3 nhóm trường (clinical/vitals/billing), có cấp cứu | **Bản ghi đơn**, 1 policy, 2 loại thuộc tính `Dept`/`Role`, 3 user demo | Giảm độ phức tạp nghiệp vụ |
| Thao tác dữ liệu | Chỉ có ghi/đọc | **Đủ CRUD + Đổi policy** (Update dùng CEK mới; Đổi policy chỉ bọc lại header) | Trục 2 thành nội dung chính |
| Thu hồi | Chỉ có epoch toàn cục | **R1 Epoch** (thu hồi user) + **R2 Attribute versioning** (thu hồi thuộc tính) × **L0/L1/L2** (re-encrypt toàn bộ / chỉ bọc header / bọc header + lazy) | Trả lời RQ2 bằng so sánh định lượng |
| Kịch bản kiểm chứng | A–I | A, B, F, **U, P, D, C1, C2, C3** | Bám theo 3 trục |
| Bị loại khỏi phạm vi | — | Chữ ký DO + manifest/Merkle (M1, M2), audit log (M4), break-glass (M5), giả danh thuộc tính HMAC (M6) | Không thuộc 3 trục, chuyển sang "Hướng phát triển" |
| Owner Signing Service | Có | **Bỏ** | Đi kèm M1/M2 |
| Sơ đồ | 9 sơ đồ | 8 sơ đồ: kiến trúc, cấu trúc bản ghi, cấp khóa, Create/Read, Update/Đổi policy/Delete, R1, R2, so sánh chiến lược | Bám theo 3 trục |

**Giữ nguyên từ v2:** mã hóa lai AES-GCM + CP-ABE · **bọc CEK kép** (CP-ABE + KEK) · App Server ở vùng tin cậy · Charm-crypto, `bsw07`/`ac17`, BN254 · collusion resistance là tính chất được bảo đảm.

**Rủi ro được chấp nhận (ghi vào báo cáo):**
- Không có toàn vẹn: MPK công khai nên ai cũng tạo được bản ghi hợp lệ.
- KGC và KEK giữ escrow.
- Mức L1 không chặn được CEK đã bị cache.
- Cloud vẫn thấy mẫu truy cập.

---

## v2 — 2026-10-10 · Rút gọn cho 1 tuần, bỏ hậu lượng tử

**Lý do:** đồ án cần hoàn thành trong 1 tuần, và người dùng yêu cầu bỏ hướng lượng tử.

| Thay đổi | Trước (v1') | Sau (v2) | Lý do |
|---|---|---|---|
| Hậu lượng tử | Covercrypt / ML-KEM (N1) | **Bỏ** | Theo yêu cầu |
| Ẩn policy | Covercrypt | Giả danh thuộc tính bằng HMAC (M6) | Rẻ, làm được trong 1 ngày |
| Đường cong | Khuyến nghị BLS12-381 | **BN254** (ghi là giới hạn PoC) | Charm và rabe chỉ hỗ trợ BN254, không kịp đổi |
| Vị trí App Server | Mơ hồ (slide 11) | **Vùng tin cậy** (gateway on-prem) | Làm rõ ranh giới tin cậy |
| Bọc lại CEK khi thu hồi | Chưa xác định | **CEK bọc kép** (CP-ABE + KEK) | Re-wrap không cần giải mã CP-ABE |
| Threat model | HbC nhưng lại kết luận "host bị xâm nhập hoàn toàn vẫn an toàn" | HbC về bí mật + malicious nhưng phát hiện được về toàn vẹn | Sửa mâu thuẫn |
| Collusion | Ngoài phạm vi | Tính chất được bảo đảm | Có sẵn trong CP-ABE |
| Phạm vi | Nhiều hướng (MA-ABE, blockchain, ABSE…) | M0–M7 | Khả thi trong 1 tuần |

---

## v1' — 2026-10-10 · Đề xuất cải tiến sau khi đánh giá (bản phân tích 01)

So với v1, bổ sung các hướng: chữ ký DO + version + Merkle root (C1) · sửa threat model (C2) · chọn lược đồ/thư viện an toàn (C3) · Covercrypt (N1) · thu hồi theo epoch + bọc lại CEK (N2) · benchmark theo ABE Squared (N3) · audit + HSM (N4) · các mở rộng E1–E5.
Chi tiết: `analysis/01_phan-tich-van-de-va-danh-gia-proposal.md`, Phần 4 (đã được thay thế bằng v2, rồi v3).

---

## v1 — Proposal gốc (`ref/proposal.pdf`)

- CP-ABE (BSW07) lai với CEK.
- Kiến trúc gồm Data Owner · Cloud · KGC · User. App Server làm trung chuyển.
- Thu hồi: liệt kê attribute versioning / lazy re-encryption / time-bound keys, chưa chọn phương án nào.
- Phạm vi: chỉ confidentiality. Integrity, collusion và search nằm ngoài phạm vi.
