# Đặc tả kiến trúc v4.1 — chuẩn bị triển khai

> Sơ đồ: [`diagrams/v4-kien-truc-cp-abe.md`](../diagrams/v4-kien-truc-cp-abe.md). Ý tưởng 6 tầng và tính mới: [`04_kien-truc-cp-abe-v4.md`](04_kien-truc-cp-abe-v4.md).
> Trạng thái: **đã chốt** D1–D8 (2026-10-10). Mọi quyết định theo phương án mặc định đề xuất.

---

## 1. Thành phần

| Container / tool | Vùng | Công nghệ (đề xuất) | Trách nhiệm | Giữ bí mật |
|---|---|---|---|---|
| `owner-cli` | Client | Python | Biên dịch Cedar → policy ABE, mã hóa (encaps + cAEAD), gọi keyvault để wrap/sign, gửi bản ghi | — (CEK chỉ nằm trong RAM) |
| `user-cli` | Client | Python | Xin SK, đọc bản ghi, xác minh (checkpoint, inclusion, owner_sig), giải mã | SK_u |
| `gateway` | Tin cậy | FastAPI | AuthN (token), revocation list, CRUD API, append entry RECORD | **Không có khóa mật mã** |
| `kgc` | Tin cậy | FastAPI + Charm | Setup, KeyGen, epoch, attr-version, revoke, append entry KEYGEN/REVOKE | MSK, sk_kgc |
| `keyvault` | Tin cậy | FastAPI | `wrap`, `unwrap` (KEK), `sign` (sk_DO), ghi log mỗi lần gọi | KEK, sk_DO |
| `worker` | Tin cậy | Python | Job re-wrap/re-encrypt, Revocation Planner, đo window | — |
| `storage` | Cloud | PostgreSQL 16 | Lưu `encrypted_records` | — |
| `translog` | Cloud | FastAPI + SQLite | Merkle log append-only, checkpoint, inclusion/consistency proof | sk_log |
| `auditor` | Độc lập | Python (cron) | Kiểm consistency, đồng ký checkpoint (witness), cảnh báo khóa lạ | sk_witness |
| HR Directory | Tin cậy | File `hr.json` (mock) | Nguồn thuộc tính `Dept`, `Role` | — |

---

## 2. API

### gateway `:8000`
| Method | Path | Ai gọi | Mô tả |
|---|---|---|---|
| PUT | `/records/{id}` | owner, worker | Tạo hoặc cập nhật bản ghi (`version+1`), append RECORD |
| PATCH | `/records/{id}/header` | owner, worker | Đổi policy hoặc re-wrap: chỉ thay `abe_header` + `owner_sig` |
| DELETE | `/records/{id}` | owner | Xóa, append RECORD(op=delete) |
| GET | `/records/{id}` | user, worker | Trả về EncryptedRecord + `log_index` (chặn nếu user nằm trong revocation list) |
| GET | `/records?policy_attr=...` | worker | Liệt kê bản ghi có thuộc tính X trong policy (phục vụ R2) |
| POST | `/internal/revocations` | kgc | Cập nhật revocation list |

### kgc `:8001`
| Method | Path | Mô tả |
|---|---|---|
| GET | `/mpk`, `/epoch`, `/attr-versions` | Tham số công khai |
| POST | `/keys` | Cấp SK cho user đang đăng nhập (lấy thuộc tính từ HR) → trả `SK_u + log_index` |
| POST | `/revoke` | `{user}` → R1; `{user, attr}` → R2. Tạo job cho worker |

### keyvault `:8002` (chỉ nhận request từ owner-cli và worker)
| Method | Path | Mô tả |
|---|---|---|
| POST | `/wrap` | `CEK → kek_header` |
| POST | `/unwrap` | `kek_header → CEK` |
| POST | `/sign` | `digest → owner_sig` |
| GET | `/pk_do` | Khóa công khai của owner |

### translog `:8003`
| Method | Path | Mô tả |
|---|---|---|
| POST | `/entries` | Append entry (chỉ kgc và gateway được gọi) → `log_index` |
| GET | `/checkpoint` | Checkpoint mới nhất (`size, root, time, sig_log, sig_witness[]`) |
| GET | `/proof/inclusion?index=&size=` | Inclusion proof |
| GET | `/proof/consistency?from=&to=` | Consistency proof |
| GET | `/entries?from=&to=` | Đọc entry (auditor, user tự giám sát khóa của mình) |
| POST | `/cosign` | Witness gửi chữ ký đồng thời cho một checkpoint |

---

## 3. Mô hình dữ liệu

### EncryptedRecord (JSON lưu trong PostgreSQL)
```json
{
  "record_id": "BA-0001",
  "version": 3,
  "content_version": 2,
  "policy_ref": { "cedar_policy_id": "read-clinical", "policy_hash": "sha256:..." },
  "policy_abe": "(DEPTXCARDIOLOGYXV1 and ROLEXDOCTORXV1) and EPOCHX7",
  "abe_backend": "fame-bn254-k2-v1",
  "abe_header": { "kem": { "...": "JSON an toàn, không pickle" }, "wrap": "base64(nonce + AES-GCM(k_abe, CEK, header_aad))" },
  "kek_header": "base64...",
  "aead": { "alg": "AES-256-GCM+HMAC-commit", "nonce": "base64...", "commit": "base64..." },
  "ciphertext": "base64...",
  "owner_sig": "base64(Ed25519)"
}
```
- `data_aad = record_id || content_version` (commit + GCM của dữ liệu)
- `header_aad = record_id || version || abe_backend || policy_hash` (lớp bọc CEK bằng k_abe)
- `version` tăng ở mọi thay đổi; `content_version` chỉ tăng khi Update nội dung. Re-wrap / đổi policy chỉ đổi `abe_header` + `version`, dữ liệu giữ nguyên.
- `owner_sig` ký trên `H(mọi trường trừ owner_sig)`.
- `policy_abe` lưu ở dạng rõ, vì giải mã cần biết policy. *(Ẩn policy là phần mở rộng, chỉ có với backend covercrypt.)*

### Entry của transparency log
```json
{ "type": "KEYGEN", "user": "u-7f3a", "attrs_hash": "sha256:...", "epoch": 7, "attr_versions": {"Dept:Cardiology": 1}, "ts": "...", "sig_kgc": "..." }
{ "type": "REVOKE", "user": "u-7f3a", "attr": "Dept:Cardiology", "new_version": 2, "ts": "...", "sig_kgc": "..." }
{ "type": "RECORD", "record_id": "BA-0001", "version": 3, "op": "put", "record_hash": "sha256:...", "ts": "..." }
```
- `user` là pseudonym, tính bằng `HMAC(k_org, user_id)`, để log công khai không làm lộ danh tính.

### Checkpoint
```json
{ "size": 1024, "root": "sha256:...", "time": "...", "sig_log": "...", "sig_witness": ["..."] }
```

---

## 4. Các luồng chính

| Luồng | Sơ đồ | Kịch bản kiểm chứng |
|---|---|---|
| Cấp khóa | §8 | L1 (khóa lén) |
| Ghi (Create/Update) | §6 | A, K1, K2 |
| Đọc | §7 | B, F, F2, I1, I2 |
| Đổi policy | §6 (PATCH header) | P1 |
| Xóa | §6 (DELETE) | — |
| Thu hồi | §9 | C1, C2, C3 |
| Giám sát log | §5 | L2 |
| Đổi backend | — | X (mở rộng) |

**Kịch bản mới F2:** ghép khóa cũ (trước khi thu hồi) với khóa mới của cùng một user. Kỳ vọng: thất bại.

---

## 5. Threat model áp vào từng container

| Container bị chiếm | Kẻ tấn công làm được | Hệ thống phát hiện / ngăn |
|---|---|---|
| storage | Đọc, sửa, xóa, rollback, tráo bản ghi | Đọc: chỉ thấy ciphertext. Sửa/tráo: owner_sig + AAD + commit. Rollback: so với log. Xóa: phát hiện được (bản ghi có trong log nhưng không còn trong DB), không ngăn được |
| translog | Viết lại lịch sử, cho mỗi người xem một bản log khác nhau (split-view) | Thiếu sig_witness hoặc consistency proof thất bại |
| gateway | Bỏ qua revocation list, trả dữ liệu cũ | Lớp mật mã vẫn chặn (epoch/version). Dữ liệu cũ bị phát hiện qua log. **Không lộ dữ liệu** vì gateway không có khóa |
| worker | Gọi unwrap/sign tùy ý | ⚠️ Lấy được CEK và ký được bản ghi. Mọi lần gọi đều có log ở keyvault. *Giả định tin cậy* |
| keyvault / kgc | Toàn quyền | ⚠️ Giả định tin cậy. Riêng kgc: cấp khóa lén thì bị log phát hiện |

---

## 6. Quyết định (đã chốt 2026-10-10 — tất cả theo cột "Mặc định đề xuất")

| # | Quyết định | Mặc định đề xuất | Phương án khác | Ghi chú |
|---|---|---|---|---|
| D1 | Ngôn ngữ / thư viện ABE | **Python + Charm-crypto** (`ac17` = FAME), BN254, chạy trong Docker | Rust `rabe` | Charm cần build PBC/GMP, nên dùng image Python 3.9 |
| D2 | Storage giả lập cloud | **PostgreSQL** | MinIO (object storage) | Postgres dễ demo hơn cho kịch bản "DBA" |
| D3 | Transparency log | **Tự viết** (Merkle kiểu RFC 6962, khoảng 300 dòng) | Trillian / Tessera | Tự viết thì dễ kiểm soát và dễ giải thích hơn |
| D4 | Cedar compiler | **Tự viết cho tập con Cedar** (`==`, `&&`, `\|\|`, `in`), dùng `cedarpy` làm authorizer tham chiếu trong kiểm thử tương đương | Partial eval của `cedar-policy` | Partial eval đang experimental, chưa chắc dùng được từ Python |
| D5 | Keyvault | **Service tự viết** (wrap/unwrap/sign, khóa lưu trong file mã hóa) | HashiCorp Vault dev mode | Vault thật thì phải thêm cấu hình |
| D6 | AuthN | **Token tĩnh theo user** trong `users.json` | OIDC (Keycloak) | Không phải trọng tâm của đồ án |
| D7 | Backend mở rộng | Chỉ làm `fame` trước; `covercrypt` để sau | Làm luôn `covercrypt` | Phụ thuộc thời gian |
| D8 | Client | **CLI** | Web UI | CLI đủ để demo và chạy test |
