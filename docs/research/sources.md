# Sổ nguồn tham khảo (research log)

Ghi lại **mọi nguồn đã tra cứu**, nội dung đã dùng, và **mức độ kiểm chứng**, để đối chiếu về sau.
Mỗi lần tra thêm nguồn thì thêm một dòng vào §1 và cập nhật [CHANGELOG](../../CHANGELOG.md).

Mức kiểm chứng:
- ✅ **Đã đọc trực tiếp**: đã mở trang/mã nguồn gốc và đối chiếu nội dung.
- 🟡 **Qua kết quả tìm kiếm**: chỉ thấy tóm tắt/metadata, chưa đọc bản gốc. Cần kiểm tra trước khi đưa lên slide.
- ❌ **Không truy cập được**.

---

## 1. Nhật ký tra cứu

| Ngày | Nguồn | Mức | Dùng cho | Ghi chú |
|---|---|---|---|---|
| 2026-10-11 | [ref/proposal.pdf](../../ref/proposal.pdf) | ✅ | Rà soát §1 | Bản đề xuất 16 slide của nhóm |
| 2026-10-11 | Cloudflare blog *Inside Geo Key Manager v2* (27/01/2023): https://blog.cloudflare.com/inside-geo-key-manager-v2 | ✅ | C1, C2, C4, §9 | Xem trích dẫn §2.1 |
| 2026-10-11 | CIRCL `tkn20` trên pkg.go.dev: https://pkg.go.dev/github.com/cloudflare/circl/abe/cpabe/tkn20 | ✅ | C1 (API) | Danh sách hàm ở §2.2 |
| 2026-10-11 | Mã nguồn CIRCL (commit `91db3e785ba2635b4f24a023e1ad76d2780e2865`), lưu tại [ref/snapshots/circl-tkn20/](../../ref/snapshots/circl-tkn20/) | ✅ | C1 (cú pháp policy) | §2.3 |
| 2026-10-11 | ETSI TS 103 532 V1.2.1 (2021-05): https://etsi.org/deliver/etsi_TS/103500_103599/103532/01.02.01_60/ts_103532v010201p.pdf | 🟡 | C1 (chuẩn hóa) | Đã xác nhận tên, phiên bản, ngày qua kết quả tìm kiếm; chưa đọc nội dung PDF |
| 2026-10-11 | ETSI TS 103 532 V1.1.1 (2018-03): https://etsi.org/deliver/etsi_TS/103500_103599/103532/01.01.01_60/ts_103532v010101p.pdf | 🟡 | Lịch sử chuẩn | Bản đầu tiên |
| 2026-10-11 | NIST STPPA6 (2023), trình bày về ETSI ABE: https://csrc.nist.gov/Presentations/2023/stppa6-abe | 🟡 | C1 | Theo tóm tắt: chuẩn hóa 4 lược đồ CP/KP-ABE |
| 2026-10-11 | Portunus – Cloudflare, Real World Crypto 2023: https://research.cloudflare.com/publications/Ladd2023b | ❌ (404) | C2 | Tên hệ thống và hội nghị chỉ thấy qua kết quả tìm kiếm. **Chưa xác nhận danh sách tác giả** |
| 2026-10-11 | Penuelas-Angulo, Feregrino-Uribe, Morales-Sandoval, *Revocation in ABE for fog-enabled IoT: A systematic survey*, Internet of Things vol. 23, 2023, DOI 10.1016/j.iot.2023.100827: https://portalcientifico.unav.edu/documentos/6a07f911df850a0fb69da48e | 🟡 | C4 | Chỉ thấy metadata, chưa đọc abstract |
| 2026-10-11 | Al-Dahhan et al., *Survey on Revocation in CP-ABE*, Sensors 2019, DOI 10.3390/s19071695: https://www.ncbi.nlm.nih.gov/pmc/articles/PMC6479996/ | 🟡 | C4 (nền) | Cũ hơn 5 năm, chỉ để tham khảo phân loại |
| 2026-10-11 | Hwang & Lee, *A Study on CP-ABE Based Data Sharing System That Provides Signature-Based Verifiable Outsourcing*, AEIS 2021: https://archive.cps-vo.org/node/83354 | 🟡 | (chưa dùng) | Về outsourced decryption có kiểm chứng, không phải quyền ghi |
| 2026-10-11 | *Access Control Scheme Supporting Attribute Revocation in Cloud Computing*, NaNA 2021, DOI 10.1109/NaNA53684.2021.00072: https://archive.cps-vo.org/node/81465 | 🟡 | C2/C4 (đối chứng) | Theo tóm tắt: CP-ABE chỉ mã hóa khóa đối xứng, nên thu hồi chỉ cập nhật bản mã của khóa. Cùng hướng với C2 |
| 2026-10-11 | Bài 2017 (scitepress) tổng hợp CP-ABE + ABS cho đọc/ghi, dẫn Zhao et al. 2011, Ruj et al.: https://www.scitepress.org/Papers/2017/63496/63496.pdf | 🟡 | C3 (nguồn ý tưởng) | Chưa đọc bản gốc Zhao et al. 2011 |
| 2026-10-11 | Yang et al., ASIACCS 2010 (proxy re-encryption + CP-ABE): https://ubisec.cse.buffalo.edu/cloud/papers/ASIACCS10-sharing.pdf | 🟡 | §11 (lý do không làm) | Cũ, chỉ tham khảo |
| 2026-10-11 | Bài tiếng Trung *支持云代理重加密的CP-ABE方案* (CP-ABE-CPRE, Acta Electronica Sinica): https://www.ejournal.org.cn/rc-pub/front/front-article/download/34822451/lowqualitypdf/支持云代理重加密的CP-ABE方案.pdf | 🟡 | §11 | Thu hồi bằng version trên khóa và bản mã, cloud cập nhật phần liên quan thuộc tính bị thu hồi. **Chưa rõ năm xuất bản** |
| 2026-10-11 | GoFE (fentec-project), lược đồ FAME: https://pkg.go.dev/github.com/fentec-project/gofe | 🟡 | Phương án thư viện thay thế | Tự ghi là "chưa ổn định, chỉ cho nghiên cứu/PoC". Không chọn |
| 2026-10-11 | godocs.io (bản mirror tài liệu CIRCL) | ❌ | — | Bị chặn (Anubis) |

---

## 2. Trích dẫn và dữ kiện đã kiểm chứng

### 2.1 Cloudflare – Inside Geo Key Manager v2 (27/01/2023)

- Một authority trung tâm chạy Setup và giữ master secret key. Máy chủ trình thuộc tính, authority đối chiếu với CSDL provisioning rồi cấp khóa ABE riêng.
- Khóa được cấp khi máy khởi động, khi xoay vòng khóa, hoặc **khi thuộc tính thay đổi**, và "never in the critical path of a TLS handshake".
- Chính sách dạng chuỗi, ví dụ `country: JP or (not region: EU)`, hỗ trợ AND/OR/NOT.
- **Policy key:** mỗi chính sách có một cặp khóa X25519. Private key được mã hóa ABE theo chính sách, còn dữ liệu (TLS private key của khách hàng) được mã hóa bằng public policy key. Bài viết gọi đây là "similar to hybrid encryption". → **Nguồn của C2.**
- Xoay vòng khóa theo nhiều thế hệ: thế hệ mới nhất dùng để mã hóa, thế hệ mới nhất và thế hệ trước dùng để giải mã. Khi xoay master key, **chỉ policy key cần mã hóa lại**, không phải từng khóa khách hàng. → **Nguồn của C4 (thế hệ).**
- Bài viết **không** mô tả cơ chế thu hồi riêng ngoài việc cấp lại khóa.
- Hiệu năng (Intel i7-10610U, **50 thuộc tính, trường hợp xấu nhất**): sinh khóa 1796 ms, mã hóa 23 byte 704 ms, giải mã 62.4 ms. Secret key 33,416 B, public key 3,282 B, ciphertext overhead ~19,419 B.
- Hạn chế tự nêu: chậm và lớn hơn nhiều so với RSA/X25519. Tác giả không biết hệ thống kiểm soát truy cập bằng ABE quy mô lớn nào khác. Chứng minh an toàn end-to-end được hẹn ở một bài sau.

### 2.2 CIRCL `abe/cpabe/tkn20`: API (pkg.go.dev, module v1.6.5)

- `Setup(rand) (PublicKey, SystemSecretKey, error)`
- `(*PublicKey) Encrypt(rand, policy Policy, msg []byte) ([]byte, error)`. Trong mã nguồn gọi `tkn.EncryptCCA`, tức biến thể CCA.
- `(*SystemSecretKey) KeyGen(rand, attrs Attributes) (AttributeKey, error)`
- `(*AttributeKey) Decrypt(ct []byte) ([]byte, error)`
- `(*Policy) FromString(str)`, `Satisfaction(attrs)`, `ExtractFromCiphertext(ct)`, `ExtractAttributeValuePairs()`
- `(*Attributes) FromMap(map[string]string)`, `CouldDecrypt(ct) bool`
- Mọi khóa đều có `MarshalBinary` / `UnmarshalBinary`
- Tài liệu gói: CP-ABE dựa trên Tomida–Kawahara–Nishimaki, có biến thể IND-CCA2.

### 2.3 CIRCL: cú pháp chính sách (đọc từ mã nguồn, xem `ref/snapshots/circl-tkn20/`)

- Từ khóa trong `dsl_lexer.go`: `and`, `or`, `not`.
- Ký tự hợp lệ của tên/giá trị (`dsl_util.go`): `a-z`, `A-Z`, `_`, `0-9`. Vì vậy `dept_finance: v3` hợp lệ, còn dấu `.` hoặc `-` thì **không**.
- `Attributes.FromMap` nhận `map[string]string`, nên **mỗi tên thuộc tính chỉ có một giá trị**. Thiết kế dùng giá trị làm số phiên bản và tên làm thuộc tính (vd. `dept_finance`), tránh kiểu `dept: finance` (không biểu diễn được user thuộc 2 phòng ban).
- Ví dụ trong `example_test.go`: `(occupation: doctor) and (country: US)`.
- `go.mod` của CIRCL (main) yêu cầu `go 1.25.0`. Dockerfile cần image Go ≥ 1.25, hoặc ghim bản CIRCL cũ hơn tương thích.

---

## 3. Việc cần kiểm chứng thêm (trước khi đưa lên slide)

- [ ] Năm và hội nghị của TKN20 (kết quả tìm kiếm ghi PKC 2020), tên bài chính xác.
- [ ] Danh sách tác giả và link chính thức của Portunus (RWC 2023).
- [ ] Đọc abstract survey Penuelas-Angulo et al. 2023 để chắc chắn có phân loại *attribute-level revocation*.
- [ ] Thông tin trích dẫn đầy đủ của Zhao et al. 2011 (read/write CP-ABE + ABS).
- [ ] Đọc mục lục ETSI TS 103 532 V1.2.1: các lược đồ được chuẩn hóa.
- [ ] Xác nhận `Encrypt` của CIRCL nhận được thông điệp độ dài bất kỳ (thiết kế chỉ mã hóa private key 32 byte nên không phụ thuộc điểm này).
