# Kết quả đo C1 (21/10/2026 16:13, 16 nhân CPU)

## Chi phí từng thao tác (trung vị 30 lần, ms)

| Thao tác | Ký hiệu | ms |
|---|---|---|
| CP-ABE Encrypt private key 32 byte, chính sách 2 thuộc tính | c_abe | 28.362 |
| CP-ABE Decrypt | c_abe_dec | 11.427 |
| CP-ABE KeyGen, 3 thuộc tính | c_keygen | 50.497 |
| Bọc DEK (X25519 sealed box) | c_seal | 0.113 |
| Mở DEK (X25519 sealed box) | c_open | 0.076 |
| AES-256-GCM mã hóa nội dung (1276 byte) | c_aead | 0.002 |
| AES-256-GCM giải mã | c_aead_dec | 0.007 |
| Ed25519 ký | c_sign | 0.019 |
| Ed25519 kiểm | c_verify | 0.045 |

Tỉ lệ c_abe / c_seal ≈ 250 lần.

## Thu hồi 1 thuộc tính theo số tài liệu D (chạy thật, ms; P_read=2, P_write=1, U=2)

| D | Cách cũ: U KeyGen + D × CP-ABE | Lazy, L=0 | Lazy, L=3 | Eager | Hai pha + re-key (pha 2) |
|---|---|---|---|---|---|
| 4 | 217.810 | 187.126 | 355.677 | 187.888 | 0.900 (pha 1 = Lazy L=0) |
| 10 | 384.498 | 184.267 | 357.704 | 186.186 | 2.256 (pha 1 = Lazy L=0) |
| 100 | 2889.440 | 187.602 | 354.120 | 211.887 | 28.757 (pha 1 = Lazy L=0) |
| 1000 | 28162.881 | 183.324 | 352.447 | 372.739 | 224.040 (pha 1 = Lazy L=0) |

Điểm hòa vốn số lần CP-ABE: D > P_read·(1+L) + P_write = 3 (L=0), 9 (L=3).

## Đọc N tài liệu cùng chính sách (ms)

| N | Không cache: N × (CP-ABE + mở) | Có cache: 1 CP-ABE + N × mở |
|---|---|---|
| 1 | 11.439 | 11.341 |
| 10 | 112.713 | 12.421 |
| 100 | 1138.858 | 23.847 |

## Thu hồi dept_finance của Bình trên stack Docker (gồm mạng + PostgreSQL, ms)

Tài liệu thêm vào đều dùng chính sách của Báo cáo Q3. Pha 2 tính từ lúc gửi yêu cầu thu hồi tới lúc pha 2 ghi audit.

| Tổng tài liệu | Chế độ | Trả lời thu hồi (pha 1) | Xong pha 2 |
|---|---|---|---|
| 4 | lazy | 262.164 | — |
| 4 | eager | 244.169 | — |
| 4 | twophase | 230.828 | 241.869 |
| 4 | rekey | 225.642 | 237.091 |
| 104 | lazy | 228.145 | — |
| 104 | eager | 410.722 | — |
| 104 | twophase | 232.946 | 416.113 |
| 104 | rekey | 235.655 | 479.379 |
| 1004 | lazy | 238.489 | — |
| 1004 | eager | 1974.774 | — |
| 1004 | twophase | 234.450 | 1986.649 |
| 1004 | rekey | 229.044 | 2616.146 |

## Kịch bản DEK đã lưu: Bình đọc Báo cáo Q3, lưu DEK + private Policy Key + bản mã, rồi bị thu hồi dept_finance

### CLOUD_ENFORCE_READ=false

| Chế độ | (1) DEK đã lưu + bản mã đã tải | (2) Tải lại từ cloud | (3) DEK đã lưu + bản mã tải lại | (4) Policy Key cũ + wrapped_dek tải lại |
|---|---|---|---|---|
| lazy | ĐỌC ĐƯỢC | cloud trả bản mã | ĐỌC ĐƯỢC | ĐỌC ĐƯỢC |
| eager | ĐỌC ĐƯỢC | cloud trả bản mã | ĐỌC ĐƯỢC | không |
| twophase | ĐỌC ĐƯỢC | cloud trả bản mã | ĐỌC ĐƯỢC | không |
| rekey | ĐỌC ĐƯỢC | cloud trả bản mã | không (bản mã đã đổi) | không |

### CLOUD_ENFORCE_READ=true

| Chế độ | (1) DEK đã lưu + bản mã đã tải | (2) Tải lại từ cloud | (3) DEK đã lưu + bản mã tải lại | (4) Policy Key cũ + wrapped_dek tải lại |
|---|---|---|---|---|
| lazy | ĐỌC ĐƯỢC | cloud không trả bản mã | — | — |
| eager | ĐỌC ĐƯỢC | cloud không trả bản mã | — | — |
| twophase | ĐỌC ĐƯỢC | cloud không trả bản mã | — | — |
| rekey | ĐỌC ĐƯỢC | cloud không trả bản mã | — | — |

