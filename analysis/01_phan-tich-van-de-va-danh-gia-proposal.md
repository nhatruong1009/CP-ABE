# Phân tích vấn đề Outsourced Database & đánh giá Proposal CP-ABE (Nhóm 06)

> ⚠️ **Phần 4 của file này đã được thay thế** bằng thiết kế v3 trong [`02_ke-hoach-cai-thien-1-tuan.md`](02_ke-hoach-cai-thien-1-tuan.md) (lịch sử thay đổi: [`logs/design-changelog.md`](../logs/design-changelog.md)). Phần 1–3 vẫn giữ nguyên giá trị.

> Nguồn đầu vào: `ref/Security-Issues-in-Outsourced-XML-Databases.pdf` (Tran Khanh Dang, ~2009) và `ref/proposal.pdf` (16 slide).
> Phạm vi "tính mới": **10/2021 → 10/2026** (5 năm gần đây).
> Định hướng: đồ án **ứng dụng**, nên bỏ qua các chứng minh toán học, chỉ giữ ý tưởng, kiến trúc và cách đo đạc.
> Danh mục paper: [`papers/README.md`](../papers/README.md).

---

## Phần 1. Các vấn đề của Outsourced Database và giải pháp hiện tại

### 1.1 Bối cảnh (theo chương sách của Dang)

- Có **hai mô hình outsource**. Ở *housing* (thuê chỗ đặt máy), DBA vẫn thuộc về chủ dữ liệu. Ở *hosting*, tức mô hình ODBS hay DBaaS hiện nay, **DBA thuộc nhà cung cấp**. Chính điều này sinh ra hầu hết các vấn đề bảo mật.
- Mô hình có ba bên: **Data Owner (DO)**, **Service Provider (SP)** và **Client**.
- Có bốn kịch bản truy cập, xếp theo độ khó tăng dần:

| Mô hình | Mô tả | Ghi chú |
|---|---|---|
| **SS** | 1 owner, cũng là client duy nhất | Đa số nghiên cứu chỉ giải quyết mô hình này |
| **MS** | Nhiều owner, mỗi owner là client của dữ liệu mình | |
| **SMS** | 1 owner, **nhiều client** | Phức tạp nhất về bảo mật. **Đây là use case bệnh viện của proposal** |
| **MMS** | Nhiều owner, nhiều client | |

### 1.2 Sáu nhóm vấn đề (5 nhóm của Dang và 1 vấn đề xuyên suốt)

| # | Vấn đề | Nội dung cốt lõi |
|---|---|---|
| **P1** | **Data confidentiality** | Người ngoài **và cả DBA/nhân viên của SP** không được thấy nội dung dữ liệu, kể cả lúc server đang xử lý truy vấn. |
| **P2a** | **User privacy** | Server không được biết user truy vấn gì, nhận được kết quả gì, đôi khi cả user là ai. |
| **P2b** | **Data privacy** | User không được lấy nhiều dữ liệu hơn phần mình được phép hoặc đã trả tiền. Đây là bài toán khó nhất ở SMS/MMS. |
| **P3** | **Query assurance** | Kết quả truy vấn phải **đúng** (không bị sửa, đúng nguồn từ DO), **đủ** (không bị bỏ sót bản ghi) và **mới** (lấy từ bản dữ liệu mới nhất, không bị rollback). |
| **P4** | **Secure auditing** | Phải kiểm toán và quy trách nhiệm được (SOX, HIPAA, PCI…). Yêu cầu này **mâu thuẫn với privacy**. |
| **P5** | **Secure & efficient storage** | Mã hóa theo độ mịn hợp lý: không mã hóa thừa, index vẫn dùng được, không làm giảm hiệu năng quá mức. |
| **P6** (xuyên suốt) | **Rò rỉ qua cấu trúc và mẫu truy cập** | Dữ liệu dạng cây (B+-tree, XML) để lộ đường duyệt cây. Server ghép dần các lần truy cập là dựng lại được cấu trúc và suy ra nội dung (inference/linking attack). |

Kết luận của chương: chưa giải pháp nào giải quyết **đồng thời** các yêu cầu (integrated assurance). Phần lớn giải pháp chỉ áp dụng cho mô hình SS. Riêng **SMS/MMS mà không cần bên thứ ba tin cậy (TTP)** vẫn là câu hỏi mở.

### 1.3 Mapping: vấn đề → giải pháp trong chương (~2009) → giải pháp hiện tại (2021–2026)

| Vấn đề | Giải pháp trong chương (2000–2008) | Hạn chế được nêu | Giải pháp/xu hướng hiện tại |
|---|---|---|---|
| **P1 Confidentiality** | Mã hóa trước khi outsource (Hacigümüş 2002, Damiani 2003). Chia dữ liệu cho nhiều SP không thông đồng (Aggarwal 2005). | Mã hóa thì khó truy vấn. Giả định các SP không thông đồng là phi thực tế. | **Client-side / field-level encryption** kết hợp envelope encryption qua KMS/HSM. **TEE** (Intel SGX/TDX, AMD SEV, AWS Nitro) thay cho secure coprocessor. SQL Server *Always Encrypted with secure enclaves*. MongoDB *Queryable Encryption* (2023). **ABE** (NIST IR 8450, 2023; ETSI TS 103 532 v1.2.1, 2021). |
| **P2a User privacy** | PIR (Chor 1995). Duyệt cây "oblivious" bằng access redundancy và node swapping (Lin & Candan 2004; Dang 2005/2006). | PIR một server rất tốn kém. Cách của Lin & Candan chỉ hỗ trợ search. | **ORAM** (Path ORAM và các biến thể). **PIR một server thực dụng** (SimplePIR, 2023). Nghiên cứu về **leakage-abuse attack** cho thấy chỉ riêng rò rỉ *access pattern/volume* đã đủ khôi phục truy vấn (Blackstone 2020; VAL, ESORICS 2022). |
| **P2b Data privacy (đa client)** | SPIR. Giao thức qua **TTP** (Dang 2006b). Secure coprocessor IBM 4758. | TTP khó tìm trong thực tế. Phần cứng yếu (99 MHz, 2 MB). | **Kiểm soát truy cập thực thi bằng mật mã: CP-ABE / MA-ABE**. TEE làm "TTP phần cứng" hiện đại. Đây là chỗ **proposal đặt chân vào**. |
| **P3 Query assurance** | Condensed-RSA, Merkle Hash Tree, DSAC (chuỗi chữ ký), challenge token (Sion 2005). Nested Merkle B+-Tree (Nguyen & Dang 2008). Timestamp trong node cha để bảo đảm freshness (Dang & Son 2006). | Tính toán phía client nặng. Completeness và freshness khó bảo đảm. | **Authenticated Data Structures** và Merkle tree vẫn là nền tảng. **Ledger database** (Azure SQL Ledger). Nhật ký append-only kiểu transparency log. **Blockchain** để kiểm toán và xác minh kết quả (BA-ORABE 2024; ABE với outsourced decryption có ZK proof, 2024). |
| **P4 Secure auditing** | Gần như chưa có lời giải, chỉ có cách qua TTP (Dang 2006b). | Mâu thuẫn giữa privacy và accountability. | Audit log chống sửa (hash-chain, ledger, blockchain). **ABE truy vết được (traceable/accountable ABE)** giúp tìm ra ai làm lộ khóa (2024–2026). |
| **P5 Efficient storage** | Iyer 2004: nhóm các trường nhạy cảm để mã hóa chung, không mã hóa trường không nhạy cảm. | Vẫn giả định server tin cậy. | **Hybrid encryption** (KEM–DEM): mã hóa dữ liệu bằng AES-GCM, chỉ mã hóa khóa bằng thuật toán bất đối xứng hoặc ABE. Mã hóa theo trường hoặc nhóm cột. Blind index (HMAC) cho truy vấn bằng. |
| **P6 Rò rỉ cấu trúc** | Mã hóa nguyên node. Node swapping. | Overhead lớn. | ORAM, volume-hiding. Ẩn chính sách trong ABE (**policy-hiding**): trong ABE, *bản thân policy công khai cũng là một kênh rò rỉ*. |

> **Nhận xét quan trọng cho đồ án:** chương của Dang nêu rằng *"loại bỏ TTP (K) mà vẫn bảo đảm các mục tiêu ở mô hình SMS/MMS là câu hỏi mở"*. CP-ABE trả lời **một phần** câu hỏi này: phần *kiểm soát ai được đọc gì* không còn cần một bên online đứng ra lọc dữ liệu, vì việc lọc được "nhúng" vào bản mã. Đổi lại, vẫn cần một **Key Authority** offline được tin cậy. Đây là luận điểm mạnh nhất để định vị proposal so với tài liệu tham khảo.

---

## Phần 2. Proposal đã giải quyết được vấn đề gì?

### 2.1 Tóm tắt proposal

- **Bài toán:** bệnh viện outsource hồ sơ bệnh án lên cloud, trong khi nhà cung cấp có toàn quyền quản trị. Vì vậy phân quyền DBMS, TDE và kiểm soát ở tầng ứng dụng đều mất tác dụng.
- **Giải pháp:** CP-ABE (Bethencourt–Sahai–Waters 2007) theo kiểu **lai**. Dữ liệu được mã hóa đối xứng bằng CEK, sau đó CEK được mã hóa bằng CP-ABE kèm policy (ví dụ: `(Dept=Cardiology AND Role=Doctor) OR Role=CMO`).
- **Kiến trúc:** Client App mã hóa và giải mã cục bộ. App Server chỉ trung chuyển. KGC giữ MSK và cấp SK. Cloud chỉ lưu ciphertext cùng policy công khai.
- **Thu hồi quyền:** đưa ra 3 phương án là attribute versioning, lazy re-encryption và time-bound keys.
- **Kiểm chứng:** 3 kịch bản tấn công. A (DBA đọc trực tiếp) và B (y tá vượt quyền) an toàn. C (nhân viên đã nghỉ việc) còn "cần đánh giá thêm".

### 2.2 Đối chiếu với 6 vấn đề

| Vấn đề | Mức độ giải quyết | Giải thích |
|---|---|---|
| **P1 Confidentiality** | ✅ **Giải quyết tốt** (trước SP/DBA/attacker) | Cloud chỉ giữ ciphertext. Không có SK phù hợp thì không giải mã được. Kịch bản A minh họa đúng điểm này. ⚠️ Nhưng **KGC giữ MSK nên giải mã được mọi thứ** (key escrow). Confidentiality chỉ đúng khi KGC trung thực. |
| **P2b Data privacy giữa các client (SMS)** | ✅ **Giải quyết phần kiểm soát truy cập** | Mỗi client chỉ giải mã được phần thỏa policy: bác sĩ, y tá và thu ngân thấy các phần khác nhau (kịch bản B). Việc này **không cần TTP online**, và đây là đóng góp chính so với chương của Dang. ❌ Nghĩa "không lấy thừa dữ liệu" (user tải về cả ciphertext không thuộc quyền mình) thì chưa xét. |
| **P5 Efficient storage** | 🟡 **Một phần** | Mã hóa lai (CEK) là đúng hướng. Policy được đặt **theo từng trường dữ liệu nhạy cảm**, giống ý tưởng nhóm trường của Iyer 2004. Nhưng proposal chưa thiết kế: mỗi bản ghi có bao nhiêu ciphertext, nhóm trường thế nào, chi phí lưu trữ ra sao. |
| **P2a User privacy** | ❌ Không | Cloud vẫn thấy ai truy vấn bản ghi nào và khi nào. **Policy để công khai còn làm lộ thêm metadata**: thấy `Dept=Oncology` là đoán được bệnh nhân đang điều trị ung thư. |
| **P3 Query assurance** | ❌ Không (tự khai là ngoài phạm vi) | Không có cơ chế chống sửa, chống bỏ sót bản ghi hay chống rollback. |
| **P4 Auditing** | ❌ Không | Không có log cấp khóa và không có log truy cập chống sửa. |
| **P6 Rò rỉ cấu trúc/mẫu truy cập** | ❌ Không | "Tìm kiếm trên dữ liệu mã hóa" nằm ngoài phạm vi, nên hệ thống thực chất là **outsourced storage** chứ chưa phải **outsourced database**. |

**Kết luận phần 2:** proposal giải quyết chắc **P1** và **phần kiểm soát truy cập của P2b** cho mô hình **SMS**, với vai trò TTP được thay bằng mật mã. Đó là hai vấn đề cốt lõi và có giá trị. Bốn vấn đề còn lại chưa được xử lý.

### 2.3 Các điểm chưa nhất quán hoặc thiếu sót trong proposal (nên sửa trước khi làm PoC)

1. **Threat model tự mâu thuẫn.** Proposal giả định cloud là *honest-but-curious*, nhưng lại liệt kê "admin lạm quyền, cấu hình sai" và kết luận "an toàn **kể cả khi host bị xâm nhập hoàn toàn**". Host bị xâm nhập hoàn toàn là **malicious**, tức có thể sửa, xóa hoặc thay ciphertext.
2. **Lỗ hổng giả mạo dữ liệu (quan trọng).** Trong CP-ABE, **MPK là công khai**, nên *bất kỳ ai*, kể cả admin cloud, cũng có thể tạo một bản ghi giả với policy hợp lệ. Bác sĩ vẫn giải mã ra "bệnh án" đó bình thường. CP-ABE **chỉ bảo đảm bí mật, không bảo đảm nguồn gốc**. Cần thêm chữ ký của Data Owner, nếu không thì kịch bản "host bị xâm nhập" không an toàn về toàn vẹn. Lỗ hổng này nối thẳng sang P3 của Dang.
3. **Collusion bị đưa ra "ngoài phạm vi" là không cần thiết.** Chống thông đồng (hai user ghép khóa của nhau) là **tính chất có sẵn của CP-ABE** (BSW07). Nên chuyển nó thành *tính chất được bảo đảm* và thêm một kịch bản kiểm thử, thay vì loại trừ.
4. **Bảng so sánh ở slide 5** ghi chi phí thu hồi của CP-ABE là "Cao". Nhưng RQ2 lại đặt mục tiêu thu hồi hiệu quả, mà chưa có phương án cụ thể nào được chọn.
5. **Ba phương án thu hồi đều là kỹ thuật cũ** (khoảng 2003–2010), không thuộc 5 năm gần đây. Proposal chỉ liệt kê mà chưa chọn hoặc kết hợp. Proposal cũng chưa nói rõ một giới hạn có sẵn: *dữ liệu và CEK user đã giải mã trước đó thì không thể thu hồi*.
6. **KGC vừa là điểm lỗi duy nhất (SPOF) vừa là điểm escrow**, lại được giả định "luôn sẵn sàng". Proposal chưa nói MSK được lưu ở đâu (HSM? Vault?) và có ghi log cấp khóa hay không.
7. **Ranh giới tin cậy của App Server chưa rõ.** Nếu App Server chạy trên cloud thì nó nằm trong vùng không tin cậy.
8. **Không có trường hợp truy cập khẩn cấp (break-glass).** Đây là yêu cầu bắt buộc trong y tế: bác sĩ cấp cứu không có thuộc tính "Cardiology" vẫn phải đọc được hồ sơ.
9. **Toàn bộ tài liệu tham khảo thuộc giai đoạn 2005–2013.** Proposal không có nguồn nào trong 5 năm gần đây, nên chưa có căn cứ để khẳng định tính mới.
10. **RQ3 (đánh đổi hiệu năng) chưa có phương pháp đo**: chưa chọn thư viện, đường cong elliptic hay chỉ số đo.

---

## Phần 3. Đánh giá tính mới (mốc 10/2021 – 10/2026)

### 3.1 Từng thành phần có mới không?

| Thành phần trong proposal | Nguồn gốc | Mới trong 5 năm? |
|---|---|---|
| CP-ABE (BSW) | 2007 | ❌ |
| Mã hóa lai CEK + ABE | Có từ khi ABE ra đời (KEM–DEM) | ❌ |
| CP-ABE cho hồ sơ y tế trên cloud | Li et al. 2013 (PHR) và hàng trăm bài sau đó | ❌ |
| Attribute versioning / lazy re-encryption / time-bound keys | ~2003–2010 | ❌ |
| Multi-authority, outsourced decryption, ABSE (ở phần hướng phát triển) | 2011–2014 | ❌ (chỉ được liệt kê, chưa dùng) |
| Ánh xạ RBAC/ABAC → policy CP-ABE (RQ1) | Có nhiều nghiên cứu cũ | 🟡 Mới nếu làm thành **công cụ hoặc quy trình chuyển đổi** cụ thể |

**Đánh giá tổng thể: tính mới hiện ở mức THẤP (khoảng 2/10).** Proposal hiện là **bản tái hiện một kiến trúc kinh điển**. Với đồ án ứng dụng thì như vậy là chấp nhận được, nhưng proposal **chưa có thành phần nào thuộc 5 năm gần đây** và **chưa tận dụng các khoảng trống** mà chương của Dang chỉ ra.

### 3.2 Hiện trạng 2021–2026: những gì mới có thể khai thác

| Hướng | Tiến bộ chính (2021–2026) | Mức sẵn sàng để ứng dụng |
|---|---|---|
| **ABE kháng lượng tử + ẩn policy** | **Covercrypt** (ESORICS 2023), được chuẩn hóa thành **ETSI TS 104 015** (2025). Đây là KEM lai ECDH + ML-KEM, ẩn access policy, có truy vết. Bài phân tích bảo mật công bố năm 2025. | ⭐⭐⭐ Có thư viện Rust mã nguồn mở |
| **Chuẩn hóa và hướng dẫn triển khai** | NIST IR 8450 (2023). ETSI TS 103 532 v1.2.1 (2021). | ⭐⭐⭐ Dùng làm checklist triển khai |
| **Benchmark đúng cách** | ABE Squared (TCHES 2022), ABE Cubed (TCHES 2025). Hai bài chỉ ra nhiều benchmark cũ dùng đường cong không còn đủ an toàn. | ⭐⭐⭐ Dùng để trả lời RQ3 |
| **Kiểm tra lược đồ có bị phá không** | A Bunch of Broken Schemes (CT-RSA 2021): phá 11 lược đồ, trong đó có bản cài sẵn trong thư viện Charm. Công cụ ACABELLA (CCS 2023). | ⭐⭐ Tránh chọn nhầm lược đồ đã bị phá |
| **Bỏ key escrow** | Registered ABE (Eurocrypt 2023): user tự sinh khóa, không còn MSK. | ⭐ Còn nặng về lý thuyết (CRS tăng theo bình phương số user) |
| **Kiểm toán + outsourced decryption kiểm chứng được** | BA-ORABE (2024, blockchain + registered ABE). ABE với outsourced decryption có trả phí và ZK proof (2024). Verifiable outsourced ABE cho e-health (2024). | ⭐⭐ |
| **Phi tập trung / truy vết** | Decentralized CP-ABE chống lạm dụng khóa (2024). Traceable + revocable MA-ABE (2025–2026). | ⭐⭐ |
| **Thu hồi** | ABE proxy re-encryption có thu hồi trực tiếp (IEEE TDSC 2024). Lattice revocable ABE chống lộ khóa giải mã (2023). | ⭐⭐ |
| **Ẩn policy một phần** | Ẩn giá trị thuộc tính, chỉ để lộ tên thuộc tính (Tongxin Xuebao 2024). Đã có cảnh báo rằng nhiều lược đồ "hidden policy" vẫn lộ qua dictionary attack. | ⭐⭐ |
| **Tìm kiếm trên dữ liệu ABE** | ABKS kiểm chứng được cho PHR (2023). Keyword search có thu hồi cho e-health (IEEE TMC 2024). Cảnh báo từ leakage-abuse attack (VAL 2022). | ⭐⭐ |

---

## Phần 4. Hướng cải thiện đề xuất (theo hướng ứng dụng, khả thi cho PoC)

### 4.1 Định vị lại đóng góp ("câu chuyện tính mới")

> **Đề xuất tên/định vị mới:**
> *"Kiến trúc kiểm soát truy cập bằng CP-ABE **ẩn chính sách, sẵn sàng hậu lượng tử**, kèm **bảo đảm toàn vẹn và độ mới** và **thu hồi theo epoch**, cho hồ sơ bệnh án outsource theo mô hình SMS. Hệ thống được đánh giá định lượng theo phương pháp benchmark ABE hiện đại."*

Đóng góp mới **không nằm ở thuật toán**. Đóng góp nằm ở việc **tích hợp các kết quả 2021–2026 vào một hệ thống chạy được** và **đóng nhiều ô trống trong bảng 6 vấn đề của Dang** hơn so với kiến trúc kinh điển.

### 4.2 Các cải tiến cụ thể, xếp theo ưu tiên

#### 🔴 Bắt buộc (sửa lỗ hổng, chi phí thấp)

**C1. Chữ ký Data Owner + version: đóng P3 (correctness, freshness)**
- Mỗi bản ghi lưu `{ciphertext, policy, record_id, version, timestamp, sig_DO}`, trong đó `sig_DO` là chữ ký Ed25519 trên toàn bộ các trường còn lại.
- Client **xác minh chữ ký trước khi giải mã**. Cách này chặn được việc giả mạo bản ghi bằng MPK công khai (lỗ hổng 2.3-2).
- Freshness: duy trì một **Merkle root** hoặc **hash-chain** của tập bản ghi, có ký và đánh timestamp. Đây chính là ý tưởng "timestamp ở node cha" của Dang & Son (2006) và Nested Merkle B+-Tree (Nguyen & Dang 2008) được áp dụng lại. Cách này **kết nối trực tiếp với tài liệu của GVHD**.
- Có thể thay hash-chain tự xây bằng ledger table nếu dùng Azure SQL/PostgreSQL kèm extension.

**C2. Sửa threat model**
- Tách hai lớp: *honest-but-curious* về confidentiality và *malicious* về integrity, phát hiện được nhờ C1.
- Đưa collusion resistance vào nhóm *tính chất được bảo đảm*.
- Nêu rõ giới hạn: KGC là bên được tin cậy và giữ escrow; dữ liệu user đã giải mã thì không thu hồi được.

**C3. Chọn lược đồ và thư viện an toàn**
- Dùng lược đồ đã được kiểm chứng (BSW07, Waters11 hoặc FAME qua OpenABE, rabe, hoặc Charm với lược đồ không nằm trong danh sách bị phá).
- Dùng đường cong **BLS12-381**, không dùng BN254 hay các đường cong 80-bit cũ (khuyến nghị của ABE Squared).
- Nếu tự chọn biến thể, kiểm tra bằng **ACABELLA** (CCS 2023).

#### 🟠 Nên có (tạo tính mới rõ ràng)

**N1. Ẩn chính sách + kháng lượng tử với Covercrypt (ETSI TS 104 015, 2025): đóng một phần P2a/P6**
- Hồ sơ y tế cần giữ hàng chục năm, nên rủi ro *"harvest-now, decrypt-later"* là có thật. Đây là lập luận rất mạnh cho tính mới trong 5 năm gần đây.
- Thực hiện: **so sánh hai backend** trong cùng kiến trúc, (a) CP-ABE pairing kinh điển với policy công khai và (b) Covercrypt với policy ẩn và hybrid hậu lượng tử. Đo hiệu năng và kích thước bản mã của từng bên.
- Lưu ý về đánh đổi: Covercrypt diễn đạt policy theo "dimension/attribute" (ví dụ `Dept`, `Role`), kém linh hoạt hơn cây AND/OR tùy ý. Cần kiểm tra xem các policy bệnh viện có biểu diễn được không. Đây là một phần trả lời **RQ1** rất cụ thể.

**N2. Thu hồi theo epoch + chỉ bọc lại CEK: trả lời RQ2 và kịch bản C**
- Thêm thuộc tính thời gian (`epoch=2026-10`) vào policy. Khóa user chỉ có hiệu lực trong epoch (time-bound).
- Khi thu hồi gấp, **chỉ mã hóa lại CEK header** (vài trăm byte) với policy hoặc epoch mới, **không mã hóa lại dữ liệu**. Dữ liệu chỉ được mã hóa lại bằng CEK mới theo kiểu lazy, khi có lần ghi tiếp theo.
- Kết hợp **phòng thủ nhiều lớp**: App Server từ chối ngay user bị thu hồi (về mặt vận hành). Lớp mật mã bảo đảm an toàn ngay cả khi lớp vận hành bị vượt qua.
- Đo **"cửa sổ thu hồi"** (thời gian từ lúc thu hồi đến lúc khóa cũ hết tác dụng) và chi phí khi thu hồi 1, 10, 100 user. Kết quả này biến kịch bản C từ "cần đánh giá thêm" thành **số liệu cụ thể**.
- Tham khảo: ABPRE có thu hồi trực tiếp (IEEE TDSC 2024).

**N3. Đánh giá định lượng theo ABE Squared/Cubed: trả lời RQ3**
- Các chỉ số đo: thời gian Encrypt/Decrypt/KeyGen theo số thuộc tính trong policy (5, 10, 20, 50), kích thước ciphertext và SK, thông lượng khi đọc N bản ghi, chi phí thu hồi.
- Ghi rõ thư viện, đường cong và phần cứng để kết quả có thể so sánh được.

**N4. Audit log chống sửa + quản lý MSK: đóng một phần P4**
- MSK được lưu trong **HSM/Vault**, không lưu ở dạng file.
- Mọi thao tác KeyGen, thu hồi và truy cập đều ghi vào một **hash-chain log** có ký.
- Nếu muốn có tính mới cao hơn, đưa log lên một blockchain nhỏ hoặc ledger (theo hướng BA-ORABE 2024). Lưu ý đây là phần *tùy chọn* và tốn công.

#### 🟢 Mở rộng (nếu còn thời gian)

- **E1. Truy vấn tối thiểu.** Dùng blind index HMAC cho các trường định danh (mã bệnh nhân) để truy vấn bằng phía server. Phải nêu rõ rò rỉ: equality pattern và nguy cơ leakage-abuse (VAL 2022). Hướng này biến hệ thống từ *storage* thành *database* đúng nghĩa ODBS.
- **E2. Break-glass.** Thêm một policy nhánh `OR (Role=Emergency AND epoch=now)` với khóa khẩn cấp hiệu lực ngắn. Mọi lần dùng khóa này đều ghi vào audit log (N4).
- **E3. Công cụ ánh xạ RBAC/ABAC → policy (RQ1).** Đọc policy dạng bảng hoặc XACML đơn giản, sinh ra cây CP-ABE, và kiểm tra tự động rằng ma trận "vai trò × trường dữ liệu" được giữ nguyên ngữ nghĩa.
- **E4. Outsourced decryption** cho client di động (nếu có app mobile), theo các lược đồ verifiable 2024.
- **E5. Giảm escrow cho KGC.** Tách KGC theo hai authority, ví dụ "Phòng Nhân sự" cấp thuộc tính `Role` và "Khoa" cấp thuộc tính `Dept` (MA-ABE). Registered ABE (2023) chỉ nên nhắc tới như hướng nghiên cứu, vì còn quá nặng cho PoC.

### 4.3 Bảng "trước / sau" theo 6 vấn đề của Dang

| Vấn đề | Proposal hiện tại | Sau cải tiến |
|---|---|---|
| P1 Confidentiality | ✅ | ✅ + hậu lượng tử (N1) |
| P2a User privacy | ❌ | 🟡 policy ẩn (N1); mẫu truy cập vẫn lộ (nêu là giới hạn) |
| P2b Data privacy (SMS) | ✅ | ✅ + thu hồi định lượng (N2) + break-glass (E2) |
| P3 Query assurance | ❌ | ✅ correctness + freshness (C1); 🟡 completeness ở mức tập bản ghi (Merkle root) |
| P4 Auditing | ❌ | 🟡 hash-chain log + log cấp khóa (N4) |
| P5 Efficient storage | 🟡 | ✅ có thiết kế nhóm trường + số liệu đo (N3) |
| P6 Rò rỉ cấu trúc | ❌ | 🟡 blind index với leakage được nêu rõ (E1) |

### 4.4 Bộ kịch bản kiểm chứng mở rộng (bổ sung cho slide 14)

| Kịch bản | Tấn công | Kỳ vọng sau cải tiến |
|---|---|---|
| A | DBA đọc trực tiếp | Chỉ thấy ciphertext (đã có) |
| B | Y tá vượt quyền | Decrypt thất bại (đã có) |
| C | User đã nghỉ việc dùng SK cũ | Thất bại sau epoch hoặc sau khi CEK được bọc lại; **đo được cửa sổ thu hồi** |
| **D** | **Admin cloud tạo bản ghi giả bằng MPK** | **Bị phát hiện do sai chữ ký DO** (C1) |
| **E** | **Rollback về phiên bản cũ của bản ghi** | **Bị phát hiện qua version + Merkle root** (C1) |
| **F** | Hai user ghép khóa (`Dept=Cardiology` của y tá + `Role=Doctor` của bác sĩ khoa khác) | Thất bại (collusion resistance) |
| **G** | Suy luận từ policy công khai (`Dept=Oncology`) | Lộ với backend (a); không lộ với Covercrypt (N1) |
| **H** | KGC bị xâm nhập | Ngoài phạm vi, nhưng **phát hiện được** qua audit log cấp khóa (N4) |

### 4.5 Câu hỏi nghiên cứu đề xuất sửa lại

- **RQ1'**: Policy RBAC/ABAC của bệnh viện có biểu diễn được trọn vẹn trong (a) CP-ABE dạng cây và (b) Covercrypt dạng dimension không? Mất ngữ nghĩa ở đâu?
- **RQ2'**: Kết hợp *epoch + bọc lại CEK + lazy re-encryption* cho cửa sổ thu hồi và chi phí bao nhiêu khi so với mã hóa lại toàn bộ?
- **RQ3'**: Chi phí của (i) ẩn policy và hậu lượng tử, (ii) chữ ký + freshness so với CP-ABE kinh điển là bao nhiêu (đo theo phương pháp ABE Squared)? Mức đó có chấp nhận được với workload bệnh án không?

### 4.6 Bổ sung bối cảnh pháp lý (tăng tính ứng dụng)

- **NIST IR 8450 (2023)** là checklist cân nhắc khi triển khai ABE: quản lý khóa, thu hồi, hiệu năng.
- Ở Việt Nam: **Nghị định 13/2023/NĐ-CP** về bảo vệ dữ liệu cá nhân, và **Luật Bảo vệ dữ liệu cá nhân 2025** (hiệu lực từ 01/01/2026). Dữ liệu sức khỏe là *dữ liệu cá nhân nhạy cảm*. *(Nên kiểm tra lại số hiệu và điều khoản cụ thể trước khi trích dẫn.)*
- HIPAA (Mỹ) và yêu cầu audit trong chương của Dang (SOX, HIPAA, PCI) liên quan trực tiếp tới N4.

---

## Phụ lục: Lộ trình PoC gợi ý

1. **Tuần 1–2:** Hiện thực bản kinh điển gồm CP-ABE (BLS12-381) + AES-GCM + PostgreSQL/S3 làm "cloud", chạy kịch bản A, B, F.
2. **Tuần 3:** Thêm C1 (chữ ký + version + Merkle root), chạy kịch bản D, E.
3. **Tuần 4:** Thêm N2 (epoch + bọc lại CEK), đo cửa sổ thu hồi (kịch bản C).
4. **Tuần 5:** Thêm backend Covercrypt (N1), chạy kịch bản G, so sánh hiệu năng (N3).
5. **Tuần 6:** Audit log (N4) + break-glass (E2), viết báo cáo theo bảng 4.3.
