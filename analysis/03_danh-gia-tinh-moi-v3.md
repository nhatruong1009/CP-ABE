# Đánh giá tính mới — Thiết kế v3 (CP-ABE · thao tác dữ liệu · thu hồi khóa)

> Mốc tính mới: **10/2021 – 10/2026**. Đối tượng đánh giá: `02_ke-hoach-cai-thien-1-tuan.md` (v3).
> Ở đây "tính mới" được hiểu theo **hướng ứng dụng**: có đóng góp về tích hợp, đo đạc hoặc thực tiễn mà các công trình gần đây chưa làm. Không đòi hỏi lược đồ mật mã mới.

---

## 1. Kết luận nhanh

| Khía cạnh | Điểm (1–10) | Nhận xét |
|---|---|---|
| Kỹ thuật/cơ chế | **2** | Mọi cơ chế đều đã có trước 2021 |
| Tích hợp hệ thống | **4** | Gộp CRUD + đổi policy + 2 cơ chế thu hồi × 3 mức xử lý dữ liệu vào một kiến trúc lai, bọc CEK kép |
| Đánh giá thực nghiệm | **6** (nếu làm đúng) | Chưa tìm thấy công trình 2021–2026 nào so sánh trực tiếp các chiến lược thu hồi trên **cùng một workload** |
| **Tổng thể** | **≈ 4/10** | Tăng so với proposal gốc (≈ 2/10). Đủ cho đồ án ứng dụng **nếu định vị đúng**: đóng góp là *đánh giá có hệ thống*, không phải *mô hình mới* |

> ⚠️ So với v2, v3 **giảm tính mới về phạm vi**, vì đã bỏ manifest/chữ ký, ẩn policy và audit. Đổi lại, v3 **tăng độ sâu** ở trục thu hồi. Đây là đánh đổi hợp lý cho thời gian 1 tuần.

---

## 2. Từng thành phần của v3 so với tài liệu

| Thành phần v3 | Nguồn gốc | Mới trong 5 năm? | Ghi chú |
|---|---|---|---|
| CP-ABE (BSW07 / FAME) | 2007 / 2017 | ❌ | Lõi, không cần mới |
| Mã hóa lai AES-GCM + CP-ABE | Có từ khi ABE ra đời | ❌ | |
| **Bọc CEK kép** (CP-ABE + KEK) | Envelope encryption của KMS (AWS/GCP/Vault) | ❌ về ý tưởng | 🟡 Ít thấy trong các bài CP-ABE học thuật. Đây là cách làm thực tế nhưng **thêm escrow** |
| CRUD + đổi policy chỉ bằng bọc lại header | Policy update trong ABE (~2013 trở đi) | ❌ | Các bài nghiên cứu cập nhật policy bằng mật mã. v3 làm bằng KEK nên đơn giản hơn nhưng yếu hơn về mô hình tin cậy |
| R1 Epoch / time-bound keys | Boldyreva et al. 2008 | ❌ | |
| R2 Attribute versioning | Yu et al. 2010 | ❌ | |
| L2 Lazy re-encryption | Plutus 2003, Kallahalla | ❌ | |
| **Ma trận thực nghiệm {R1, R2} × {L0, L1, L2}** trên cùng workload | — | ✅ **khoảng trống** | Tìm kiếm không thấy so sánh trực tiếp. Các bài 2023–2024 chỉ so lược đồ của mình với lược đồ khác ở mức lý thuyết hoặc định tính |
| **KB C3: rủi ro CEK đã cache** khi chỉ bọc lại header | Đã biết về lý thuyết | 🟡 | Hiếm khi được **đo** thành chỉ số |
| Phương pháp đo theo ABE Squared (2022) | 2022 | ✅ (phương pháp) | Làm kết quả đáng tin và so sánh được |

---

## 3. Đặt cạnh các công trình thu hồi 2021–2026

| Công trình | Cách thu hồi | Mô hình tin cậy | v3 so với công trình này |
|---|---|---|---|
| ABPRE thu hồi trực tiếp (IEEE TDSC 2024) | Cloud re-encrypt bằng re-encryption key, loại user khỏi tập chia sẻ | Không cần bên giữ CEK | **v3 kém hơn** về mô hình tin cậy (cần KEK), **đơn giản hơn** nhiều để triển khai |
| Revocable CP-ABE dựa trên proxy (2024) | Re-encrypt ciphertext + cập nhật khóa | Proxy bán tin cậy | Bài này ghi nhận chi phí lưu trữ tăng sau mỗi lần thu hồi; v3 có thể **đo thực tế** điều này |
| UR-CP-ABE (cây nhị phân user) | Giảm chi phí re-encryption | KGC | v3 không tối ưu bằng mật mã mà **so sánh chiến lược ở mức hệ thống** |
| mRLWE-CP-ABE (2024) | Mediator, không re-encrypt | Mediator bán tin cậy | Ngoài phạm vi v3 (lattice) |
| Decentralized CP-ABE, thu hồi định kỳ + tức thời (2023) | Hai chế độ thu hồi | Multi-authority | Ý tưởng "2 chế độ" **giống R1 + lớp vận hành** của v3, nhưng bài này chỉ đánh giá định tính |

**Nhận định:** về *cơ chế*, v3 đi sau các công trình gần đây. Về *đánh giá thực nghiệm so sánh trên cùng một hệ thống*, v3 có thể đóng góp, vì đây là khoảng trống mà các bài 2023–2024 để lại: phần lớn chỉ báo cáo lược đồ của mình "tốt hơn" mà không so sánh chéo trên cùng workload.

---

## 4. Rủi ro khi bảo vệ (hội đồng có thể hỏi)

| Câu hỏi có thể gặp | Trả lời gợi ý |
|---|---|
| "Có gì mới, toàn kỹ thuật cũ?" | Đóng góp là **đánh giá có hệ thống 6 tổ hợp thu hồi trên cùng hệ thống**, kèm chỉ số **cửa sổ thu hồi** và **cửa sổ phơi nhiễm CEK**. Khoảng trống này chưa được lấp trong các bài 2021–2026 |
| "KEK giữ mọi CEK thì khác gì TDE?" | KEK nằm trong **vùng tin cậy của tổ chức**, không nằm ở cloud. Cloud chỉ thấy ciphertext. Khác TDE ở chỗ nhà cung cấp cloud không giữ khóa. Escrow được thừa nhận là giới hạn, kèm hướng phát triển (ABPRE 2024 / MA-ABE) |
| "Sao không dùng lược đồ revocable có sẵn?" | Mục tiêu là ứng dụng: dùng thư viện đã kiểm chứng (Charm, `bsw07`/`ac17`), tránh lược đồ bị phá (*A Bunch of Broken Schemes* 2021, ACABELLA 2023) |
| "L1 có lỗ hổng?" | Đúng, và đó là **phát hiện được đo đạc** (KB C3). Báo cáo đưa ra khuyến nghị chọn L0/L2 theo độ nhạy của dữ liệu |

---

## 5. Cách tăng tính mới mà KHÔNG mở rộng phạm vi (≤ 1 ngày công mỗi mục)

Cả ba mục đều nằm trong trục **thu hồi khóa**, tận dụng số liệu đã đo ở ngày 6.

| # | Bổ sung | Vì sao tăng tính mới | Công sức |
|---|---|---|---|
| **T1** | **Định nghĩa 2 chỉ số**: *Revocation window* (từ lúc thu hồi tới lúc SK cũ vô hiệu) và *CEK exposure window* (từ lúc thu hồi tới lúc ciphertext cũ không còn mở được bằng CEK đã cache) | Biến khái niệm định tính thành chỉ số đo được. Đây là cách trả lời RQ2 rõ ràng nhất | ½ ngày (chủ yếu viết) |
| **T2** | **Revocation planner**: một mô hình chi phí đơn giản (số user, số bản ghi liên quan, kích thước dữ liệu, độ nhạy) để **tự chọn** R1/R2 × L0/L1/L2. Mô hình được kiểm chứng bằng số liệu đo thật | Từ "đo" thành "khuyến nghị có căn cứ". Chưa thấy công cụ tương tự trong các bài gần đây | 1 ngày |
| **T3** | **Đặt kết quả cạnh số liệu đã công bố** (TDSC 2024, proxy-based 2024) ở dạng bảng so sánh định tính và độ phức tạp | Định vị rõ đóng góp so với nghiên cứu 5 năm gần đây | ½ ngày |

Nếu làm T1 + T2, tính mới ước đạt **khoảng 5–6/10**, đủ để khẳng định: *"so sánh thực nghiệm và hướng dẫn chọn chiến lược thu hồi cho CP-ABE lai"*.

> Đây mới là **đề xuất**, chưa đưa vào thiết kế. Nếu đồng ý, T1/T2 sẽ được ghi thành v3.1 trong `logs/design-changelog.md`.

---

## 6. Câu định vị đóng góp đề xuất (dùng cho slide/báo cáo)

> *"Đồ án hiện thực một hệ thống kiểm soát truy cập dựa trên CP-ABE lai cho dữ liệu outsource, hỗ trợ đầy đủ các thao tác dữ liệu (CRUD, đổi policy). Đồ án **đánh giá thực nghiệm có hệ thống** hai cơ chế thu hồi (epoch, attribute versioning) kết hợp với ba mức xử lý dữ liệu, dùng hai chỉ số revocation window và CEK exposure window, và đưa ra **khuyến nghị chọn chiến lược thu hồi** theo quy mô và độ nhạy của dữ liệu."*

## Nguồn bổ sung (phiên này)
- PIRATTE — proxy-based immediate revocation: https://arxiv.org/pdf/1208.4877
- Performance analysis proxy-based revocable CP-ABE (2024): https://inderscience.com/filter.php?aid=134428
- Decentralized CP-ABE, periodic + immediate attribute revocation (2023): https://researchportal.murdoch.edu.au/esploro/outputs/conferencePaper/Decentralized-Attribute-Based-Access-Control-with-Attribute/991005602265807891
- Entropy 2023 (revocable CP-ABE): https://doaj.org/article/b88fe16dddbc46c99d721709a97f7fad
- mRLWE-CP-ABE (2024): https://irep.mbzuai.ac.ae/items/0ed76551-9de6-4c14-a313-834c64489971
- Các nguồn còn lại: xem `papers/README.md`
