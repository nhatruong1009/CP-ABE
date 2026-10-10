# Danh mục paper liên quan / ảnh hưởng đến đồ án

Ký hiệu: 📥 = đã tải PDF về thư mục này · 🔗 = chỉ có link (ePrint IACR chặn tải tự động bằng Cloudflare, hoặc paper không truy cập mở).
"Trong 5 năm" = công bố trong khoảng 10/2021 – 10/2026.
Cột *Dùng cho* tham chiếu mã cải tiến trong `analysis/01_phan-tich-van-de-va-danh-gia-proposal.md` (C1–C3, N1–N4, E1–E5).

## A. Tài liệu gốc (thư mục `ref/`)

| Tài liệu | Năm | Vai trò |
|---|---|---|
| Dang, T.K. — *Security Issues in Outsourced XML Databases* | ~2009 | Khung 5 vấn đề ODBS, mô hình SS/MS/SMS/MMS |
| Proposal Nhóm 06 — *Ứng dụng mô hình kiểm soát truy cập cho Outsourced Storage (CP-ABE)* | 2026 | Đối tượng đánh giá |

## B. Paper trong 5 năm gần đây

| # | File / Link | Paper | Năm · Venue | Trong 5 năm | Dùng cho |
|---|---|---|---|---|---|
| 1 | 📥 `2022_ABE-Squared_TCHES.pdf` | de la Piedra, Venema, Alpár — *ABE Squared: Accurately Benchmarking Efficiency of ABE* | 2022 · TCHES | ✅ | N3, C3 |
| 2 | 🔗 https://eprint.iacr.org/2025/1230 | *ABE Cubed* — benchmark đa chiều | 2025 · TCHES | ✅ | N3 |
| 3 | 🔗 https://eprint.iacr.org/2023/1274 | de la Piedra, Venema, Alpár — *ACABELLA: Automated (Crypt)analysis of ABE* | 2023 · ACM CCS | ✅ | C3 |
| 4 | 📥 `2023_Registered-ABE_Eurocrypt.pdf` | Hohenberger, Lu, Waters, Wu — *Registered Attribute-Based Encryption* | 2023 · Eurocrypt | ✅ | E5 (hướng nghiên cứu, bỏ key escrow) |
| 5 | 🔗 https://eprint.iacr.org/2023/836 | Brézot, de Perthuis, Pointcheval — *Covercrypt: Efficient Early-Abort KEM for Hidden Access Policies with Traceability from DDH and LWE* | 2023 · ESORICS | ✅ | **N1** (ẩn policy + hậu lượng tử) |
| 6 | 🔗 https://eprint.iacr.org/2025/544 | Brézot, Hébant, de Perthuis, Pointcheval — *Security Analysis of Covercrypt (ECDH + ML-KEM)* | 2025 | ✅ | N1 |
| 7 | 🔗 https://github.com/Cosmian/cover_crypt | Thư viện Covercrypt (Rust) — chuẩn ETSI TS 104 015 | 2025 | ✅ | N1 (hiện thực) |
| 8 | 📥 `2023_NIST-IR-8450_ABE-Access-Control.pdf` | NIST IR 8450 — *Overview and Considerations of Access Control Based on Attribute Encryption* | 2023 · NIST | ✅ | Bối cảnh, checklist triển khai |
| 9 | 📥 `2024_BA-ORABE_arXiv.pdf` | *BA-ORABE: Blockchain-Based Auditable Registered ABE with Reliable Outsourced Decryption* (arXiv 2412.08957) | 2024 | ✅ | N4, E4 |
| 10 | 📥 `2024_Payable-Outsourced-Decryption-ABE_arXiv.pdf` | Cai et al. — ABE với outsourced decryption có trả phí, blockchain + ZK (arXiv 2411.03844) | 2024 | ✅ | E4, N4 |
| 11 | 📥 `2024_Decentralized-CP-ABE-Key-Abuse-Metaverse_arXiv.pdf` | *Data sharing in the metaverse with key abuse resistance based on decentralized CP-ABE* (arXiv 2412.13770) | 2024 | ✅ | E5 (phi tập trung, chống lạm dụng khóa) |
| 12 | 📥 `2022_Data-Querying-with-CP-ABE_arXiv.pdf` | *Data Querying with Ciphertext Policy Attribute Based Encryption* (arXiv 2209.15103) | 2022 | ✅ | E1 (truy vấn trên dữ liệu CP-ABE) |
| 13 | 🔗 https://ro.uow.edu.au/test2021/8057 | Ge, Susilo, Liu, Baek, Luo, Fang — *Attribute-Based Proxy Re-Encryption With Direct Revocation Mechanism for Data Sharing in Clouds* | 2024 · IEEE TDSC 21(2) | ✅ | N2 |
| 14 | 🔗 https://www.ncbi.nlm.nih.gov/pmc/articles/PMC10008079/ | *Efficient lattice-based revocable ABE against decryption key exposure for cloud file sharing* | 2023 | ✅ | N2, N1 (hậu lượng tử) |
| 15 | 🔗 https://www.doaj.org/article/1e33b77ac9764eb3afd77c8a2529480d | CP-ABE ẩn policy một phần (Tongxin Xuebao, Vol. 45) | 2024 | ✅ | N1 (phương án thay thế) |
| 16 | 🔗 https://ink.library.smu.edu.sg/sis_research/9858 | *Verifiable outsourced ABE scheme for cloud-assisted mobile e-health system* | 2024 | ✅ | E4 |
| 17 | 🔗 https://ink.library.smu.edu.sg/sis_research/8753 | *Time-controllable keyword search scheme with efficient revocation in mobile e-health cloud* (IEEE TMC, DOI 10.1109/TMC.2023.3277702) | 2024 | ✅ | E1, N2 |
| 18 | 🔗 https://doaj.org/article/e43f31d17fc441efa425665b6116e222 | Inner-product predicate medical data sharing, blockchain-aided ABSE, hidden policy (IEEE Access, DOI 10.1109/access.2024.3400611) | 2024 | ✅ | E1, N1 |
| 19 | 🔗 https://doaj.org/article/a3022f214ca74daaac3fcad46fbe7938 | *Verifiable attribute-based keyword search for PHR* (Journal of Cloud Computing) | 2023 | ✅ | E1, C1 |
| 20 | 🔗 https://research.tudelft.nl/files/145062074/978_3_031_17140_6_32.pdf | Lambregts et al. — *VAL: Volume and Access Pattern Leakage-Abuse Attack with Leaked Documents* | 2022 · ESORICS | ✅ | E1 (cảnh báo rò rỉ) |
| 21 | 🔗 https://www.ncbi.nlm.nih.gov/pmc/articles/PMC12839963/ | *Revocable and Traceable Decentralized ABE for P2P Networks* | 2025–2026 | ✅ | E5, N4 |
| 22 | 🔗 https://journal.hep.com.cn/fcs/EN/10.1007/s11704-025-41356-7 | Traceable & revocable MA-ABE với outsourced decryption & policy update (Frontiers of Computer Science) | 2026 | ✅ | E5, N2 |
| 23 | 🔗 https://repository.lboro.ac.uk/articles/conference_contribution/Correctness_proof_for_a_Ring-Learning-with-Errors_multi-authority_Ciphertext-Policy_Attribute-Based_Encryption_scheme/29247323/1 | *Correctness proof for a Ring-LWE multi-authority CP-ABE scheme* | 2025 | ✅ | N1 (bối cảnh hậu lượng tử) |

## C. Paper nền tảng (ngoài 5 năm nhưng ảnh hưởng trực tiếp)

| # | File / Link | Paper | Năm | Vai trò |
|---|---|---|---|---|
| F1 | 🔗 https://eprint.iacr.org/2020/460 | Venema, Alpár — *A Bunch of Broken Schemes* (CT-RSA 2021) — phá 11 lược đồ ABE, có lược đồ trong thư viện Charm | 2021 (05) | C3 — tránh lược đồ bị phá (ngay sát mốc 5 năm) |
| F2 | 📥 `2021_ETSI-TS-103532-v1.2.1_ABE.pdf` | ETSI TS 103 532 v1.2.1 — *ABE for Attribute Based Access Control* | 2021 (05) | Chuẩn triển khai ABE |
| F3 | (không tải) | Bethencourt, Sahai, Waters — *Ciphertext-Policy ABE* | 2007 · IEEE S&P | Lược đồ gốc của proposal |
| F4 | (không tải) | Li et al. — *Scalable and Secure Sharing of PHR in Cloud using ABE* | 2013 · TPDS | Use case y tế gốc |
| F5 | 🔗 https://www.ndss-symposium.org/ndss-paper/revisiting-leakage-abuse-attacks/ | Blackstone, Kamara, Moataz — *Revisiting Leakage Abuse Attacks* | 2020 · NDSS | E1 |
| F6 | 🔗 https://www.mdpi.com/1424-8220/19/7/1695 | Al-Dahhan et al. — *Survey on Revocation in CP-ABE* | 2019 · Sensors | N2 — tổng quan các kỹ thuật thu hồi mà proposal đang liệt kê |
| F7 | (trong chương Dang) | Dang & Son 2006; Nguyen & Dang 2008 — Query assurance / Nested Merkle B+-Tree | 2006–2008 | C1 — cơ sở cho chữ ký + freshness |

> Ghi chú: các bài 🔗 trên eprint.iacr.org có thể tải thủ công bằng trình duyệt (trang dùng Cloudflare challenge). Nên tải thêm Covercrypt (#5, #6) vì đây là trụ cột của hướng N1.

## D. Bổ sung khi đánh giá tính mới v3 (trục thu hồi)

| # | Link | Paper | Năm | Dùng cho |
|---|---|---|---|---|
| R1 | 🔗 https://inderscience.com/filter.php?aid=134428 | Performance analysis of proxy-based collusion-resistant revocable CP-ABE | 2024 | So sánh chi phí re-encryption khi thu hồi |
| R2 | 🔗 https://researchportal.murdoch.edu.au/esploro/outputs/conferencePaper/Decentralized-Attribute-Based-Access-Control-with-Attribute/991005602265807891 | Decentralized ABAC with periodic + immediate attribute revocation | 2023 | Đối chiếu R1 (epoch) + lớp vận hành |
| R3 | 🔗 https://irep.mbzuai.ac.ae/items/0ed76551-9de6-4c14-a313-834c64489971 | mRLWE-CP-ABE — revocation via mediators, không re-encrypt | 2024 | Related work |
| R4 | 🔗 https://doaj.org/article/b88fe16dddbc46c99d721709a97f7fad | Revocable CP-ABE (Entropy) | 2023 | Related work |
| R5 | 📎 https://arxiv.org/pdf/1208.4877 | PIRATTE — proxy-based immediate revocation (nền tảng) | 2012 | Baseline khái niệm |

## E. Bổ sung cho thiết kế v4 (6 tầng)

| # | File / Link | Paper | Năm | Tầng v4 |
|---|---|---|---|---|
| V1 | 📥 `2024_Cedar-Authorization-Language_OOPSLA.pdf` · https://arxiv.org/abs/2403.04651 | Cutler et al. — *Cedar: A New Language for Expressive, Fast, Safe, and Analyzable Authorization* | 2024 · OOPSLA | T1 |
| V2 | 🔗 https://github.com/Brandon-Rozek/cedar-examples | Cedar examples / OOPSLA 2024 benchmarks | 2024 | T1 |
| V3 | 🔗 https://eprint.iacr.org/2022/569 | Venema, Alpár — *TinyABE: Unrestricted CP-ABE for Embedded Devices and Low-Quality Networks* | 2022 · AFRICACRYPT | T2 |
| V4 | 🔗 https://eprint.iacr.org/2024/1352 | Riepel, Venema, Verma — *ISABELLA: Improving Structures of ABE Leveraging Linear Algebra* | 2024 · ACM CCS | T2, T4 |
| V5 | 🔗 https://eprint.iacr.org/2026/414 | *Towards Practical Registered ABE* (NTT Research) | 2026 | T4 (hướng phát triển) |
| V6 | 📥 `Registered-ABE-Linear-CRS_Stracovsky-Waters-Wu.pdf` | Stracovsky, Waters, Wu — Pairing-based Registered ABE với CRS kích thước tuyến tính (năm: cần kiểm tra) | ? | T4 (hướng phát triển) |
| V7 | 📥 `2023_Parakeet-Key-Transparency_NDSS.pdf` | Malvai et al. — *Parakeet: Practical Key Transparency for E2EE Messaging* | 2023 · NDSS | T4, T5 |
| V8 | 📥 `2024_OPTIKS-Key-Transparency_USENIX.pdf` | Len, Chase, Ghosh, Laine, Cruz Moreno — *OPTIKS* | 2024 · USENIX Security | T4, T5 |
| V9 | 🔗 https://www.usenix.org/conference/usenixsecurity21/presentation/len | Len, Grubbs, Ristenpart — *Partitioning Oracle Attacks* (động cơ cho committing AEAD) | 2021 (08) · USENIX Security | T3 (ngay sát mốc 5 năm) |
| V10 | 🔗 https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/ | IETF CFRG — *The AEGIS Family of AEAD Algorithms* (draft) | 2023–2025 | T3 |
| V11 | (chưa mở được) | Bellare, Hoang — *Efficient Schemes for Committing Authenticated Encryption* (Eurocrypt 2022); Chan, Rogaway — *On Committing Authenticated Encryption* (ESORICS 2022) | 2022 | T3 (cần kiểm tra lại) |
| V12 | 📥 `2025_Blockchain-Distributed-ABE-Key-Generation_Frontiers.pdf` | Frontiers in Blockchain — phân tán việc sinh khóa ABE, bỏ SPOF của authority | 2025 | T4 (đối chiếu) |
| V13 | 🔗 https://csrc.nist.gov/presentations/2023/mpts2023-day2-talk-multi-authority-abe | NIST MPTS 2023 — Multi-authority ABE talk | 2023 | T4 |
