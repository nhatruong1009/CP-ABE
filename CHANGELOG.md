# Lịch sử thay đổi

Mỗi lần thay đổi tài liệu/mã nguồn thì thêm một mục ở đầu danh sách (mới nhất ở trên), đồng thời tạo git commit tương ứng.
Định dạng: `## [YYYY-MM-DD] Tiêu đề ngắn`, kèm các mục *Thêm / Sửa / Xóa / Nguồn mới*.

## [2026-10-21] v4: thu hồi hai pha, cloud kiểm access token, công cụ đo (theo góp ý của thầy)

**Thêm**
- C7 · `code/shared/token.go`, `authority` `GET /users/{id}/token`: access token Ed25519 sống 5 phút, mang thuộc tính hiện hành. `cloud-api` nhận public key của authority qua `PUT /authority-key` (lưu bảng `settings`). Khi `CLOUD_ENFORCE_READ=true`, cloud bỏ `wrapped_dek`, `nonce`, `ciphertext` (trường `withheld`) với phiên bản mà token không thỏa chính sách đọc (`ABECouldDecrypt` trên `abe_wrapped_priv`, không giải mã gì). Ghi cần token hợp lệ. Mặc định tắt để giữ demo cũ.
- C8 · thu hồi hai pha `mode=twophase`: pha 1 như Lazy (trả lời ngay), pha 2 chạy nền bọc lại DEK, phiên bản mới nhất trước, hủy thế hệ cũ khi xong, ghi audit `revoke.phase2`.
- C9 · `mode=rekey`: pha 2 giải mã nội dung, mã hóa lại bằng DEK mới, ký lại bằng Write Key hiện hành, thay phiên bản qua `PUT /documents/{id}/versions/{v}` (cloud vẫn kiểm chữ ký). DEK user đã lưu không mở được bản mã mới.
- C1 · `code/bench`: `bench micro` (chi phí từng thao tác, mô phỏng thu hồi theo D, đọc có/không cache), `bench e2e` (thu hồi trên stack Docker với D tài liệu), `bench dek` (kịch bản user đã lưu DEK + Policy Key). `bench/run_all.sh` chạy tất cả, kết quả ở `docs/bench-ket-qua.md`. Service `bench` trong compose (profile `bench`).
- App: gửi access token của vai đang đóng; hiển thị "Cloud không trả bản mã…" (trạng thái `withheld`); ô chế độ thu hồi thêm "Hai pha" và "Hai pha + re-key".

**Sửa**
- `docker-compose.yml` và `README.md`: bỏ câu sai "cloud-api không gọi được authority" (authority và app cũng nằm trong `cloud_net`, API authority chưa xác thực).

**Hạn chế đã biết:** hàng đợi pha 2 nằm trong RAM; re-key làm authority thấy plaintext và thay phiên bản cũ; token làm cloud biết thuộc tính người gọi.

- `code/test/e2e.sh`: kiểm thử tự động kịch bản A–K + bench dek qua Web UI, trên project riêng `cpabe-test`. README thêm hướng dẫn chạy các chế độ thu hồi, bật C7, kiểm thử, đo hiệu năng. `bench/run_all.sh` chạy trên project riêng `cpabe-bench` (không xóa dữ liệu stack demo).

**Kiểm tra:** clone sạch nhánh `v4-cai-tien` rồi `bash test/e2e.sh`: 19 đạt, 0 lỗi; `docker compose build` (gồm `go vet ./...`) không lỗi; `bench/run_all.sh` chạy hết 20 cấu hình; giao diện kiểm tay với `CLOUD_ENFORCE_READ=true` (Bình sau thu hồi không nhận bản mã, Dũng vẫn ghi mà không đọc được Đề xuất ngân sách).

## [2026-10-19] Sửa câu mô tả chế độ Lazy / Eager cho đúng với code

**Sửa**
- `code/authority/main.go`: thông báo sau khi thu hồi ở chế độ Lazy đổi thành "phiên bản cũ giữ thế hệ khóa cũ; lần sửa sau tạo phiên bản mới dùng thế hệ mới".
- `code/app/templates/admin.html`, ô chọn chế độ thu hồi:
  - Lazy: "không bọc lại phiên bản cũ, phiên bản mới dùng thế hệ mới (rẻ)"
  - Eager: "bọc lại ngay DEK các phiên bản còn ở thế hệ cũ, hủy thế hệ cũ"

Lý do: nhánh Lazy của `revoke` không bọc lại gì; phiên bản cũ giữ DEK và `read_gen` cũ (thế hệ cũ đã được mã CP-ABE lại theo version mới). Câu cũ "bọc lại khi có người sửa" mâu thuẫn với code và với kết quả kiểm thử ngày 11/10 (Q3: v1, v2 vẫn ở thế hệ 1). Eager (`eagerRewrap`) chỉ bọc lại các phiên bản có `read_gen` khác thế hệ hiện hành, không phải mọi phiên bản.

**Kiểm tra:** `go build ./...` và `go vet ./...` không lỗi. Chưa build lại Docker.

## [2026-10-11] Slide trình bày (Slidev, nền sáng)

**Thêm**
- `slides/slides.md`: 24 slide về cấu trúc hiện tại:
  - bài toán, threat model cập nhật
  - 6 cải tiến
  - use case Công ty ABC
  - kiến trúc 5 container / 2 vùng
  - cấu trúc mã nguồn
  - C1 TKN20, C2 khóa 3 tầng
  - cấu trúc dữ liệu cloud
  - luồng đọc, luồng ghi
  - version thuộc tính, cấp/thu hồi, Lazy/Eager
  - demo, kịch bản, kết quả đo, hạn chế, tham khảo

  Sơ đồ dùng Mermaid. Có ghi chú cho người trình bày ở 7 slide chính. Số liệu chỉ lấy từ lần chạy thử thật (thu hồi Lazy ~0,66 s, Eager ~0,26 s, bản mã CP-ABE ~2,7 KB).
- `slides/package.json` (Slidev, theme default, `colorSchema: light`), `slides/style.css`, `slides/.gitignore`.

**Trạng thái:** chưa cài npm, chưa render.

## [2026-10-11] Tab Thuật ngữ, hiện đầy đủ giá trị, quy trình xét quyền sửa & quy trình ghi

**Thêm**
- Tab **Thuật ngữ** (`/glossary`), nằm sau "Góc nhìn Cloud". Giải thích các tên trường trên cloud (`wrapped_dek`, `abe_wrapped_priv`, `read_gen`, `compiled_expr`, `header_sig`…), khóa/thuật toán (DEK, Policy Key, Write Key, X25519, AES-GCM, AAD…), khái niệm thu hồi (version, thế hệ, epoch, Lazy/Eager…) và thành phần hệ thống.
- **Quy trình xem xét quyền sửa** khi mở trang Sửa, gồm 7 bước:
  1. Phiên bản mới nhất
  2. Write policy + chữ ký authority
  3. Đối chiếu thuộc tính
  4. CP-ABE mở Write Key
  5. Chuẩn bị bọc DEK
  6. Những gì cloud sẽ kiểm
  7. Kết luận
- **Quy trình ghi** hiển thị sau khi lưu (cả khi bị từ chối):
  1. Mở Write Key, hoặc dùng khóa giả khi ghi trái phép
  2. DEK mới + AES-GCM
  3. Bọc DEK
  4. Ký
  5. Gửi cloud + phản hồi (201/403/409)
- `app/write.go`: `WriteCheck`, `Write` có ghi từng bước. `Forge` gộp vào `Write(…, forge=true)`.

**Sửa**
- Mọi tài liệu đều có nút **Xem** và **Sửa**. Không đủ quyền thì trang Sửa hiện lý do, khóa nút lưu, và có nút "thử ghi trái phép".
- Phần chi tiết không còn che bớt: hiện đầy đủ hex của private key, DEK, bản mã, chữ ký, `abe_wrapped_priv`. Giá trị dài nằm trong ô cuộn.
- Template dùng chung `steps` trong `layout.html`.

**Kiểm thử** (`docker compose up -d --build app`, giữ dữ liệu). Tất cả **đạt**:
- `/glossary` trả 200.
- Dũng thấy nút Sửa ở cả 4 tài liệu.
- Dũng mở Sửa Q3: bước đối chiếu thất bại, kết luận "KHÔNG được sửa", nút lưu bị khóa, có nút ghi trái phép.
- An mở Sửa Q3: 7 bước đạt, hiện đầy đủ private Write Key (128 ký tự hex).
- An lưu v2, v3: trang tài liệu hiện quy trình ghi (DEK, plaintext JSON, nonce, ciphertext, wrapped_dek, chữ ký, phản hồi 201). Quy trình chỉ hiện 1 lần.
- Dũng ghi trái phép: quy trình ghi kết thúc với 403 Forbidden.

**Thay đổi dữ liệu do kiểm thử:** Báo cáo Q3 có thêm v2, v3 (do An).

**Sửa sau kiểm thử** (chưa build): khi ghi trái phép, bước ký đổi tiêu đề thành "Ký bằng KHÓA GIẢ" và đánh dấu thất bại.

## [2026-10-11] Hiển thị chi tiết quy trình giải mã ("bản thô")

**Thêm**
- Trang tài liệu có mục **"🔍 Quy trình giải mã chi tiết"** cho mọi phiên bản (đọc được lẫn bị khóa). Gồm sơ đồ luồng và 7 bước:
  1. Bản ghi thô trên cloud
  2. Header chính sách + chữ ký authority
  3. Đối chiếu từng thuộc tính / version
  4. Tầng 1 CP-ABE
  5. Tầng 2 X25519 → DEK
  6. Tầng 3 AES-GCM → plaintext JSON thô
  7. Chữ ký ghi Ed25519

  Mỗi bước hiển thị nguồn dữ liệu, giá trị hex và thời gian. Các khóa bí mật chỉ hiện một phần.
- Bảng lịch sử có link "Xem quy trình" cho từng phiên bản (`?v=N`).
- `shared.OpenPayloadRaw`, `Session.openPrivCached` (báo private key lấy từ cache hay vừa giải mã).

**Kiểm thử** (sau `docker compose down -v` + build lại):
- An đọc Q3: 7 bước đạt.
- Dũng đọc Q3: dừng ở bước đối chiếu thuộc tính, Tầng 2–3 "bỏ qua", chữ ký vẫn kiểm được.

**Sửa sau kiểm thử** (chưa build lại): thuộc tính *không có* trong chính sách không tô đỏ nữa. Với `or`, thiếu một nhánh vẫn có thể thỏa. Chỉ version cũ mới tô đỏ.

## [2026-10-11] Chạy thử toàn bộ hệ thống trên Docker

**Kết quả kiểm thử** (dùng `curl` qua app, cookie `as=<user>`). Tất cả **đạt**:

| Kịch bản | Kết quả |
|---|---|
| Quyền đọc/ghi ban đầu | An đọc 2/sửa 2 · Bình 1/1 · Chi 1/2 · Dũng 1/2 · Hà 3/0 (đúng bảng chính sách) |
| D: ghi trái phép (khóa tự tạo) | Cloud trả 403 "chữ ký ghi không hợp lệ" |
| D2: sửa khi không thỏa write policy | App chặn trước, không mở được Write Key |
| Sửa bình thường / sửa từ phiên bản cũ | Lưu v2 / 409 Conflict |
| C: thu hồi `dept_finance` của Bình (Lazy) | v1→v2, KeyGen lại 2 user, 3 chính sách sang thế hệ mới, khoảng 0,66 s. Bình đọc 0, An vẫn đọc 2 |
| H: Bình dùng khóa cũ (epoch 1, `dept_finance: v1`) | Đọc 0 |
| F: cấp `proj_alpha` cho Bình | KeyGen 1 lần, đọc được ngay tài liệu Alpha cũ |
| I: Dũng ghi Đề xuất ngân sách | Ghi được (không đọc được), An đọc được bản của Dũng |
| E: cloud sửa 1 bit | App báo bản mã bị sửa đổi (AES-GCM) |
| J: thu hồi `proj_alpha` của Dũng (Eager) | Bọc lại DEK 1 phiên bản sang thế hệ mới, hủy thế hệ cũ, khoảng 0,26 s |
| Lazy so với Eager trên cloud | Q3: v1, v2 vẫn ở thế hệ 1, v3 ở thế hệ 2 · Alpha: đã chuyển sang thế hệ 2 |
| Các trang `/ /admin /cloud /new /doc /edit` | HTTP 200, không có panic/lỗi render trong log |

**Sửa**
- `code/docker-compose.yml`:
  - cổng app mặc định đổi sang **8088**, vì 8080 bị container `cpabe-v4-webui-1` của project khác chiếm
  - thêm biến `APP_PORT`, `ADMINER_PORT`
- `code/app/vault.go`: sửa thông báo lỗi bị lặp ("Bản mã bị sửa đổi: bản mã bị sửa đổi…"). **Chưa build lại.**

## [2026-10-11] Chuyển mã nguồn vào `code/`, cố định phiên bản thư viện

**Sửa**
- Chuyển `shared/ authority/ app/ cloudapi/ go.mod Dockerfile docker-compose.yml .dockerignore` vào `code/`.
- Cố định thư viện bằng `go.mod`/`go.sum` lấy từ lần build đầu:
  - Go 1.26
  - CIRCL v1.6.5
  - pgx v5.11.0
  - x/crypto v0.58.0

  Dockerfile dùng `go mod download` thay vì `go mod tidy`.
- `docker-compose.yml`:
  - đặt `name: cpabe-demo`
  - chỉ build image 1 lần (service `authority`), 2 service còn lại dùng lại image
- Cập nhật đường dẫn trong `README.md` và `docs/01-de-xuat-cai-tien.md`.

**Kết quả build (trước khi chuyển thư mục):** `docker compose build` thành công, `go vet` không cảnh báo.

## [2026-10-11] PoC bằng Go: authority, app, cloud-api trên Docker

**Quyết định:** chọn Go cho toàn bộ code (thay vì phương án Python + Charm-crypto).

**Thêm**
- `shared/`: wrapper CP-ABE (CIRCL tkn20), Policy Key X25519 + DEK AES-256-GCM, Write Key Ed25519, kiểu dữ liệu, client HTTP.
- `authority/`:
  - Setup, KeyGen, thuộc tính có version, biên dịch chính sách logic thành chính sách có version
  - Policy Key theo thế hệ, ký bằng khóa authority để cloud không tráo được
  - Cấp/thu hồi thuộc tính, chế độ Lazy/Eager
  - Seed 5 user, 4 tài liệu
- `cloudapi/`: REST + PostgreSQL, kiểm chữ ký ghi theo Write Key thế hệ hiện hành, optimistic locking (409), chặn đổi chính sách khi sửa, endpoint mô phỏng cloud độc hại.
- `app/`: Web UI gồm chọn vai, kho tài liệu, xem/lịch sử, tạo/sửa, thử ghi trái phép, quản trị thuộc tính, góc nhìn cloud. Keystore giữ cả khóa cũ để demo.
- `Dockerfile`, `docker-compose.yml` (2 network `trusted_net` / `cloud_net`), `README.md` kèm kịch bản demo A–J.

**Sửa**
- `docs/01-de-xuat-cai-tien.md`:
  - authority lưu bằng file JSON (thay SQLite)
  - không cho đổi chính sách khi sửa (lý do bảo mật, ghi vào §11)
  - cập nhật cấu trúc thư mục

**Trạng thái:** chưa build, chưa chạy thử.

## [2026-10-11] Rà soát đề xuất và đề xuất cải tiến

**Thêm**
- `docs/01-de-xuat-cai-tien.md`: rà soát `ref/proposal.pdf` và đề xuất 6 cải tiến (C1–C6):
  - C1: TKN20 qua Cloudflare CIRCL thay cho BSW07
  - C2: phân cấp khóa 3 tầng (Policy Key)
  - C3: tách quyền đọc/ghi bằng chữ ký
  - C4: cấp/thu hồi thuộc tính theo phiên bản, kèm lazy/eager re-encryption
  - C5: ẩn tên thuộc tính
  - C6: use case doanh nghiệp nhiều người ghi/đọc

  Tài liệu cũng có kiến trúc Docker, schema DB, REST API, UI, kịch bản demo, kế hoạch đo đạc và phân công.
- `docs/research/sources.md`: sổ nguồn tham khảo kèm mức độ kiểm chứng và danh sách việc cần kiểm thêm.
- `ref/snapshots/circl-tkn20/`: bản lưu mã nguồn CIRCL `tkn20` (commit `91db3e7`) dùng để xác minh API và cú pháp chính sách.
- `CHANGELOG.md`: file này.

**Ghi chú**
- Sửa nhận định trong slide 7: collusion là tính chất được CP-ABE bảo vệ sẵn, không phải "ngoài phạm vi".
