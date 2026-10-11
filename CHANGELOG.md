# Lịch sử thay đổi

Mỗi lần thay đổi tài liệu/mã nguồn thì thêm một mục ở đầu danh sách (mới nhất ở trên), đồng thời tạo git commit tương ứng.
Định dạng: `## [YYYY-MM-DD] Tiêu đề ngắn`, kèm các mục *Thêm / Sửa / Xóa / Nguồn mới*.

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
