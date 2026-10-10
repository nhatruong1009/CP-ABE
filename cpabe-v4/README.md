# cpabe-v4 — hiện thực kiến trúc CP-ABE v4.2

Thiết kế: `../analysis/05_dac-ta-kien-truc-v4.1.md` · Sơ đồ: `../diagrams/v4-kien-truc-cp-abe.md` · Lịch sử: `../logs/design-changelog.md`

## Trạng thái

| Bước | Nội dung | Trạng thái |
|---|---|---|
| 1 | Lõi mật mã T2/T3: `provider`, backend `fame` (Charm ac17, BN254), cAEAD, KEK envelope, EncryptedRecord, test A/B/F/F2/K1/K2 | **Xong (2026-10-10)** |
| 2 | Policy T1: compiler tập con Cedar → policy ABE + kiểm thử tương đương | Chưa làm |
| 3 | **PoC phase 1**: image outsource-db, auth, kgc, keyvault, app, client + thu hồi R1 + `scripts/demo.sh` | **Xong (2026-10-10)**: 30/30 unit test pass, demo 8 bước chạy đúng kỳ vọng |
| 3b | **Web UI** (`cpabe-v4/webui`): đăng nhập nhanh, lấy khóa, đọc, tạo/cập nhật/đổi policy/xóa, thu hồi + re-wrap, tab góc nhìn cloud | **Xong (2026-10-10)**: đã smoke-test API |
| 4 | Transparency log + auditor (T4, T5) | Chưa làm |
| 5 | Thu hồi + planner (T6) | Chưa làm |
| 6 | Benchmark | Chưa làm |

## Cấu trúc

```
cpabe-v4/
├── docker/charm.Dockerfile     # Python 3.9 (bookworm) + GMP + PBC 0.5.14 + Charm 0.63 (b2db00b)
├── docker-compose.yml          # bước 1: chỉ có service crypto-test
├── requirements.txt
├── cpabe/crypto/
│   ├── provider.py             # giao diện AbeProvider (KEM: encaps/decaps → k_abe)
│   ├── backends/fame.py        # FAME qua Charm ac17
│   ├── backends/charm_json.py  # serialize Charm <-> JSON (KHÔNG dùng pickle)
│   ├── attrs.py                # token thuộc tính: DEPTXCARDIOLOGYXV1, EPOCHX7 (viết hoa, không có _)
│   ├── caead.py                # key-committing AEAD
│   ├── envelope.py             # KEK wrap/unwrap (LocalKek; sau này là KeyvaultClient)
│   ├── record.py               # seal / open / rewrap EncryptedRecord (KEM 3 lớp)
│   └── errors.py
└── tests/test_crypto_scenarios.py
```

## Cách chạy (CẦN ĐƯỢC ĐỒNG Ý TRƯỚC KHI CHẠY)

```bash
cd cpabe-v4
docker compose build                          # build các image cpabe-v4/*
docker compose run --rm crypto-test           # unit test lõi mật mã + policy
docker compose up -d                          # outsource-db, auth, kgc, keyvault, app
./scripts/demo.sh                             # kịch bản end-to-end
docker compose down                           # dừng (thêm -v để xóa dữ liệu)
```

**Web UI: http://localhost:8080** (image `cpabe-v4/webui`, đóng vai máy của user).

Cổng trên host: app `8000`, kgc `8001`, auth `8002`. webui `8080`. keyvault và outsource-db không mở ra host.
User demo (`config/users.json`): alice (owner), bob (bác sĩ Tim mạch), carol (y tá Tim mạch), dave (thu ngân), erin (bác sĩ Nhi), admin.

## Kết quả lần build / chạy đầu (2026-10-10)
- Base `python:3.9-slim-bullseye` lỗi 404 ở apt, nên chuyển sang `python:3.9-slim-bookworm`.
- Charm 0.63, commit `b2db00be7adf681c6bc35d35be3682ba047b3577`, đã ghim trong Dockerfile.
- `BN254` + `AC17CPABE` chạy được. `util.createPolicy`, `util.prune`, `util.strip_index` có trong MSP. Khóa ac17 có `attr_list`.
- Charm **viết hoa** thuộc tính trong policy và **cắt `_<số>`** ở cuối, nên token được đổi sang `DEPTXCARDIOLOGYXV1`. Lần chạy đầu: 6/16 test thất bại vì lệch chữ hoa/thường.
- Charm 0.63 tự xác thực ciphertext ac17 (`InvalidCiphertext`). Hệ thống gộp lỗi này thành `IntegrityError`.
- Kết quả cuối: **20 passed in 3.27s**.
