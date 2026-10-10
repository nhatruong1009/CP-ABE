# Sơ đồ kiến trúc CP-ABE — v4.1 (làm rõ để triển khai)

> Đặc tả chi tiết (bảng thành phần, API, khóa, mô hình dữ liệu): `analysis/05_dac-ta-kien-truc-v4.1.md`.
> Thay đổi so với v4: xem `logs/design-changelog.md` (mục v4.1).
> Xem bằng trình duyệt: `v4-kien-truc-cp-abe.html`.

---

## 1. Ngữ cảnh hệ thống (C4 mức 1)

```mermaid
flowchart LR
    OW(["Data Owner<br/>(nhân viên tạo / sửa dữ liệu)"])
    US(["User<br/>(Bác sĩ · Y tá · Thu ngân)"])
    AD(["Admin<br/>(cấp / thu hồi quyền)"])
    AU(["Auditor<br/>(bên kiểm toán độc lập)"])
    HR[("HR Directory<br/>nguồn thuộc tính Dept, Role")]

    SYS["HỆ THỐNG CP-ABE v4.1<br/>Lưu dữ liệu mã hóa trên cloud,<br/>kiểm soát truy cập bằng thuộc tính"]
    CLOUD[("Cloud provider<br/>(không tin cậy)")]

    OW -- "tạo / sửa / đổi policy / xóa" --> SYS
    US -- "đọc dữ liệu" --> SYS
    AD -- "cấp khóa, thu hồi" --> SYS
    AU -- "giám sát log, đồng ký checkpoint" --> SYS
    HR -- "thuộc tính user" --> SYS
    SYS -- "chỉ ciphertext + log" --> CLOUD
```

---

## 2. Container (C4 mức 2): ai chạy ở đâu

```mermaid
flowchart TB
    subgraph CLI["MÁY NGƯỜI DÙNG (client)"]
        direction LR
        OCLI["owner-cli<br/>Python · policy compiler (Cedar)<br/>AbeProvider.encaps · cAEAD"]
        UCLI["user-cli<br/>Python · verify · decaps · cAEAD<br/>giữ SK_u, pk_DO, pk_witness"]
    end

    subgraph TRUST["VÙNG TIN CẬY — mạng nội bộ tổ chức (docker net: trusted)"]
        direction LR
        GW["gateway :8000<br/>FastAPI · AuthN token<br/>revocation list · định tuyến CRUD<br/>append log RECORD"]
        KGC["kgc :8001<br/>FastAPI · Setup · KeyGen<br/>epoch · attr-version · revoke<br/>giữ MSK (sealed file)"]
        KV["keyvault :8002<br/>FastAPI · KEK wrap/unwrap<br/>sign bằng sk_DO<br/>(giống Vault Transit)"]
        WK["worker<br/>re-wrap / re-encrypt job<br/>Revocation Planner"]
    end

    subgraph CLOUDZ["VÙNG KHÔNG TIN CẬY — cloud (docker net: cloud)"]
        direction LR
        PG[("storage :5432<br/>PostgreSQL<br/>bảng encrypted_records")]
        TL["translog :8003<br/>FastAPI + SQLite<br/>Merkle log append-only<br/>ký checkpoint bằng sk_log"]
    end

    AUD["auditor (witness)<br/>CLI / cron · độc lập<br/>kiểm consistency · đồng ký checkpoint"]

    OCLI -- "HTTPS: PUT/PATCH/DELETE record" --> GW
    OCLI -- "HTTPS: wrap(CEK), sign(record)" --> KV
    OCLI -- "HTTPS: GET MPK, epoch" --> KGC
    UCLI -- "HTTPS: GET record" --> GW
    UCLI -- "HTTPS: xin SK" --> KGC
    UCLI -- "HTTPS: proof, checkpoint" --> TL
    KGC -- "push revocation list" --> GW
    KGC -- "append KEYGEN / REVOKE" --> TL
    KGC -- "kích hoạt job" --> WK
    WK -- "unwrap(CEK), sign(record)" --> KV
    WK -- "đọc / ghi header" --> GW
    GW -- "SQL" --> PG
    GW -- "append RECORD, lấy proof" --> TL
    AUD -- "lấy checkpoint, consistency proof" --> TL
    AUD -- "đẩy cosignature" --> TL

    classDef trusted fill:#e8f5e9,stroke:#2e7d32,color:#1b5e20
    classDef untrusted fill:#fdecea,stroke:#c62828,color:#7f0000
    classDef client fill:#e3f2fd,stroke:#1565c0,color:#0d47a1
    classDef indep fill:#f3e5f5,stroke:#6a1b9a,color:#4a148c
    class GW,KGC,KV,WK trusted
    class PG,TL untrusted
    class OCLI,UCLI client
    class AUD indep
```

**Nguyên tắc phân tách:**
- `gateway` **không giữ khóa mật mã nào**, chỉ có token xác thực. Nhờ vậy, gateway bị lộ cũng không làm lộ dữ liệu.
- `keyvault` là nơi **duy nhất** chạm vào KEK và sk_DO. Mọi thao tác đi qua API và đều được ghi log.
- `kgc` là nơi **duy nhất** giữ MSK.
- `translog` đặt trên cloud. Nó không cần được tin cậy, vì checkpoint chỉ được chấp nhận khi có **chữ ký đồng thời của witness (auditor)**.

---

## 3. Bản đồ khóa và bí mật: khóa nào nằm ở đâu, ai được dùng

```mermaid
flowchart LR
    subgraph PUB["CÔNG KHAI"]
        MPK(["MPK"])
        PKDO(["pk_DO"])
        PKL(["pk_log · pk_witness"])
    end

    subgraph KGCB["kgc"]
        MSK(["MSK"])
        SKKGC(["sk_kgc<br/>ký entry KEYGEN/REVOKE"])
    end

    subgraph KVB["keyvault"]
        KEK(["KEK"])
        SKDO(["sk_DO<br/>chữ ký owner"])
    end

    subgraph USERB["thiết bị user"]
        SKU(["SK_u<br/>CP-ABE user key"])
    end

    subgraph TLB["translog (cloud)"]
        SKLOG(["sk_log<br/>ký checkpoint"])
    end

    subgraph AUB["auditor"]
        SKW(["sk_witness<br/>đồng ký checkpoint"])
    end

    subgraph EPH["TẠM THỜI — chỉ trong RAM"]
        CEK(["CEK"]) --> KENC(["K_enc"])
        CEK --> KCOM(["K_com"])
    end

    MSK -. "KeyGen" .-> SKU
    KEK -. "wrap/unwrap" .-> CEK
```

| Bí mật | Nơi lưu | Ai được dùng | Nếu bị lộ thì sao |
|---|---|---|---|
| MSK | kgc (file được seal) | Chỉ kgc | Giải mã được mọi thứ. Nhưng khóa cấp lén vẫn **bị log phát hiện** |
| KEK | keyvault | owner-cli (wrap), worker (unwrap) qua API | Lấy được mọi CEK. Mọi lần unwrap đều có log |
| sk_DO | keyvault | owner-cli, worker qua API `sign` | Giả mạo được bản ghi có chữ ký hợp lệ |
| SK_u | Thiết bị user | User | Lộ quyền của user đó. Xử lý bằng thu hồi |
| sk_log | translog | translog | Không đủ để giả checkpoint, vì còn thiếu chữ ký của witness |
| sk_witness | auditor | auditor | Cần đi cùng sk_log mới giả được checkpoint |
| CEK, K_enc, K_com | RAM | Phiên mã hóa / giải mã | Lộ đúng một bản ghi |

---

## 4. Triển khai (docker compose)

```mermaid
flowchart TB
    subgraph HOST["Máy chạy demo"]
        subgraph NT["docker network: trusted"]
            GW["gateway"]
            KGC["kgc"]
            KV["keyvault"]
            WK["worker"]
        end
        subgraph NC["docker network: cloud"]
            PG[("postgres")]
            TL["translog"]
        end
        AUD["auditor (container riêng, network: audit)"]
        CLI["owner-cli · user-cli (chạy trên host)"]
        VOL[("volumes:<br/>kgc-sealed · kv-keys · pg-data · tl-data · aud-state")]
    end

    GW --- PG
    GW --- TL
    KGC --- TL
    AUD --- TL
    CLI --> GW
    CLI --> KGC
    CLI --> KV
    CLI --> TL
```

- Hai docker network `trusted` và `cloud` mô phỏng hai vùng tin cậy. Riêng `gateway` và `kgc` được nối vào cả hai network, vì chúng cần ghi xuống storage và log.
- Kịch bản tấn công "DBA của cloud" được chạy bằng `docker exec` vào container `postgres` / `translog`.

---

## 5. Transparency log: entry, checkpoint, witness

```mermaid
flowchart LR
    E1["KEYGEN<br/>user_pseudonym · H(attrs) · epoch · attr_versions<br/>sig_kgc"] --> LOG
    E2["REVOKE<br/>user_pseudonym hoặc attr · epoch / version mới<br/>sig_kgc"] --> LOG
    E3["RECORD<br/>record_id · version · H(record) · op: put/patch/delete<br/>(H(record) đã gồm owner_sig)"] --> LOG
    LOG[("Merkle log append-only")] --> CP["Checkpoint<br/>size · root · time<br/>sig_log"]
    CP --> W["Witness (auditor)<br/>kiểm consistency với checkpoint trước<br/>đồng ký: sig_witness"]
    W --> OK["Checkpoint hợp lệ = có đủ sig_log + sig_witness"]
    OK --> C["user-cli chỉ tin checkpoint hợp lệ"]
```

---

## 6. Luồng ghi (Create / Update)

```mermaid
sequenceDiagram
    autonumber
    participant O as owner-cli
    participant KGC as kgc
    participant KV as keyvault
    participant GW as gateway
    participant PG as storage
    participant TL as translog

    O->>KGC: GET /mpk, /epoch
    O->>O: biên dịch Cedar thành policy ABE, tính policy_hash
    O->>O: CEK mới, HKDF sinh K_enc, K_com
    O->>O: ciphertext = AES-GCM(K_enc, data, data_aad), commit = HMAC(K_com, nonce + data_aad)
    O->>O: (k_abe, kem) = encaps(MPK, policy AND epoch), wrap = AES-GCM(k_abe, CEK, header_aad)
    O->>KV: POST /wrap (CEK)
    KV-->>O: kek_header
    O->>KV: POST /sign (H(record không có sig))
    KV-->>O: owner_sig
    O->>GW: PUT /records/id (token owner)
    GW->>GW: kiểm tra token có vai trò owner, version = version + 1
    GW->>PG: INSERT / UPDATE
    GW->>TL: append RECORD(id, version, H(record))
    TL-->>GW: log_index
    GW-->>O: 201 + log_index
```

---

## 7. Luồng đọc

```mermaid
sequenceDiagram
    autonumber
    participant U as user-cli
    participant GW as gateway
    participant PG as storage
    participant TL as translog

    U->>GW: GET /records/id (token user)
    GW->>GW: kiểm tra revocation list
    GW->>PG: SELECT
    GW-->>U: EncryptedRecord + log_index
    U->>TL: GET checkpoint mới nhất + inclusion proof(log_index)
    U->>U: verify sig_log + sig_witness trên checkpoint
    U->>U: verify inclusion proof và version là mới nhất của record_id
    U->>U: verify owner_sig bằng pk_DO
    alt có bước sai
        U->>U: từ chối (giả mạo / rollback / tráo)
    else hợp lệ
        U->>U: k_abe = decaps(SK_u, kem), CEK = mở wrap bằng k_abe + header_aad
        U->>U: kiểm tra commit, rồi AES-GCM decrypt với data_aad
    end
```

---

## 8. Luồng cấp khóa

```mermaid
sequenceDiagram
    autonumber
    participant U as user-cli
    participant KGC as kgc
    participant TL as translog

    U->>KGC: POST /keys (token user)
    KGC->>KGC: tra HR Directory lấy Dept, Role, gắn epoch + attr-version
    KGC->>KGC: SK_u = KeyGen(MSK, attrs)
    KGC->>TL: append KEYGEN(user_pseudonym, H(attrs), epoch), sig_kgc
    TL-->>KGC: log_index
    KGC-->>U: SK_u + log_index
    U->>TL: inclusion proof + checkpoint hợp lệ
    U->>U: lưu SK_u nếu entry của mình có trong log
```

---

## 9. Luồng thu hồi

```mermaid
sequenceDiagram
    autonumber
    actor A as Admin
    participant KGC as kgc
    participant GW as gateway
    participant WK as worker
    participant KV as keyvault
    participant TL as translog

    A->>KGC: POST /revoke (user hoặc user + attr)
    KGC->>GW: cập nhật revocation list — chặn ngay
    KGC->>KGC: R1 tăng epoch hoặc R2 tăng attr-version
    KGC->>TL: append REVOKE
    KGC->>WK: tạo job (phạm vi bản ghi, user bị ảnh hưởng)
    WK->>WK: Planner chọn L0 / L1 / L2
    loop bản ghi liên quan
        WK->>GW: GET record
        WK->>KV: POST /unwrap (kek_header)
        WK->>WK: L1 encaps mới + bọc lại CEK cũ (dữ liệu giữ nguyên), hoặc L0 CEK mới + re-encrypt
        WK->>KV: POST /sign (record mới)
        WK->>GW: PUT record (version + 1), gateway append RECORD
    end
    Note over KGC: user còn hợp lệ xin lại SK (luồng 8), mỗi khóa đều có entry KEYGEN
    WK->>WK: ghi revocation window, CEK exposure window
```

---

## 10. Cấu trúc EncryptedRecord (v4.2 — KEM 3 lớp)

```mermaid
flowchart LR
    DATA["data"] --> CA["cAEAD: HKDF(CEK) → K_enc, K_com<br/>AES-256-GCM + HMAC commit<br/>AAD = data_aad"]
    CEK(["CEK ngẫu nhiên<br/>(sinh mới khi Create / Update)"]) --> CA
    CEK --> W1["AES-GCM(k_abe, CEK)<br/>AAD = header_aad"]
    CEK --> W2["KEK wrap(CEK)<br/>context = record_id"]
    POL["policy_abe"] --> KEM["CP-ABE KEM (AbeProvider.encaps)"]
    KEM --> KABE(["k_abe"])
    KABE --> W1

    subgraph REC["EncryptedRecord"]
        M["record_id · version · content_version<br/>policy_abe · policy_ref · abe_backend"]
        H["abe_header = { kem, wrap }"]
        K["kek_header"]
        C["aead { alg, nonce, commit } · ciphertext"]
        S["owner_sig · log_index (tầng T5)"]
    end
    KEM --> H
    W1 --> H
    W2 --> K
    CA --> C
```

| Thao tác | abe_header | kek_header | ciphertext | version | content_version |
|---|---|---|---|---|---|
| Create | mới | mới | mới | 1 | 1 |
| Update nội dung | mới (CEK mới) | mới | mới | +1 | +1 |
| Đổi policy / thu hồi L1 | **mới** (CEK cũ) | giữ | **giữ** | +1 | giữ |
| Thu hồi L0 | mới (CEK mới) | mới | mới | +1 | +1 |

---

## 11. PoC phase 1 (v4.3): các docker image thực tế

```mermaid
flowchart LR
    subgraph HOST["docker compose — cpabe-v4"]
        subgraph TR["network: trusted"]
            AUTH["cpabe-v4/auth :8002<br/>login → JWT EdDSA<br/>thuộc tính user"]
            KGC["cpabe-v4/kgc :8001<br/>Setup · KeyGen · epoch · revoke<br/>MSK sealed"]
            KV["cpabe-v4/keyvault<br/>KEK wrap / unwrap"]
            CL["cpabe-v4/client (CLI)<br/>owner · user · admin · worker-rewrap<br/>Encrypt / Decrypt tại đây"]
        end
        APP["cpabe-v4/app :8000<br/>CRUD · kiểm version<br/>chặn user bị thu hồi<br/>không giữ khóa"]
        subgraph CLD["network: cloud"]
            DB[("outsource-db<br/>postgres:16-alpine<br/>encrypted_records")]
        end
    end

    CL -- "login" --> AUTH
    CL -- "fetch-key (JWT)" --> KGC
    KGC -- "thuộc tính (service token)" --> AUTH
    CL -- "wrap / unwrap CEK" --> KV
    CL -- "PUT / PATCH / GET / DELETE (JWT)" --> APP
    APP -- "revocation list" --> KGC
    APP -- "public key" --> AUTH
    KV -- "public key" --> AUTH
    APP -- "SQL (chỉ ciphertext)" --> DB
```
