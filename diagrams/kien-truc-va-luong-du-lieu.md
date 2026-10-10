# Sơ đồ kiến trúc & luồng dữ liệu — CP-ABE: thao tác dữ liệu & thu hồi khóa

> Ứng với thiết kế **v3**: `analysis/02_ke-hoach-cai-thien-1-tuan.md`.
> Xem trong VS Code bằng extension *Markdown Preview Mermaid Support*, hoặc mở file `.html` cùng tên bằng trình duyệt. Muốn xuất PNG/SVG thì dán từng khối vào https://mermaid.live.

---

## 1. Kiến trúc tổng thể

```mermaid
flowchart LR
    subgraph TZ["VÙNG TIN CẬY — Tổ chức"]
        direction TB
        DO["Data Owner Client<br/>Create · Update · Đổi policy · Delete"]
        UC["User Client<br/>Read (Decrypt cục bộ)"]
        subgraph KGCZ["Key Generation Center"]
            KG["KGC Service<br/>Setup · KeyGen · Revoke<br/>Epoch · Attribute version"]
            KS[("MSK + KEK")]
        end
        APP["Application Server<br/>CRUD API · Revocation list<br/>Re-wrap / Re-encrypt job"]
    end

    subgraph UZ["VÙNG KHÔNG TIN CẬY — Cloud"]
        ST[("Ciphertext Store<br/>EncryptedRecord")]
    end

    KG --- KS
    KG -- "MPK + epoch/version hiện tại" --> DO
    KG -- "SK(thuộc tính)" --> UC
    DO -- "EncryptedRecord" --> APP
    UC -- "yêu cầu đọc" --> APP
    APP -- "EncryptedRecord" --> UC
    APP <-->|"chỉ ciphertext"| ST
    KG -- "revoke → revocation list, kích hoạt job" --> APP
    APP -. "Unwrap CEK khi re-wrap" .-> KS

    classDef trusted fill:#e8f5e9,stroke:#2e7d32,color:#1b5e20
    classDef untrusted fill:#fdecea,stroke:#c62828,color:#7f0000
    classDef secret fill:#fff8e1,stroke:#f9a825,color:#5d4037
    class DO,UC,KG,APP trusted
    class ST untrusted
    class KS secret
```

---

## 2. Cấu trúc bản ghi mã hóa (mã hóa lai, CEK bọc kép)

```mermaid
flowchart LR
    D["Dữ liệu gốc"] --> AES["AES-256-GCM"]
    CEK(["CEK ngẫu nhiên"]) --> AES
    CEK --> ABE["CP-ABE.Encrypt<br/>(MPK, policy)"]
    CEK --> WR["Wrap(KEK)"]
    POL["policy<br/>(Dept:Cardiology AND Role:Doctor)<br/>OR Role:Director"] --> ABE

    subgraph ER["EncryptedRecord trên cloud"]
        M["record_id · version · policy · policy_version"]
        H1["abe_header — dành cho user"]
        H2["kek_header — dành cho hệ thống"]
        C["nonce · ciphertext"]
    end
    AES --> C
    ABE --> H1
    WR --> H2
```

---

## 3. Setup & cấp khóa

```mermaid
sequenceDiagram
    autonumber
    actor Admin
    participant KGC
    actor U as User

    Admin->>KGC: Setup()
    KGC->>KGC: sinh MSK, MPK, KEK, epoch = 1, version mọi thuộc tính = 1
    U->>KGC: đăng nhập + xin khóa
    KGC->>KGC: tra thuộc tính: Dept, Role
    KGC-->>U: SK = KeyGen(MSK, Dept@v, Role@v, Epoch:e)
```

---

## 4. Create & Read

```mermaid
sequenceDiagram
    autonumber
    participant DO as Data Owner
    participant APP as App Server
    participant ST as Cloud
    actor U as User

    rect rgb(232,245,233)
    Note over DO,ST: CREATE
    DO->>DO: CEK mới, ciphertext = AES-GCM(CEK, data)
    DO->>DO: abe_header = CPABE.Encrypt(MPK, CEK, policy AND Epoch:e)
    DO->>DO: kek_header = Wrap(KEK, CEK)
    DO->>APP: POST /records
    APP->>ST: lưu EncryptedRecord (version 1)
    end

    rect rgb(227,242,253)
    Note over U,ST: READ
    U->>APP: GET /records/id
    APP->>APP: user có trong revocation list?
    alt bị thu hồi
        APP-->>U: 403
    else hợp lệ
        APP->>ST: lấy EncryptedRecord
        APP-->>U: EncryptedRecord
        U->>U: CEK = CPABE.Decrypt(SK, abe_header)
        alt thuộc tính không thỏa policy
            U->>U: thất bại — không có quyền
        else thỏa
            U->>U: data = AES-GCM.Decrypt(CEK, ciphertext)
        end
    end
    end
```

---

## 5. Update, Đổi policy, Delete

```mermaid
sequenceDiagram
    autonumber
    participant DO as Data Owner
    participant APP as App Server
    participant ST as Cloud

    rect rgb(255,248,225)
    Note over DO,ST: UPDATE NỘI DUNG — CEK mới, dữ liệu mã hóa lại
    DO->>DO: CEK' mới, ciphertext' = AES-GCM(CEK', data mới)
    DO->>DO: abe_header' và kek_header' bọc CEK'
    DO->>APP: PUT /records/id
    APP->>ST: ghi đè, version + 1
    end

    rect rgb(243,229,245)
    Note over DO,ST: ĐỔI POLICY — giữ CEK, chỉ bọc lại header
    DO->>APP: PATCH /records/id/policy (policy mới)
    APP->>ST: đọc kek_header
    APP->>APP: CEK = Unwrap(KEK, kek_header)
    APP->>APP: abe_header' = CPABE.Encrypt(MPK, CEK, policy mới)
    APP->>ST: ghi abe_header', policy_version + 1
    Note over APP: Nếu thu hẹp quyền và cần chặn CEK đã cache, dùng UPDATE thay thế
    end

    rect rgb(253,236,234)
    Note over DO,ST: DELETE
    DO->>APP: DELETE /records/id
    APP->>ST: xóa bản ghi và kek_header
    end
```

---

## 6. Thu hồi R1 — Epoch (thu hồi một user)

```mermaid
sequenceDiagram
    autonumber
    actor Admin
    participant KGC
    participant APP as App Server
    participant ST as Cloud
    actor R as User còn hợp lệ

    Admin->>KGC: revoke(user X)
    KGC->>APP: thêm X vào revocation list
    Note over APP: Lớp vận hành — X bị chặn ngay
    KGC->>KGC: epoch e chuyển thành e+1
    KGC-->>R: cấp lại SK với Epoch:e+1 (mọi user còn hợp lệ)
    KGC->>APP: chạy job re-wrap
    loop mọi bản ghi
        APP->>ST: đọc kek_header
        APP->>APP: CEK = Unwrap(KEK), abe_header' = CPABE.Encrypt(CEK, policy AND Epoch:e+1)
        APP->>ST: ghi abe_header'
    end
    Note over APP,ST: Lớp mật mã — SK cũ của X (Epoch:e) không mở được header mới
    opt L2 — lazy re-encryption
        APP->>ST: dần dần thay CEK mới + mã hóa lại dữ liệu (job nền / lần Update kế tiếp)
    end
```

---

## 7. Thu hồi R2 — Attribute versioning (thu hồi một thuộc tính)

```mermaid
sequenceDiagram
    autonumber
    actor Admin
    participant KGC
    participant APP as App Server
    participant ST as Cloud
    actor Y as Y tá (chuyển khoa)
    actor O as User khác có Dept:Cardiology

    Admin->>KGC: gỡ Dept:Cardiology khỏi Y tá, thêm Dept:Finance
    KGC->>KGC: Dept:Cardiology v1 chuyển thành v2
    KGC-->>O: cấp lại SK chứa Dept:Cardiology@v2 (chỉ user có thuộc tính này)
    KGC-->>Y: cấp SK mới chứa Dept:Finance@v1
    KGC->>APP: re-wrap các bản ghi có Dept:Cardiology trong policy
    loop chỉ các bản ghi liên quan
        APP->>APP: CEK = Unwrap(KEK), abe_header' theo policy với Dept:Cardiology@v2
        APP->>ST: ghi abe_header'
    end
    Note over ST: Bản ghi không chứa Dept:Cardiology giữ nguyên
```

---

## 8. So sánh các chiến lược thu hồi (khung thí nghiệm RQ2)

```mermaid
flowchart TB
    REQ["Yêu cầu thu hồi"] --> OP["Lớp vận hành:<br/>revocation list — hiệu lực ngay"]
    REQ --> Q{"Thu hồi gì?"}
    Q -- "cả user" --> R1["R1 Epoch<br/>cấp lại SK: mọi user<br/>bọc lại: mọi bản ghi"]
    Q -- "một thuộc tính" --> R2["R2 Attribute version<br/>cấp lại SK: user có thuộc tính<br/>bọc lại: bản ghi liên quan"]
    R1 --> L{"Xử lý dữ liệu"}
    R2 --> L
    L --> L0["L0 Re-encrypt toàn bộ ngay<br/>an toàn nhất · tốn nhất"]
    L --> L1["L1 Chỉ bọc lại header<br/>rẻ nhất · CEK cache vẫn mở được bản cũ"]
    L --> L2["L2 Bọc header + lazy re-encryption<br/>cân bằng"]
```
