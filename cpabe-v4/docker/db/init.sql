-- Outsource database (vùng cloud, không tin cậy): chỉ lưu EncryptedRecord.
CREATE TABLE IF NOT EXISTS encrypted_records (
    record_id        TEXT PRIMARY KEY,
    version          INTEGER NOT NULL CHECK (version >= 1),
    content_version  INTEGER NOT NULL CHECK (content_version >= 1),
    doc              JSONB   NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
