"""Kịch bản kiểm chứng tầng T2/T3: A, B, F, F2, K1, K2 (+ các test cơ bản)."""
import copy
import json

import pytest

from cpabe.crypto.attrs import attr_token as A, epoch_token as E
from cpabe.crypto.errors import AccessDenied, CommitmentError, IntegrityError
from cpabe.crypto.record import open_record, rewrap_header, seal_record, unwrap_cek
from tests.conftest import CLINICAL_POLICY, EPOCH, PLAINTEXT


@pytest.fixture()
def record(provider, mpk, kek):
    return seal_record(provider, mpk, kek, record_id="BA-0001",
                       policy_abe=CLINICAL_POLICY, data=PLAINTEXT)


def _merge_keys(provider, k1: dict, k2: dict) -> dict:
    """Tấn công ghép key: lấy mọi thành phần theo thuộc tính từ cả hai khóa.
    Trường dạng dict (theo thuộc tính) được hợp lại, trường khác lấy từ k1."""
    o1, o2 = provider._load(k1), provider._load(k2)
    merged = {}
    for field in o1:
        v1, v2 = o1[field], o2.get(field)
        if isinstance(v1, dict) and isinstance(v2, dict):
            merged[field] = {**v2, **v1}
        elif field == "attr_list":
            merged[field] = list(dict.fromkeys(list(v1) + list(v2)))
        else:
            merged[field] = v1
    return provider._dump(merged)


# --- cơ bản ------------------------------------------------------------------
def test_authorized_users_can_read(mpk, user_keys, record):
    assert open_record(mpk, user_keys["doctor_cardio"], record) == PLAINTEXT
    assert open_record(mpk, user_keys["director"], record) == PLAINTEXT


def test_record_is_json_serializable(record):
    json.dumps(record)  # lưu được vào PostgreSQL dạng JSONB


def test_update_uses_fresh_cek(provider, mpk, kek, record):
    updated = seal_record(provider, mpk, kek, record_id="BA-0001", policy_abe=CLINICAL_POLICY,
                          data=b"noi dung moi", version=2, content_version=2)
    assert unwrap_cek(kek, updated) != unwrap_cek(kek, record)


# --- A: DBA của cloud đọc trực tiếp DB ------------------------------------------
def test_A_cloud_view_has_no_plaintext(record):
    dump = json.dumps(record, ensure_ascii=False).encode("utf-8")
    assert PLAINTEXT not in dump
    assert "rung nhĩ".encode("utf-8") not in dump


# --- B: user không đủ thuộc tính --------------------------------------------------
@pytest.mark.parametrize("who", ["nurse_cardio", "doctor_peds", "cashier"])
def test_B_unauthorized_user_cannot_read(mpk, user_keys, record, who):
    with pytest.raises(AccessDenied):
        open_record(mpk, user_keys[who], record)


# --- F: hai user ghép khóa ------------------------------------------------------------
def test_F_collusion_nurse_cardio_plus_doctor_peds(provider, mpk, user_keys, record):
    # Mỗi người thiếu một thuộc tính; gộp lại thì "đủ" DEPTxCARDIOLOGY + ROLExDOCTOR.
    forged = _merge_keys(provider, user_keys["nurse_cardio"], user_keys["doctor_peds"])
    # Prune "thỏa" vì attr_list đã gộp, nhưng thành phần khóa mang giá trị ngẫu nhiên của
    # hai user khác nhau nên KEM không khớp: phải là IntegrityError, không phải AccessDenied.
    with pytest.raises(IntegrityError):
        open_record(mpk, forged, record)


# --- F2: ghép khóa cũ và khóa mới của cùng một user ----------------------------
def test_F2_old_and_new_key_of_same_user(provider, mpk, msk, kek):
    new_epoch = EPOCH + 1
    # Trước: y tá Tim mạch ở epoch 7. Sau: chuyển sang Finance, được cấp khóa epoch 8.
    old_key = provider.keygen(mpk, msk, [A("Dept", "Cardiology"), A("Role", "Nurse"), E(EPOCH)])
    new_key = provider.keygen(mpk, msk, [A("Dept", "Finance"), A("Role", "Nurse"), E(new_epoch)])
    policy = f"{A('Dept', 'Cardiology')} and {A('Role', 'Nurse')} and {E(new_epoch)}"
    rec = seal_record(provider, mpk, kek, record_id="BA-0002", policy_abe=policy, data=PLAINTEXT)

    for k in (old_key, new_key):
        with pytest.raises(AccessDenied):
            open_record(mpk, k, rec)
    forged = _merge_keys(provider, old_key, new_key)
    with pytest.raises(IntegrityError):
        open_record(mpk, forged, rec)


# --- K1: ciphertext "nhiều khóa" / commit không khớp ----------------------------------
def test_K1_ciphertext_from_other_cek_rejected_by_commit(provider, mpk, kek, user_keys, record):
    other = seal_record(provider, mpk, kek, record_id="BA-0001", policy_abe=CLINICAL_POLICY,
                        data=b"noi dung gia")
    forged = copy.deepcopy(record)
    forged["ciphertext"] = other["ciphertext"]
    forged["aead"] = other["aead"]
    with pytest.raises(CommitmentError):
        open_record(mpk, user_keys["doctor_cardio"], forged)


def test_K1_content_version_tamper_rejected(mpk, user_keys, record):
    forged = copy.deepcopy(record)
    forged["content_version"] += 1
    with pytest.raises(CommitmentError):
        open_record(mpk, user_keys["doctor_cardio"], forged)


# --- K2: tráo header / sửa metadata --------------------------------------------------
def test_K2_header_swapped_from_other_record(provider, mpk, kek, user_keys, record):
    other = seal_record(provider, mpk, kek, record_id="BA-9999", policy_abe=CLINICAL_POLICY,
                        data=b"ban ghi khac")
    forged = copy.deepcopy(record)
    forged["abe_header"] = other["abe_header"]
    with pytest.raises(IntegrityError):
        open_record(mpk, user_keys["doctor_cardio"], forged)


def test_K2_kek_header_swapped_from_other_record(provider, mpk, kek, record):
    other = seal_record(provider, mpk, kek, record_id="BA-9999", policy_abe=CLINICAL_POLICY,
                        data=b"ban ghi khac")
    forged = copy.deepcopy(record)
    forged["kek_header"] = other["kek_header"]
    with pytest.raises(IntegrityError):
        unwrap_cek(kek, forged)


def test_K2_version_tamper_rejected(mpk, user_keys, record):
    forged = copy.deepcopy(record)
    forged["version"] += 1
    with pytest.raises(IntegrityError):
        open_record(mpk, user_keys["doctor_cardio"], forged)


def test_K2_policy_widened_by_cloud_rejected(mpk, user_keys, record):
    # Cloud sửa policy_abe để y tá "thỏa" policy -> phải thất bại.
    forged = copy.deepcopy(record)
    forged["policy_abe"] = f"{A('Role', 'Nurse')} and {E(EPOCH)}"
    with pytest.raises(IntegrityError):
        open_record(mpk, user_keys["nurse_cardio"], forged)


# --- Re-wrap / đổi policy (chuẩn bị cho T6) ------------------------------------------
def test_rewrap_keeps_ciphertext_and_changes_access(provider, mpk, kek, user_keys, record):
    new_policy = f"{A('Dept', 'Cardiology')} and {A('Role', 'Nurse')} and {E(EPOCH)}"
    out = rewrap_header(provider, mpk, kek, record, new_policy_abe=new_policy)
    assert out["ciphertext"] == record["ciphertext"]  # dữ liệu giữ nguyên (L1)
    assert out["version"] == record["version"] + 1
    assert open_record(mpk, user_keys["nurse_cardio"], out) == PLAINTEXT
    with pytest.raises(AccessDenied):
        open_record(mpk, user_keys["doctor_cardio"], out)


# --- token thuộc tính an toàn cho Charm -----------------------------------------
@pytest.mark.parametrize("bad", ["EPOCH_7", "DEPTxCARDIOLOGYxV1", "Dept:Cardiology"])
def test_bad_tokens_rejected(provider, mpk, msk, bad):
    with pytest.raises(ValueError):
        provider.keygen(mpk, msk, [bad])
    with pytest.raises(ValueError):
        provider.encaps(mpk, f"{bad} and {E(EPOCH)}")


def test_epoch_tokens_are_distinct_after_charm_parsing(provider, mpk, msk, kek):
    # Hồi quy cho strip_index: EPOCH 7 và EPOCH 8 không được bị coi là cùng thuộc tính.
    k7 = provider.keygen(mpk, msk, [A("Role", "Doctor"), E(7)])
    rec8 = seal_record(provider, mpk, kek, record_id="BA-0003",
                       policy_abe=f"{A('Role', 'Doctor')} and {E(8)}", data=PLAINTEXT)
    with pytest.raises(AccessDenied):
        open_record(mpk, k7, rec8)
