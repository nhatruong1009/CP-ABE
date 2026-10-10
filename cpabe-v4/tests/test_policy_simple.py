import pytest

from cpabe.crypto.errors import AccessDenied
from cpabe.crypto.record import open_record, seal_record
from cpabe.policy.simple import compile_policy


def test_compile_basic():
    assert compile_policy("Dept:Cardiology AND Role:Doctor", 3) == \
        "(DEPTXCARDIOLOGYXV1 and ROLEXDOCTORXV1) and EPOCHX3"


def test_compile_nested_case_insensitive_ops():
    assert compile_policy("(Dept:Cardiology and Role:Doctor) or Role:Director", 1) == \
        "(( DEPTXCARDIOLOGYXV1 and ROLEXDOCTORXV1 ) or ROLEXDIRECTORXV1) and EPOCHX1"


@pytest.mark.parametrize("bad", ["", "NOT Role:Doctor", "Role:Doctor AND", "(Role:Doctor",
                                 "Role:Doctor Dept:X", "Role Doctor", "AND Role:Doctor"])
def test_compile_rejects(bad):
    with pytest.raises(ValueError):
        compile_policy(bad, 1)


def test_compiled_policy_works_with_fame(provider, mpk, msk, kek):
    pol = compile_policy("(Dept:Cardiology AND Role:Doctor) OR Role:Director", 1)
    rec = seal_record(provider, mpk, kek, record_id="P-1", policy_abe=pol, data=b"x")
    doctor = provider.keygen(mpk, msk, ["DEPTXCARDIOLOGYXV1", "ROLEXDOCTORXV1", "EPOCHX1"])
    nurse = provider.keygen(mpk, msk, ["DEPTXCARDIOLOGYXV1", "ROLEXNURSEXV1", "EPOCHX1"])
    assert open_record(mpk, doctor, rec) == b"x"
    with pytest.raises(AccessDenied):
        open_record(mpk, nurse, rec)
