import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cpabe.crypto.attrs import attr_token as A, epoch_token as E  # noqa: E402
from cpabe.crypto.backends.fame import FameProvider  # noqa: E402
from cpabe.crypto.envelope import LocalKek  # noqa: E402

EPOCH = 7

USERS = {
    "doctor_cardio": [A("Dept", "Cardiology"), A("Role", "Doctor"), E(EPOCH)],
    "nurse_cardio": [A("Dept", "Cardiology"), A("Role", "Nurse"), E(EPOCH)],
    "doctor_peds": [A("Dept", "Pediatrics"), A("Role", "Doctor"), E(EPOCH)],
    "cashier": [A("Dept", "Finance"), A("Role", "Cashier"), E(EPOCH)],
    "director": [A("Role", "Director"), E(EPOCH)],
}

# Bản ghi lâm sàng: chỉ bác sĩ Tim mạch hoặc Giám đốc, trong epoch hiện tại.
CLINICAL_POLICY = (
    f"(({A('Dept', 'Cardiology')} and {A('Role', 'Doctor')}) or {A('Role', 'Director')})"
    f" and {E(EPOCH)}"
)
PLAINTEXT = "Chẩn đoán: rung nhĩ. Điều trị: kháng đông.".encode("utf-8")


@pytest.fixture(scope="session")
def provider():
    return FameProvider()


@pytest.fixture(scope="session")
def keys(provider):
    mpk, msk = provider.setup()
    return mpk, msk


@pytest.fixture(scope="session")
def mpk(keys):
    return keys[0]


@pytest.fixture(scope="session")
def msk(keys):
    return keys[1]


@pytest.fixture(scope="session")
def kek():
    return LocalKek.generate()


@pytest.fixture(scope="session")
def user_keys(provider, mpk, msk):
    return {name: provider.keygen(mpk, msk, attrs) for name, attrs in USERS.items()}
