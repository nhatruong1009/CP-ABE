# Image chứa Charm-crypto (pairing-based crypto) cho lõi CP-ABE.
# Charm cần PBC + GMP; dùng Python 3.9 vì Charm chưa ổn định trên các bản Python mới.
FROM python:3.9-slim-bookworm

ARG PBC_VERSION=0.5.14
# Charm 0.63 — commit đã build và chạy test thành công (2026-10-10).
ARG CHARM_REF=b2db00be7adf681c6bc35d35be3682ba047b3577

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential flex bison m4 wget git ca-certificates \
        libgmp-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# PBC (Pairing-Based Cryptography library)
RUN wget -q https://crypto.stanford.edu/pbc/files/pbc-${PBC_VERSION}.tar.gz \
    && tar xzf pbc-${PBC_VERSION}.tar.gz \
    && cd pbc-${PBC_VERSION} && ./configure && make && make install \
    && cd .. && rm -rf pbc-${PBC_VERSION}* && ldconfig

# Charm phụ thuộc pyparsing 2.x (API cũ)
RUN pip install --no-cache-dir "pyparsing>=2.1.5,<3"

RUN git clone https://github.com/JHUISI/charm.git /opt/charm \
    && cd /opt/charm && git checkout ${CHARM_REF} \
    && ./configure.sh && make && make install && ldconfig

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /app

# Mã nguồn (service images dùng chung Dockerfile này, khác nhau ở command)
ENV PYTHONPATH=/app PYTHONUNBUFFERED=1
COPY cpabe /app/cpabe
