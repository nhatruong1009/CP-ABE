# Một image chứa cả 3 binary (authority, app, cloudapi). docker-compose chọn binary bằng `command`.
FROM golang:1.26-alpine AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=auto
WORKDIR /src
COPY go.mod go.sum* ./
COPY shared ./shared
COPY authority ./authority
COPY app ./app
COPY cloudapi ./cloudapi
# go mod tidy tải thư viện (CIRCL, x/crypto, pgx) và sinh go.sum ngay trong lúc build.
RUN go mod tidy && go vet ./... && \
    go build -o /out/authority ./authority && \
    go build -o /out/app ./app && \
    go build -o /out/cloudapi ./cloudapi

FROM alpine:3.20
RUN adduser -D -u 10001 svc && mkdir -p /data /keystore && chown svc /data /keystore
COPY --from=build /out/ /usr/local/bin/
COPY --from=build /src/go.mod /src/go.sum /opt/build-info/
USER svc
