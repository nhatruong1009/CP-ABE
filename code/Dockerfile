# Một image chứa cả 3 binary (authority, app, cloudapi). docker-compose chọn binary bằng `command`.
FROM golang:1.26-alpine AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=auto
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY shared ./shared
COPY authority ./authority
COPY app ./app
COPY cloudapi ./cloudapi
COPY bench ./bench
# Phiên bản thư viện được cố định trong go.mod / go.sum.
RUN go vet ./... && \
    go build -o /out/authority ./authority && \
    go build -o /out/app ./app && \
    go build -o /out/cloudapi ./cloudapi && \
    go build -o /out/bench ./bench

FROM alpine:3.20
RUN adduser -D -u 10001 svc && mkdir -p /data /keystore && chown svc /data /keystore
COPY --from=build /out/ /usr/local/bin/
USER svc
