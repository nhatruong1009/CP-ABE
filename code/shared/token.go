package shared

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// AccessToken (C2): authority ký, cloud-api kiểm bằng public key của authority.
// Mang thuộc tính HIỆN HÀNH (có version) của user để cloud quyết định có trả bản mã hay không.
// Đánh đổi: cloud biết thuộc tính của người đang gọi.
type AccessToken struct {
	UserID string            `json:"sub"`
	Attrs  map[string]string `json:"attrs"`
	Exp    time.Time         `json:"exp"`
}

const TokenTTL = 5 * time.Minute

var b64 = base64.RawURLEncoding

// SignToken trả chuỗi "<payload>.<chữ ký>", cả hai mã hóa base64url.
func SignToken(priv []byte, t *AccessToken) (string, error) {
	body, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	sig, err := Sign(priv, digest([]byte("access-token"), body))
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(body) + "." + b64.EncodeToString(sig), nil
}

// ParseToken kiểm chữ ký và hạn dùng.
func ParseToken(pub []byte, s string) (*AccessToken, error) {
	bodyS, sigS, ok := strings.Cut(s, ".")
	if !ok {
		return nil, errors.New("token sai định dạng")
	}
	body, err1 := b64.DecodeString(bodyS)
	sig, err2 := b64.DecodeString(sigS)
	if err1 != nil || err2 != nil {
		return nil, errors.New("token sai định dạng")
	}
	if !Verify(pub, digest([]byte("access-token"), body), sig) {
		return nil, errors.New("chữ ký token không hợp lệ")
	}
	var t AccessToken
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, err
	}
	if time.Now().After(t.Exp) {
		return nil, errors.New("token đã hết hạn")
	}
	return &t, nil
}
