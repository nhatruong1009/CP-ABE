package shared

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// ---- Tầng 3: DEK + AES-256-GCM cho nội dung ----

func RandomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func newGCM(dek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// SealPayload mã hóa {tiêu đề, nội dung} bằng DEK. aad gắn bản mã với (doc_id, version).
func SealPayload(dek []byte, p Payload, aad []byte) (nonce, ct []byte, err error) {
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, nil, err
	}
	plain, err := json.Marshal(p)
	if err != nil {
		return nil, nil, err
	}
	nonce = RandomBytes(gcm.NonceSize())
	return nonce, gcm.Seal(nil, nonce, plain, aad), nil
}

var ErrIntegrity = errors.New("bản mã bị sửa đổi (AES-GCM không hợp lệ)")

func OpenPayload(dek, nonce, ct, aad []byte) (Payload, error) {
	p, _, err := OpenPayloadRaw(dek, nonce, ct, aad)
	return p, err
}

// OpenPayloadRaw trả thêm plaintext thô (JSON) để UI hiển thị quy trình giải mã.
func OpenPayloadRaw(dek, nonce, ct, aad []byte) (Payload, []byte, error) {
	var p Payload
	gcm, err := newGCM(dek)
	if err != nil {
		return p, nil, err
	}
	plain, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return p, nil, ErrIntegrity
	}
	err = json.Unmarshal(plain, &p)
	return p, plain, err
}

// ---- Tầng 2: Policy Key đọc (X25519 sealed box) ----

// NewReadKeypair sinh cặp khóa của một Policy Key đọc.
func NewReadKeypair() (pub, priv []byte, err error) {
	pk, sk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pk[:], sk[:], nil
}

// WrapDEK bọc DEK bằng public key của Policy: ai cũng làm được (cho phép "ghi mà không đọc").
func WrapDEK(pub, dek []byte) ([]byte, error) {
	if len(pub) != 32 {
		return nil, fmt.Errorf("public key policy sai độ dài: %d", len(pub))
	}
	return box.SealAnonymous(nil, dek, (*[32]byte)(pub), rand.Reader)
}

// UnwrapDEK mở DEK, cần private key của Policy (chỉ có được qua CP-ABE).
func UnwrapDEK(pub, priv, wrapped []byte) ([]byte, error) {
	if len(pub) != 32 || len(priv) != 32 {
		return nil, errors.New("khóa policy sai độ dài")
	}
	dek, ok := box.OpenAnonymous(nil, wrapped, (*[32]byte)(pub), (*[32]byte)(priv))
	if !ok {
		return nil, ErrIntegrity
	}
	return dek, nil
}

// ---- Write Key (Ed25519) ----

func NewWriteKeypair() (pub, priv []byte, err error) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pk, sk, nil
}

func Sign(priv, msg []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("write key sai độ dài")
	}
	return ed25519.Sign(ed25519.PrivateKey(priv), msg), nil
}

func Verify(pub, msg, sig []byte) bool {
	return len(pub) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// MustSign dùng khi khóa ký chắc chắn hợp lệ (khóa của authority).
func MustSign(priv, msg []byte) []byte {
	sig, err := Sign(priv, msg)
	if err != nil {
		panic(err)
	}
	return sig
}

// NewDocID sinh mã tài liệu ngẫu nhiên (không lộ thông tin gì về nội dung).
func NewDocID() string {
	return fmt.Sprintf("%x", RandomBytes(8))
}
