// Package shared chứa phần dùng chung cho cả 3 service:
// lớp CP-ABE (Tầng 1), Policy Key + DEK (Tầng 2-3), chữ ký ghi, kiểu dữ liệu và client gọi cloud.
package shared

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/abe/cpabe/tkn20"
)

// ABESetup sinh cặp Public Key / Master Secret Key của hệ thống (chỉ authority gọi).
func ABESetup() (pk, msk []byte, err error) {
	pub, sec, err := tkn20.Setup(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if pk, err = pub.MarshalBinary(); err != nil {
		return nil, nil, err
	}
	if msk, err = sec.MarshalBinary(); err != nil {
		return nil, nil, err
	}
	return pk, msk, nil
}

// ABEKeyGen cấp khóa bí mật cho một tập thuộc tính, vd. {"dept_finance": "v3"}.
func ABEKeyGen(mskBytes []byte, attrs map[string]string) ([]byte, error) {
	var msk tkn20.SystemSecretKey
	if err := msk.UnmarshalBinary(mskBytes); err != nil {
		return nil, fmt.Errorf("đọc master key: %w", err)
	}
	var a tkn20.Attributes
	a.FromMap(attrs)
	key, err := msk.KeyGen(rand.Reader, a)
	if err != nil {
		return nil, err
	}
	return key.MarshalBinary()
}

// ABEEncrypt mã hóa msg theo chính sách dạng chuỗi, vd. "(dept_finance: v3) or (role_director: v1)".
func ABEEncrypt(pkBytes []byte, policy string, msg []byte) ([]byte, error) {
	var pk tkn20.PublicKey
	if err := pk.UnmarshalBinary(pkBytes); err != nil {
		return nil, fmt.Errorf("đọc public key: %w", err)
	}
	var p tkn20.Policy
	if err := p.FromString(policy); err != nil {
		return nil, fmt.Errorf("chính sách không hợp lệ %q: %w", policy, err)
	}
	return pk.Encrypt(rand.Reader, p, msg)
}

// ABEDecrypt giải mã; lỗi nếu thuộc tính trong khóa không thỏa chính sách.
func ABEDecrypt(keyBytes, ct []byte) ([]byte, error) {
	var k tkn20.AttributeKey
	if err := k.UnmarshalBinary(keyBytes); err != nil {
		return nil, fmt.Errorf("đọc khóa thuộc tính: %w", err)
	}
	return k.Decrypt(ct)
}

// ABECouldDecrypt kiểm tra nhanh (không giải mã) tập thuộc tính có thỏa chính sách gắn trong bản mã không.
func ABECouldDecrypt(attrs map[string]string, ct []byte) bool {
	var a tkn20.Attributes
	a.FromMap(attrs)
	return a.CouldDecrypt(ct)
}

// ABEValidatePolicy kiểm tra cú pháp chính sách theo DSL của CIRCL.
func ABEValidatePolicy(policy string) error {
	var p tkn20.Policy
	return p.FromString(policy)
}
