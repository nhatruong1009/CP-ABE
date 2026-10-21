package shared

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"time"
)

const (
	KindRead  = "read"
	KindWrite = "write"
)

// PolicyHeader: thông tin công khai của một chính sách, lưu trên cloud.
// Sig do authority ký để cloud không thể tráo khóa hay đổi thế hệ hiện hành.
type PolicyHeader struct {
	PolicyID   string `json:"policy_id"`
	Kind       string `json:"kind"`
	Logical    string `json:"logical_expr"`
	CurrentGen int    `json:"current_gen"`
	Sig        []byte `json:"header_sig"`
}

// PolicyKey: một thế hệ của Policy Key (đọc: X25519; ghi: Ed25519).
// ABEWrappedPriv = private key được mã hóa CP-ABE theo Compiled; rỗng nghĩa là thế hệ đã bị hủy.
type PolicyKey struct {
	PolicyID       string `json:"policy_id"`
	Gen            int    `json:"gen"`
	Compiled       string `json:"compiled_expr"`
	PublicKey      []byte `json:"public_key"`
	ABEWrappedPriv []byte `json:"abe_wrapped_priv,omitempty"`
	Sig            []byte `json:"key_sig"`
}

type Policy struct {
	PolicyHeader
	Keys []PolicyKey `json:"keys"`
}

func (p *Policy) Key(gen int) *PolicyKey {
	for i := range p.Keys {
		if p.Keys[i].Gen == gen {
			return &p.Keys[i]
		}
	}
	return nil
}

// DocVersion: một phiên bản tài liệu đúng như cloud lưu, toàn bộ là bản mã.
type DocVersion struct {
	DocID         string    `json:"doc_id"`
	Version       int       `json:"version"`
	ReadPolicyID  string    `json:"read_policy_id"`
	ReadGen       int       `json:"read_gen"`
	WrappedDEK    []byte    `json:"wrapped_dek"`
	Nonce         []byte    `json:"nonce"`
	Ciphertext    []byte    `json:"ciphertext"`
	WritePolicyID string    `json:"write_policy_id"`
	WriteGen      int       `json:"write_gen"`
	Signature     []byte    `json:"signature"`
	CreatedAt     time.Time `json:"created_at"`
	// Withheld (C2): cloud không trả wrapped_dek / nonce / ciphertext vì token không thỏa chính sách đọc.
	Withheld bool `json:"withheld,omitempty"`
}

// Payload: phần plaintext, chỉ tồn tại trong vùng tin cậy.
type Payload struct {
	Title  string `json:"title"`
	Body   string `json:"body"`
	Author string `json:"author"`
}

// ---- Thông điệp được ký ----

func digest(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(p)))
		h.Write(l[:])
		h.Write(p)
	}
	return h.Sum(nil)
}

func itob(i int) []byte { return []byte(strconv.Itoa(i)) }

// SignedBytes của phiên bản tài liệu. Cố ý KHÔNG gồm read_gen và wrapped_dek,
// để chế độ Eager bọc lại DEK mà không phải ký lại. Nếu cloud tráo DEK thì AES-GCM sẽ báo lỗi.
func (v *DocVersion) SignedBytes() []byte {
	return digest([]byte("doc-version"), []byte(v.DocID), itob(v.Version),
		[]byte(v.ReadPolicyID), []byte(v.WritePolicyID), itob(v.WriteGen), v.Nonce, v.Ciphertext)
}

// AAD cho AES-GCM.
func (v *DocVersion) AAD() []byte {
	return []byte(fmt.Sprintf("%s:%d", v.DocID, v.Version))
}

func (h *PolicyHeader) SignedBytes() []byte {
	return digest([]byte("policy-header"), []byte(h.PolicyID), []byte(h.Kind), []byte(h.Logical), itob(h.CurrentGen))
}

func (k *PolicyKey) SignedBytes(kind string) []byte {
	return digest([]byte("policy-key"), []byte(k.PolicyID), []byte(kind), itob(k.Gen), k.PublicKey)
}

// VerifyPolicy kiểm chữ ký authority trên header và mọi thế hệ khóa.
func VerifyPolicy(p *Policy, authorityPub []byte) error {
	if !Verify(authorityPub, p.PolicyHeader.SignedBytes(), p.Sig) {
		return errors.New("chữ ký authority trên chính sách không hợp lệ")
	}
	for i := range p.Keys {
		k := &p.Keys[i]
		if k.PolicyID != p.PolicyID || !Verify(authorityPub, k.SignedBytes(p.Kind), k.Sig) {
			return fmt.Errorf("chữ ký authority trên khóa thế hệ %d không hợp lệ", k.Gen)
		}
	}
	return nil
}

// BuildVersion: Tầng 3 + chữ ký. Sinh DEK MỚI mỗi lần (lazy re-encryption),
// bọc DEK bằng Policy Key đọc thế hệ hiện hành, ký bằng Write Key thế hệ hiện hành.
func BuildVersion(docID string, version int, p Payload, readPolicyID string, readKey *PolicyKey,
	writePolicyID string, writeGen int, writePriv []byte) (*DocVersion, error) {
	v := &DocVersion{
		DocID: docID, Version: version,
		ReadPolicyID: readPolicyID, ReadGen: readKey.Gen,
		WritePolicyID: writePolicyID, WriteGen: writeGen,
	}
	dek := RandomBytes(32)
	var err error
	if v.Nonce, v.Ciphertext, err = SealPayload(dek, p, v.AAD()); err != nil {
		return nil, err
	}
	if v.WrappedDEK, err = WrapDEK(readKey.PublicKey, dek); err != nil {
		return nil, err
	}
	if v.Signature, err = Sign(writePriv, v.SignedBytes()); err != nil {
		return nil, err
	}
	return v, nil
}
