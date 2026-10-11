package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"cpabe-demo/shared"
)

// Identity: khóa ABE mà user đang dùng (bình thường là khóa mới nhất; có thể chọn khóa cũ để demo).
type Identity struct {
	UserID string
	Name   string
	Epoch  int
	Latest bool
	Attrs  map[string]string
	Key    []byte
}

var (
	ErrNoAccess = errors.New("không đủ thuộc tính")
	ErrRetired  = errors.New("thế hệ khóa đã bị hủy")
)

// Vault: mọi thao tác mã hóa / giải mã / ký phía client. Plaintext không bao giờ rời khỏi app.
type Vault struct {
	cloud   *shared.CloudClient
	authPub []byte

	mu        sync.Mutex
	privCache map[string][]byte // private key của Policy đã mở bằng CP-ABE (1 lần cho mỗi chính sách)
}

// Session gom các lời gọi trong 1 request; chính sách chỉ tải 1 lần mỗi request.
type Session struct {
	v    *Vault
	ID   *Identity
	pols map[string]*shared.Policy
}

func (v *Vault) Session(id *Identity) *Session {
	return &Session{v: v, ID: id, pols: map[string]*shared.Policy{}}
}

// Policy tải chính sách từ cloud và KIỂM CHỮ KÝ authority, nên cloud không tráo được Policy Key.
func (s *Session) Policy(id string) (*shared.Policy, error) {
	if p, ok := s.pols[id]; ok {
		return p, nil
	}
	p, err := s.v.cloud.GetPolicy(id)
	if err != nil {
		return nil, err
	}
	if err := shared.VerifyPolicy(p, s.v.authPub); err != nil {
		return nil, err
	}
	s.pols[id] = p
	return p, nil
}

// openPriv mở private key của một thế hệ Policy Key / Write Key bằng CP-ABE (Tầng 1).
func (s *Session) openPriv(p *shared.Policy, gen int) ([]byte, error) {
	k := p.Key(gen)
	if k == nil {
		return nil, fmt.Errorf("không có thế hệ %d", gen)
	}
	if len(k.ABEWrappedPriv) == 0 {
		return nil, ErrRetired
	}
	if s.ID.Key == nil || !shared.ABECouldDecrypt(s.ID.Attrs, k.ABEWrappedPriv) {
		return nil, ErrNoAccess
	}
	sum := sha256.Sum256(k.ABEWrappedPriv)
	ck := fmt.Sprintf("%s|%d|%x", s.ID.UserID, s.ID.Epoch, sum)
	s.v.mu.Lock()
	priv, ok := s.v.privCache[ck]
	s.v.mu.Unlock()
	if ok {
		return priv, nil
	}
	priv, err := shared.ABEDecrypt(s.ID.Key, k.ABEWrappedPriv)
	if err != nil {
		return nil, ErrNoAccess
	}
	s.v.mu.Lock()
	s.v.privCache[ck] = priv
	s.v.mu.Unlock()
	return priv, nil
}

// CanWrite: user có mở được Write Key thế hệ HIỆN HÀNH không.
func (s *Session) CanWrite(writePolicyID string) bool {
	wp, err := s.Policy(writePolicyID)
	if err != nil {
		return false
	}
	_, err = s.openPriv(wp, wp.CurrentGen)
	return err == nil
}

type ReadResult struct {
	V            shared.DocVersion
	Payload      shared.Payload
	Status       string // ok | noaccess | retired | tampered | error
	Msg          string
	SigOK        bool
	ReadLogical  string
	WriteLogical string
	CurReadGen   int
	CurWriteGen  int
	CanWrite     bool
}

func (r ReadResult) OK() bool { return r.Status == "ok" }

func (s *Session) Read(v shared.DocVersion) ReadResult {
	res := ReadResult{V: v}
	rp, err := s.Policy(v.ReadPolicyID)
	if err != nil {
		res.Status, res.Msg = "error", err.Error()
		return res
	}
	wp, err := s.Policy(v.WritePolicyID)
	if err != nil {
		res.Status, res.Msg = "error", err.Error()
		return res
	}
	res.ReadLogical, res.WriteLogical = rp.Logical, wp.Logical
	res.CurReadGen, res.CurWriteGen = rp.CurrentGen, wp.CurrentGen
	res.CanWrite = s.CanWrite(v.WritePolicyID)

	// Chữ ký kiểm được mà không cần khóa bí mật nào.
	if wk := wp.Key(v.WriteGen); wk != nil {
		res.SigOK = shared.Verify(wk.PublicKey, v.SignedBytes(), v.Signature)
	}

	priv, err := s.openPriv(rp, v.ReadGen)
	switch {
	case errors.Is(err, ErrNoAccess):
		res.Status, res.Msg = "noaccess", "Không đủ thuộc tính để đọc"
		return res
	case errors.Is(err, ErrRetired):
		res.Status, res.Msg = "retired", "Thế hệ khóa đã bị hủy"
		return res
	case err != nil:
		res.Status, res.Msg = "error", err.Error()
		return res
	}
	dek, err := shared.UnwrapDEK(rp.Key(v.ReadGen).PublicKey, priv, v.WrappedDEK)
	if err == nil {
		res.Payload, err = shared.OpenPayload(dek, v.Nonce, v.Ciphertext, v.AAD())
	}
	if err != nil {
		res.Status, res.Msg = "tampered", "Bản mã bị sửa đổi: "+err.Error()
		return res
	}
	res.Status = "ok"
	if !res.SigOK {
		res.Msg = "Chữ ký ghi không hợp lệ"
	}
	return res
}

// Write tạo phiên bản mới: DEK mới, bọc bằng Policy Key đọc hiện hành, ký bằng Write Key hiện hành.
// Không cần quyền đọc: chỉ cần public key của Policy đọc.
func (s *Session) Write(docID string, version int, readPID, writePID string, p shared.Payload) error {
	rp, err := s.Policy(readPID)
	if err != nil {
		return err
	}
	wp, err := s.Policy(writePID)
	if err != nil {
		return err
	}
	wpriv, err := s.openPriv(wp, wp.CurrentGen)
	if err != nil {
		return fmt.Errorf("không có quyền ghi (%s): %w", wp.Logical, err)
	}
	v, err := shared.BuildVersion(docID, version, p, readPID, rp.Key(rp.CurrentGen), writePID, wp.CurrentGen, wpriv)
	if err != nil {
		return err
	}
	if version == 1 {
		return s.v.cloud.CreateDocument(v)
	}
	return s.v.cloud.AddVersion(v)
}

// Forge (kịch bản D): thử ghi khi KHÔNG có Write Key, tức ký bằng một khóa tự sinh. Cloud phải từ chối.
func (s *Session) Forge(docID string, version int, readPID, writePID string) error {
	rp, err := s.Policy(readPID)
	if err != nil {
		return err
	}
	wp, err := s.Policy(writePID)
	if err != nil {
		return err
	}
	_, fake, err := shared.NewWriteKeypair()
	if err != nil {
		return err
	}
	v, err := shared.BuildVersion(docID, version,
		shared.Payload{Title: "NỘI DUNG GIẢ MẠO", Body: "bị ghi đè bởi " + s.ID.Name, Author: s.ID.Name},
		readPID, rp.Key(rp.CurrentGen), writePID, wp.CurrentGen, fake)
	if err != nil {
		return err
	}
	return s.v.cloud.AddVersion(v)
}
