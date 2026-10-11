package main

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// State là toàn bộ dữ liệu của authority, lưu thành 1 file JSON trên volume (vùng tin cậy).
// Dùng JSON cho dễ mở ra xem khi demo; hệ thống thật nên dùng DB + HSM cho MSK.
type State struct {
	PK         []byte                `json:"abe_public_key"`
	MSK        []byte                `json:"abe_master_secret_key"`
	SignKey    ed25519.PrivateKey    `json:"authority_sign_key"`
	Attributes map[string]*Attribute `json:"attributes"`
	Users      map[string]*User      `json:"users"`
	Policies   map[string]*PolicyRec `json:"policies"`
	Audit      []AuditEntry          `json:"audit"`
	Seeded     bool                  `json:"seeded"`
}

type Attribute struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	Desc    string `json:"desc"`
}

type User struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Attrs    []string          `json:"attrs"`
	KeyEpoch int               `json:"key_epoch"`
	Key      []byte            `json:"key"`       // khóa ABE hiện hành
	KeyAttrs map[string]string `json:"key_attrs"` // thuộc tính + version nằm trong khóa đó
}

// PolicyRec: chính sách và mọi thế hệ Policy Key / Write Key của nó.
type PolicyRec struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	Logical    string          `json:"logical"`
	CurrentGen int             `json:"current_gen"`
	Gens       map[int]*GenRec `json:"gens"`
}

type GenRec struct {
	Pub      []byte `json:"pub"`
	Priv     []byte `json:"priv"`     // chỉ giữ trong vùng tin cậy, phục vụ chế độ Eager
	Compiled string `json:"compiled"` // chính sách thật đã gắn version, dùng cho bản mã CP-ABE hiện tại
	ABECt    []byte `json:"abe_ct"`   // nil = thế hệ đã bị hủy
}

type AuditEntry struct {
	Time   time.Time `json:"time"`
	Action string    `json:"action"`
	Detail string    `json:"detail"`
}

func loadState(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s State
	return &s, json.Unmarshal(b, &s)
}

// save ghi nguyên tử (file tạm + rename) để không hỏng state nếu container bị dừng giữa chừng.
func (s *State) save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), ".state.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *State) audit(action, detail string) {
	s.Audit = append(s.Audit, AuditEntry{Time: time.Now(), Action: action, Detail: detail})
}
