package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"

	"cpabe-demo/shared"
)

// Keystore mô phỏng "thiết bị của user": lưu mọi khóa ABE user từng nhận, kể cả khóa cũ,
// để demo kịch bản "giữ lại khóa cũ sau khi bị thu hồi".
type Keystore struct{ dir string }

type StoredKey struct {
	shared.UserKey
	SavedAt time.Time `json:"saved_at"`
}

var epochFile = regexp.MustCompile(`^epoch-(\d+)\.json$`)

func (k *Keystore) path(uid string, epoch int) string {
	return filepath.Join(k.dir, uid, fmt.Sprintf("epoch-%04d.json", epoch))
}

func (k *Keystore) Has(uid string, epoch int) bool {
	_, err := os.Stat(k.path(uid, epoch))
	return err == nil
}

func (k *Keystore) Save(key *shared.UserKey) error {
	p := k.path(key.UserID, key.Epoch)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(StoredKey{UserKey: *key, SavedAt: time.Now()}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}

func (k *Keystore) Load(uid string, epoch int) (*StoredKey, error) {
	b, err := os.ReadFile(k.path(uid, epoch))
	if err != nil {
		return nil, err
	}
	var sk StoredKey
	return &sk, json.Unmarshal(b, &sk)
}

// Epochs: các khóa user đang giữ, mới nhất trước.
func (k *Keystore) Epochs(uid string) []int {
	entries, _ := os.ReadDir(filepath.Join(k.dir, uid))
	var out []int
	for _, e := range entries {
		if m := epochFile.FindStringSubmatch(e.Name()); m != nil {
			n, _ := strconv.Atoi(m[1])
			out = append(out, n)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(out)))
	return out
}
