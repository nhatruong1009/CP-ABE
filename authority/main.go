// authority: Key Authority trong VÙNG TIN CẬY.
// Giữ Master Secret Key, quản lý thuộc tính có version, chính sách, các thế hệ Policy Key / Write Key,
// và thực hiện cấp / thu hồi thuộc tính.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"sort"
	"sync"
	"time"

	"cpabe-demo/shared"
)

type Authority struct {
	mu    sync.Mutex
	st    *State
	path  string
	cloud *shared.CloudClient
}

func main() {
	a := &Authority{
		path:  env("STATE_FILE", "/data/state.json"),
		cloud: &shared.CloudClient{Base: env("CLOUD_URL", "http://cloud-api:8082"), Token: os.Getenv("CLOUD_ADMIN_TOKEN")},
	}
	if err := a.init(); err != nil {
		log.Fatalf("khởi tạo: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /system", a.handleSystem)
	mux.HandleFunc("GET /attributes", a.handleAttributes)
	mux.HandleFunc("GET /users", a.handleUsers)
	mux.HandleFunc("GET /users/{id}/key", a.handleUserKey)
	mux.HandleFunc("POST /users/{id}/attributes", a.handleGrant)
	mux.HandleFunc("DELETE /users/{id}/attributes/{attr}", a.handleRevoke)
	mux.HandleFunc("GET /policies", a.handlePolicies)
	mux.HandleFunc("POST /policies", a.handleRegisterPolicy)
	mux.HandleFunc("GET /audit", a.handleAudit)

	log.Println("authority lắng nghe :8081")
	log.Fatal(http.ListenAndServe(":8081", mux))
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ---------------- Khởi tạo & seed ----------------

func (a *Authority) init() error {
	st, err := loadState(a.path)
	if errors.Is(err, os.ErrNotExist) {
		log.Println("Setup(): sinh Public Key / Master Key lần đầu")
		st = &State{Attributes: map[string]*Attribute{}, Users: map[string]*User{}, Policies: map[string]*PolicyRec{}}
		if st.PK, st.MSK, err = shared.ABESetup(); err != nil {
			return err
		}
		if _, st.SignKey, err = ed25519.GenerateKey(rand.Reader); err != nil {
			return err
		}
		a.st = st
		a.seedIdentities()
		st.audit("setup", "khởi tạo hệ thống")
		if err := a.st.save(a.path); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	a.st = st

	for i := 0; a.cloud.Health() != nil; i++ {
		if i > 60 {
			return errors.New("không kết nối được cloud-api")
		}
		log.Println("chờ cloud-api...")
		time.Sleep(2 * time.Second)
	}
	// Đăng lại mọi chính sách (idempotent) để cloud luôn đồng bộ với authority.
	for _, p := range a.st.Policies {
		if err := a.publish(p); err != nil {
			return err
		}
	}
	if !a.st.Seeded {
		if err := a.seedDocuments(); err != nil {
			return err
		}
		a.st.Seeded = true
	}
	return a.st.save(a.path)
}

func (a *Authority) seedIdentities() {
	attrs := []Attribute{
		{"dept_hr", 1, "Phòng Nhân sự"}, {"dept_finance", 1, "Phòng Tài chính"},
		{"dept_sales", 1, "Phòng Kinh doanh"}, {"dept_eng", 1, "Phòng Kỹ thuật"},
		{"role_staff", 1, "Nhân viên"}, {"role_manager", 1, "Trưởng phòng"}, {"role_director", 1, "Giám đốc"},
		{"proj_alpha", 1, "Thành viên dự án Alpha"}, {"proj_beta", 1, "Thành viên dự án Beta"},
	}
	for i := range attrs {
		a.st.Attributes[attrs[i].Name] = &attrs[i]
	}
	users := []User{
		{ID: "an", Name: "An", Attrs: []string{"dept_finance", "role_manager"}},
		{ID: "binh", Name: "Bình", Attrs: []string{"dept_finance", "role_staff"}},
		{ID: "chi", Name: "Chi", Attrs: []string{"dept_hr", "role_manager"}},
		{ID: "dung", Name: "Dũng", Attrs: []string{"dept_eng", "role_staff", "proj_alpha"}},
		{ID: "ha", Name: "Hà (Giám đốc)", Attrs: []string{"role_director"}},
	}
	for i := range users {
		u := &users[i]
		a.st.Users[u.ID] = u
		if err := a.rekey(u); err != nil {
			log.Fatalf("KeyGen %s: %v", u.ID, err)
		}
	}
}

func (a *Authority) seedDocuments() error {
	docs := []struct{ title, body, read, write string }{
		{"Bảng lương tháng 10", "Tổng quỹ lương: 4,2 tỷ.\nAn: 45tr · Bình: 22tr · Chi: 40tr · Dũng: 30tr.",
			"(dept_hr and role_manager) or role_director", "dept_hr and role_manager"},
		{"Báo cáo tài chính Q3", "Doanh thu: 120 tỷ (+8%).\nLợi nhuận gộp: 31 tỷ.\nDòng tiền tự do: 9 tỷ.",
			"dept_finance or role_director", "dept_finance and role_manager"},
		{"Đặc tả dự án Alpha", "Mục tiêu: hệ thống thanh toán nội bộ.\nMốc 1: 15/11 · Mốc 2: 20/12.",
			"proj_alpha or role_director", "proj_alpha"},
		{"Đề xuất ngân sách phòng Kỹ thuật", "Đề xuất mua 10 máy chủ, tổng 1,5 tỷ.",
			"dept_finance and role_manager", "role_staff or role_manager"},
	}
	for _, d := range docs {
		rid, err := a.registerPolicy(shared.KindRead, d.read)
		if err != nil {
			return err
		}
		wid, err := a.registerPolicy(shared.KindWrite, d.write)
		if err != nil {
			return err
		}
		rp, wp := a.st.Policies[rid], a.st.Policies[wid]
		readKey := &shared.PolicyKey{Gen: rp.CurrentGen, PublicKey: rp.Gens[rp.CurrentGen].Pub}
		v, err := shared.BuildVersion(shared.NewDocID(), 1,
			shared.Payload{Title: d.title, Body: d.body, Author: "Hệ thống (dữ liệu mẫu)"},
			rid, readKey, wid, wp.CurrentGen, wp.Gens[wp.CurrentGen].Priv)
		if err != nil {
			return err
		}
		if err := a.cloud.CreateDocument(v); err != nil {
			return fmt.Errorf("seed %q: %w", d.title, err)
		}
	}
	a.st.audit("seed", fmt.Sprintf("tạo %d tài liệu mẫu", len(docs)))
	return nil
}

// ---------------- Khóa người dùng ----------------

// rekey chạy KeyGen với toàn bộ thuộc tính hiện có của user, ở version hiện hành.
func (a *Authority) rekey(u *User) error {
	m := map[string]string{}
	for _, name := range u.Attrs {
		m[name] = fmt.Sprintf("v%d", a.st.Attributes[name].Version)
	}
	u.Key = nil
	if len(m) > 0 {
		key, err := shared.ABEKeyGen(a.st.MSK, m)
		if err != nil {
			return err
		}
		u.Key = key
	}
	u.KeyAttrs = m
	u.KeyEpoch++
	return nil
}

// grant – UC4: chỉ cần KeyGen lại cho 1 user; không mã hóa lại gì cả.
func (a *Authority) grant(uid, attr string) (string, error) {
	u, ok := a.st.Users[uid]
	if !ok {
		return "", fmt.Errorf("không có user %s", uid)
	}
	if _, ok := a.st.Attributes[attr]; !ok {
		return "", fmt.Errorf("không có thuộc tính %s", attr)
	}
	if slices.Contains(u.Attrs, attr) {
		return "", fmt.Errorf("%s đã có %s", u.Name, attr)
	}
	u.Attrs = append(u.Attrs, attr)
	if err := a.rekey(u); err != nil {
		return "", err
	}
	msg := fmt.Sprintf("Cấp %s cho %s → KeyGen 1 lần (epoch %d). Không cần mã hóa lại dữ liệu.", attr, u.Name, u.KeyEpoch)
	a.st.audit("grant", msg)
	return msg, nil
}

// revoke – UC5: tăng version thuộc tính, cấp lại khóa cho người còn giữ thuộc tính,
// sinh thế hệ Policy Key mới cho mọi chính sách liên quan, mã hóa lại các thế hệ cũ.
func (a *Authority) revoke(uid, attr, mode string) (string, error) {
	u, ok := a.st.Users[uid]
	if !ok {
		return "", fmt.Errorf("không có user %s", uid)
	}
	idx := slices.Index(u.Attrs, attr)
	if idx < 0 {
		return "", fmt.Errorf("%s không có %s", u.Name, attr)
	}
	start := time.Now()
	u.Attrs = slices.Delete(u.Attrs, idx, idx+1)
	at := a.st.Attributes[attr]
	at.Version++

	rekeyed := []string{}
	for _, other := range a.st.Users {
		if other == u || slices.Contains(other.Attrs, attr) {
			if err := a.rekey(other); err != nil {
				return "", err
			}
			rekeyed = append(rekeyed, other.Name)
		}
	}
	sort.Strings(rekeyed)

	var affected []*PolicyRec
	for _, p := range a.st.Policies {
		if !a.usesAttr(p, attr) {
			continue
		}
		if err := a.newGen(p); err != nil {
			return "", err
		}
		if err := a.reencryptOldGens(p); err != nil {
			return "", err
		}
		if err := a.publish(p); err != nil {
			return "", err
		}
		affected = append(affected, p)
	}

	msg := fmt.Sprintf("Thu hồi %s của %s: %s v%d→v%d · KeyGen lại %d user (%v) · %d chính sách sang thế hệ mới",
		attr, u.Name, attr, at.Version-1, at.Version, len(rekeyed), rekeyed, len(affected))
	if mode == "eager" {
		n, err := a.eagerRewrap(affected)
		if err != nil {
			return "", err
		}
		msg += fmt.Sprintf(" · EAGER: bọc lại DEK của %d phiên bản tài liệu, hủy thế hệ cũ", n)
	} else {
		msg += " · LAZY: tài liệu cũ được bọc lại khi có người sửa"
	}
	msg += fmt.Sprintf(" · %v", time.Since(start).Round(time.Millisecond))
	a.st.audit("revoke", msg)
	return msg, nil
}

// eagerRewrap bọc lại DEK của mọi phiên bản còn dùng thế hệ cũ sang thế hệ hiện hành,
// rồi hủy hẳn các thế hệ cũ. Nội dung không cần mã hóa lại; chữ ký vẫn hợp lệ.
func (a *Authority) eagerRewrap(pols []*PolicyRec) (int, error) {
	byID := map[string]*PolicyRec{}
	for _, p := range pols {
		if p.Kind == shared.KindRead {
			byID[p.ID] = p
		}
	}
	if len(byID) == 0 {
		return 0, nil
	}
	versions, err := a.cloud.AllVersions()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, v := range versions {
		p := byID[v.ReadPolicyID]
		if p == nil || v.ReadGen == p.CurrentGen {
			continue
		}
		old, cur := p.Gens[v.ReadGen], p.Gens[p.CurrentGen]
		if old == nil || old.Priv == nil {
			return n, fmt.Errorf("thiếu khóa thế hệ %d của %s", v.ReadGen, p.ID)
		}
		dek, err := shared.UnwrapDEK(old.Pub, old.Priv, v.WrappedDEK)
		if err != nil {
			return n, fmt.Errorf("mở DEK %s v%d: %w", v.DocID, v.Version, err)
		}
		wrapped, err := shared.WrapDEK(cur.Pub, dek)
		if err != nil {
			return n, err
		}
		if err := a.cloud.Rewrap(v.DocID, v.Version, p.CurrentGen, wrapped); err != nil {
			return n, err
		}
		n++
	}
	for _, p := range byID {
		for gen, g := range p.Gens {
			if gen != p.CurrentGen {
				g.ABECt, g.Priv, g.Compiled = nil, nil, "(đã hủy - eager)"
			}
		}
		if err := a.publish(p); err != nil {
			return n, err
		}
	}
	return n, nil
}

// ---------------- HTTP ----------------

func (a *Authority) persist() {
	if err := a.st.save(a.path); err != nil {
		log.Printf("LỖI lưu state: %v", err)
	}
}

func (a *Authority) handleSystem(w http.ResponseWriter, r *http.Request) {
	shared.WriteJSON(w, 200, map[string]any{"authority_pub": a.st.SignKey.Public().(ed25519.PublicKey)})
}

func (a *Authority) handleAttributes(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := []Attribute{}
	for _, at := range a.st.Attributes {
		out = append(out, *at)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	shared.WriteJSON(w, 200, out)
}

func (a *Authority) handleUsers(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := []shared.UserView{}
	for _, u := range a.st.Users {
		out = append(out, shared.UserView{ID: u.ID, Name: u.Name, Attrs: slices.Sorted(slices.Values(u.Attrs)), KeyEpoch: u.KeyEpoch, KeyAttrs: u.KeyAttrs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	shared.WriteJSON(w, 200, out)
}

func (a *Authority) handleUserKey(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	u, ok := a.st.Users[r.PathValue("id")]
	if !ok {
		shared.WriteErr(w, 404, "không có user")
		return
	}
	shared.WriteJSON(w, 200, shared.UserKey{UserID: u.ID, Epoch: u.KeyEpoch, Attrs: u.KeyAttrs, Key: u.Key})
}

func (a *Authority) handleGrant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Attr string `json:"attr"`
	}
	if err := shared.ReadJSON(r, &req); err != nil {
		shared.WriteErr(w, 400, "dữ liệu không hợp lệ")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	msg, err := a.grant(r.PathValue("id"), req.Attr)
	a.persist()
	if err != nil {
		shared.WriteErr(w, 400, "%v", err)
		return
	}
	shared.WriteJSON(w, 200, map[string]string{"message": msg})
}

func (a *Authority) handleRevoke(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	msg, err := a.revoke(r.PathValue("id"), r.PathValue("attr"), r.URL.Query().Get("mode"))
	a.persist()
	if err != nil {
		shared.WriteErr(w, 400, "%v", err)
		return
	}
	shared.WriteJSON(w, 200, map[string]string{"message": msg})
}

func (a *Authority) handlePolicies(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := []shared.PolicyView{}
	for _, p := range a.st.Policies {
		out = append(out, shared.PolicyView{ID: p.ID, Kind: p.Kind, Logical: p.Logical, CurrentGen: p.CurrentGen, Compiled: p.Gens[p.CurrentGen].Compiled})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Logical < out[j].Logical
	})
	shared.WriteJSON(w, 200, out)
}

func (a *Authority) handleRegisterPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Kind    string `json:"kind"`
		Logical string `json:"logical"`
	}
	if err := shared.ReadJSON(r, &req); err != nil {
		shared.WriteErr(w, 400, "dữ liệu không hợp lệ")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	id, err := a.registerPolicy(req.Kind, req.Logical)
	a.persist()
	if err != nil {
		shared.WriteErr(w, 400, "%v", err)
		return
	}
	shared.WriteJSON(w, 200, map[string]string{"policy_id": id})
}

func (a *Authority) handleAudit(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := slices.Clone(a.st.Audit)
	slices.Reverse(out)
	if len(out) > 100 {
		out = out[:100]
	}
	shared.WriteJSON(w, 200, out)
}
