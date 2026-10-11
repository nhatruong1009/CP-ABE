// app: Client App + Web UI trong VÙNG TIN CẬY.
// Mã hóa / giải mã / ký ngay tại đây; cloud chỉ nhận bản mã.
// Không có đăng nhập: chọn "Đang đóng vai" để tập trung vào authorization.
package main

import (
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"cpabe-demo/shared"
)

//go:embed templates/*.html
var tplFS embed.FS

type Server struct {
	auth     *shared.AuthClient
	cloud    *shared.CloudClient
	keys     *Keystore
	vault    *Vault
	tpl      map[string]*template.Template
	adminerU string

	mu        sync.Mutex
	lastWrite map[string]*writeTrace // user → quy trình ghi vừa thực hiện, hiển thị 1 lần ở trang tài liệu
}

type writeTrace struct {
	DocID string
	Title string
	Steps []*Step
}

func (s *Server) putWrite(uid string, w *writeTrace) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastWrite[uid] = w
}

func (s *Server) popWrite(uid, docID string) *writeTrace {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.lastWrite[uid]
	if w == nil || w.DocID != docID {
		return nil
	}
	delete(s.lastWrite, uid)
	return w
}

func main() {
	s := &Server{
		auth:     &shared.AuthClient{Base: env("AUTHORITY_URL", "http://authority:8081")},
		cloud:    &shared.CloudClient{Base: env("CLOUD_URL", "http://cloud-api:8082")},
		keys:     &Keystore{dir: env("KEYSTORE_DIR", "/keystore")},
		adminerU:  env("ADMINER_URL", "http://localhost:8090"),
		lastWrite: map[string]*writeTrace{},
	}
	var authPub []byte
	var err error
	for i := 0; ; i++ {
		if authPub, err = s.auth.System(); err == nil {
			break
		}
		if i > 90 {
			log.Fatalf("không kết nối được authority: %v", err)
		}
		log.Println("chờ authority...")
		time.Sleep(2 * time.Second)
	}
	s.vault = &Vault{cloud: s.cloud, authPub: authPub, privCache: map[string][]byte{}}
	s.loadTemplates()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.page(s.handleIndex))
	mux.HandleFunc("GET /doc/{id}", s.page(s.handleDoc))
	mux.HandleFunc("GET /new", s.page(s.handleNewForm))
	mux.HandleFunc("POST /new", s.page(s.handleNew))
	mux.HandleFunc("GET /doc/{id}/edit", s.page(s.handleEditForm))
	mux.HandleFunc("POST /doc/{id}/edit", s.page(s.handleEdit))
	mux.HandleFunc("POST /doc/{id}/forge", s.page(s.handleForge))
	mux.HandleFunc("GET /admin", s.page(s.handleAdmin))
	mux.HandleFunc("POST /admin/grant", s.page(s.handleGrant))
	mux.HandleFunc("POST /admin/revoke", s.page(s.handleRevoke))
	mux.HandleFunc("GET /cloud", s.page(s.handleCloud))
	mux.HandleFunc("POST /cloud/tamper", s.page(s.handleTamper))
	mux.HandleFunc("GET /glossary", s.page(s.handleGlossary))
	mux.HandleFunc("POST /as", s.handleSwitch)

	log.Println("app lắng nghe :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ---------------- Template ----------------

var funcs = template.FuncMap{
	"hexp": func(b []byte, n int) string {
		if len(b) > n {
			return hex.EncodeToString(b[:n]) + "…"
		}
		return hex.EncodeToString(b)
	},
	"time": func(t time.Time) string { return t.Local().Format("02/01 15:04:05") },
	"has": func(list []string, x string) bool {
		for _, v := range list {
			if v == x {
				return true
			}
		}
		return false
	},
	"short": func(s string) string {
		if len(s) > 8 {
			return s[:8]
		}
		return s
	},
}

func (s *Server) loadTemplates() {
	s.tpl = map[string]*template.Template{}
	pages, _ := tplFS.ReadDir("templates")
	for _, p := range pages {
		if p.Name() == "layout.html" {
			continue
		}
		s.tpl[p.Name()] = template.Must(template.New("layout.html").Funcs(funcs).
			ParseFS(tplFS, "templates/layout.html", "templates/"+p.Name()))
	}
}

// Page: dữ liệu chung cho mọi trang.
type Page struct {
	Title   string
	Nav     string
	Users   []shared.UserView
	Me      *Identity
	Epochs  []int
	Flash   string
	Error   string
	Adminer string
	Data    any
}

type ctx struct {
	w    http.ResponseWriter
	r    *http.Request
	page *Page
	sess *Session
}

// page: mỗi request đồng bộ khóa của user đang đóng vai rồi gọi handler.
func (s *Server) page(h func(*ctx) (string, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := &ctx{w: w, r: r, page: &Page{
			Flash: r.URL.Query().Get("msg"), Error: r.URL.Query().Get("err"), Adminer: s.adminerU,
		}}
		id, err := s.identity(r, c.page)
		if err != nil {
			http.Error(w, "Không lấy được khóa từ authority: "+err.Error(), http.StatusBadGateway)
			return
		}
		c.page.Me = id
		c.sess = s.vault.Session(id)
		tpl, err := h(c)
		if err != nil {
			c.page.Error = err.Error()
		}
		if tpl == "" { // handler đã redirect
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := s.tpl[tpl].Execute(w, c.page); err != nil {
			log.Printf("render %s: %v", tpl, err)
		}
	}
}

func (s *Server) identity(r *http.Request, p *Page) (*Identity, error) {
	users, err := s.auth.Users()
	if err != nil {
		return nil, err
	}
	p.Users = users
	uid := "an"
	if c, err := r.Cookie("as"); err == nil {
		uid = c.Value
	}
	var me *shared.UserView
	for i := range users {
		if users[i].ID == uid {
			me = &users[i]
		}
	}
	if me == nil {
		me, uid = &users[0], users[0].ID
	}
	// Đồng bộ khóa mới nhất về keystore nếu authority vừa cấp lại (key_epoch tăng).
	if !s.keys.Has(uid, me.KeyEpoch) {
		k, err := s.auth.UserKey(uid)
		if err != nil {
			return nil, err
		}
		if err := s.keys.Save(k); err != nil {
			return nil, err
		}
	}
	p.Epochs = s.keys.Epochs(uid)
	epoch := me.KeyEpoch
	if c, err := r.Cookie("epoch"); err == nil {
		if n, _ := strconv.Atoi(c.Value); n > 0 && s.keys.Has(uid, n) {
			epoch = n
		}
	}
	sk, err := s.keys.Load(uid, epoch)
	if err != nil {
		return nil, err
	}
	return &Identity{UserID: uid, Name: me.Name, Epoch: epoch, Latest: epoch == me.KeyEpoch,
		Attrs: sk.Attrs, Key: sk.Key}, nil
}

func (s *Server) handleSwitch(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	http.SetCookie(w, &http.Cookie{Name: "as", Value: r.FormValue("user"), Path: "/"})
	epoch := r.FormValue("epoch")
	if r.FormValue("user_changed") == "1" {
		epoch = "0"
	}
	http.SetCookie(w, &http.Cookie{Name: "epoch", Value: epoch, Path: "/"})
	back := r.FormValue("back")
	if back == "" || !strings.HasPrefix(back, "/") {
		back = "/"
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func (c *ctx) redirect(path, msg, errMsg string) (string, error) {
	q := url.Values{}
	if msg != "" {
		q.Set("msg", msg)
	}
	if errMsg != "" {
		q.Set("err", errMsg)
	}
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	http.Redirect(c.w, c.r, path, http.StatusSeeOther)
	return "", nil
}

// friendly đổi lỗi HTTP từ cloud thành câu dễ hiểu cho demo.
func friendly(err error) string {
	var he *shared.HTTPError
	if errors.As(err, &he) {
		switch he.Status {
		case http.StatusForbidden:
			return "☁ Cloud TỪ CHỐI (403): " + he.Msg
		case http.StatusConflict:
			return "☁ Xung đột phiên bản (409): " + he.Msg
		}
		return fmt.Sprintf("☁ Cloud trả lỗi %d: %s", he.Status, he.Msg)
	}
	return err.Error()
}
