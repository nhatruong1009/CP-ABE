// cloud-api: Storage Gateway trong VÙNG KHÔNG TIN CẬY.
// Không giữ bất kỳ khóa bí mật nào. Chỉ lưu bản mã và kiểm chữ ký ghi bằng public Write Key.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"cpabe-demo/shared"
)

const schema = `
CREATE TABLE IF NOT EXISTS policies (
  policy_id    TEXT PRIMARY KEY,
  kind         TEXT NOT NULL CHECK (kind IN ('read','write')),
  logical_expr TEXT NOT NULL,
  current_gen  INT  NOT NULL,
  header_sig   BYTEA NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_keys (
  policy_id        TEXT REFERENCES policies ON DELETE CASCADE,
  gen              INT,
  compiled_expr    TEXT NOT NULL,
  public_key       BYTEA NOT NULL,
  abe_wrapped_priv BYTEA,
  key_sig          BYTEA NOT NULL,
  PRIMARY KEY (policy_id, gen)
);
CREATE TABLE IF NOT EXISTS documents (
  doc_id         TEXT PRIMARY KEY,
  latest_version INT NOT NULL
);
CREATE TABLE IF NOT EXISTS document_versions (
  doc_id          TEXT REFERENCES documents,
  version         INT,
  read_policy_id  TEXT NOT NULL REFERENCES policies,
  read_gen        INT  NOT NULL,
  wrapped_dek     BYTEA NOT NULL,
  nonce           BYTEA NOT NULL,
  ciphertext      BYTEA NOT NULL,
  write_policy_id TEXT NOT NULL REFERENCES policies,
  write_gen       INT  NOT NULL,
  signature       BYTEA NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (doc_id, version)
);`

type server struct {
	db    *pgxpool.Pool
	token string
}

func main() {
	ctx := context.Background()
	var db *pgxpool.Pool
	var err error
	for i := 0; ; i++ {
		db, err = pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
		if err == nil {
			if err = db.Ping(ctx); err == nil {
				break
			}
		}
		if i > 30 {
			log.Fatalf("không kết nối được DB: %v", err)
		}
		log.Printf("chờ DB... (%v)", err)
		time.Sleep(2 * time.Second)
	}
	if _, err := db.Exec(ctx, schema); err != nil {
		log.Fatalf("tạo schema: %v", err)
	}
	s := &server{db: db, token: os.Getenv("CLOUD_ADMIN_TOKEN")}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /policies", s.listPolicies)
	mux.HandleFunc("GET /policies/{id}", s.getPolicy)
	mux.HandleFunc("PUT /policies/{id}", s.admin(s.putPolicy))
	mux.HandleFunc("GET /documents", s.listDocuments)
	mux.HandleFunc("GET /versions", s.allVersions)
	mux.HandleFunc("GET /documents/{id}/versions", s.docVersions)
	mux.HandleFunc("POST /documents", s.createDocument)
	mux.HandleFunc("POST /documents/{id}/versions", s.addVersion)
	mux.HandleFunc("PUT /documents/{id}/versions/{v}/wrap", s.admin(s.rewrap))
	mux.HandleFunc("POST /_demo/tamper/{id}/{v}", s.demoTamper)

	log.Println("cloud-api lắng nghe :8082")
	log.Fatal(http.ListenAndServe(":8082", logRequests(mux)))
}

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		h.ServeHTTP(w, r)
	})
}

// admin: các thao tác chỉ authority được gọi (đăng chính sách, bọc lại DEK).
func (s *server) admin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.token == "" || r.Header.Get("Authorization") != "Bearer "+s.token {
			shared.WriteErr(w, http.StatusUnauthorized, "chỉ authority được gọi")
			return
		}
		h(w, r)
	}
}

// ---------- Policies ----------

func (s *server) loadPolicy(ctx context.Context, id string) (*shared.Policy, error) {
	p := &shared.Policy{}
	err := s.db.QueryRow(ctx, `SELECT policy_id, kind, logical_expr, current_gen, header_sig FROM policies WHERE policy_id=$1`, id).
		Scan(&p.PolicyID, &p.Kind, &p.Logical, &p.CurrentGen, &p.Sig)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx, `SELECT policy_id, gen, compiled_expr, public_key, abe_wrapped_priv, key_sig
		FROM policy_keys WHERE policy_id=$1 ORDER BY gen`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k shared.PolicyKey
		if err := rows.Scan(&k.PolicyID, &k.Gen, &k.Compiled, &k.PublicKey, &k.ABEWrappedPriv, &k.Sig); err != nil {
			return nil, err
		}
		p.Keys = append(p.Keys, k)
	}
	return p, rows.Err()
}

func (s *server) getPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := s.loadPolicy(r.Context(), r.PathValue("id"))
	if errors.Is(err, pgx.ErrNoRows) {
		shared.WriteErr(w, http.StatusNotFound, "không có chính sách")
		return
	} else if err != nil {
		shared.WriteErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, p)
}

func (s *server) listPolicies(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(r.Context(), `SELECT policy_id FROM policies ORDER BY kind, policy_id`)
	if err != nil {
		shared.WriteErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		shared.WriteErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	out := []shared.Policy{}
	for _, id := range ids {
		p, err := s.loadPolicy(r.Context(), id)
		if err != nil {
			shared.WriteErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		out = append(out, *p)
	}
	shared.WriteJSON(w, http.StatusOK, out)
}

func (s *server) putPolicy(w http.ResponseWriter, r *http.Request) {
	var p shared.Policy
	if err := shared.ReadJSON(r, &p); err != nil || p.PolicyID != r.PathValue("id") {
		shared.WriteErr(w, http.StatusBadRequest, "dữ liệu chính sách không hợp lệ")
		return
	}
	ctx := r.Context()
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO policies (policy_id, kind, logical_expr, current_gen, header_sig)
			VALUES ($1,$2,$3,$4,$5) ON CONFLICT (policy_id) DO UPDATE
			SET logical_expr=$3, current_gen=$4, header_sig=$5`,
			p.PolicyID, p.Kind, p.Logical, p.CurrentGen, p.Sig); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM policy_keys WHERE policy_id=$1`, p.PolicyID); err != nil {
			return err
		}
		for _, k := range p.Keys {
			if _, err := tx.Exec(ctx, `INSERT INTO policy_keys (policy_id, gen, compiled_expr, public_key, abe_wrapped_priv, key_sig)
				VALUES ($1,$2,$3,$4,$5,$6)`, p.PolicyID, k.Gen, k.Compiled, k.PublicKey, k.ABEWrappedPriv, k.Sig); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		shared.WriteErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- Documents ----------

const versionCols = `doc_id, version, read_policy_id, read_gen, wrapped_dek, nonce, ciphertext,
	write_policy_id, write_gen, signature, created_at`

func scanVersions(rows pgx.Rows) ([]shared.DocVersion, error) {
	defer rows.Close()
	out := []shared.DocVersion{}
	for rows.Next() {
		var v shared.DocVersion
		if err := rows.Scan(&v.DocID, &v.Version, &v.ReadPolicyID, &v.ReadGen, &v.WrappedDEK, &v.Nonce,
			&v.Ciphertext, &v.WritePolicyID, &v.WriteGen, &v.Signature, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *server) queryVersions(w http.ResponseWriter, r *http.Request, sql string, args ...any) {
	rows, err := s.db.Query(r.Context(), sql, args...)
	if err != nil {
		shared.WriteErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	vs, err := scanVersions(rows)
	if err != nil {
		shared.WriteErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	shared.WriteJSON(w, http.StatusOK, vs)
}

func (s *server) listDocuments(w http.ResponseWriter, r *http.Request) {
	s.queryVersions(w, r, `SELECT `+versionCols+` FROM document_versions v
		WHERE version = (SELECT latest_version FROM documents d WHERE d.doc_id = v.doc_id)
		ORDER BY created_at`)
}

func (s *server) allVersions(w http.ResponseWriter, r *http.Request) {
	s.queryVersions(w, r, `SELECT `+versionCols+` FROM document_versions ORDER BY doc_id, version`)
}

func (s *server) docVersions(w http.ResponseWriter, r *http.Request) {
	s.queryVersions(w, r, `SELECT `+versionCols+` FROM document_versions WHERE doc_id=$1 ORDER BY version DESC`,
		r.PathValue("id"))
}

// checkWrite: cloud kiểm chữ ký bằng public Write Key THẾ HỆ HIỆN HÀNH.
// Không cần khóa bí mật nào, và người bị thu hồi quyền ghi bị chặn ngay.
func (s *server) checkWrite(ctx context.Context, v *shared.DocVersion) (int, string) {
	rp, err := s.loadPolicy(ctx, v.ReadPolicyID)
	if err != nil || rp.Kind != shared.KindRead || rp.Key(v.ReadGen) == nil {
		return http.StatusBadRequest, "read policy / thế hệ không tồn tại"
	}
	wp, err := s.loadPolicy(ctx, v.WritePolicyID)
	if err != nil || wp.Kind != shared.KindWrite {
		return http.StatusBadRequest, "write policy không tồn tại"
	}
	if v.WriteGen != wp.CurrentGen {
		return http.StatusForbidden, "Write Key thế hệ " + strconv.Itoa(v.WriteGen) +
			" đã bị thu hồi (hiện hành: " + strconv.Itoa(wp.CurrentGen) + ")"
	}
	if !shared.Verify(wp.Key(wp.CurrentGen).PublicKey, v.SignedBytes(), v.Signature) {
		return http.StatusForbidden, "chữ ký ghi không hợp lệ: người ghi không thỏa write policy"
	}
	return 0, ""
}

func (s *server) createDocument(w http.ResponseWriter, r *http.Request) {
	var v shared.DocVersion
	if err := shared.ReadJSON(r, &v); err != nil || v.DocID == "" || v.Version != 1 {
		shared.WriteErr(w, http.StatusBadRequest, "tài liệu mới phải có doc_id và version = 1")
		return
	}
	s.insertVersion(w, r, &v, true)
}

func (s *server) addVersion(w http.ResponseWriter, r *http.Request) {
	var v shared.DocVersion
	if err := shared.ReadJSON(r, &v); err != nil || v.DocID != r.PathValue("id") {
		shared.WriteErr(w, http.StatusBadRequest, "dữ liệu không hợp lệ")
		return
	}
	// Không cho đổi chính sách khi sửa: nếu cho, người thỏa write policy MỚI có thể chiếm tài liệu.
	// (Đổi chính sách đúng cách cần chữ ký bằng Write Key cũ, xem "hướng phát triển".)
	var rpid, wpid string
	err := s.db.QueryRow(r.Context(), `SELECT read_policy_id, write_policy_id FROM document_versions
		WHERE doc_id=$1 ORDER BY version DESC LIMIT 1`, v.DocID).Scan(&rpid, &wpid)
	if errors.Is(err, pgx.ErrNoRows) {
		shared.WriteErr(w, http.StatusNotFound, "không có tài liệu")
		return
	} else if err != nil {
		shared.WriteErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if v.ReadPolicyID != rpid || v.WritePolicyID != wpid {
		shared.WriteErr(w, http.StatusBadRequest, "không được đổi chính sách khi sửa tài liệu")
		return
	}
	s.insertVersion(w, r, &v, false)
}

func (s *server) insertVersion(w http.ResponseWriter, r *http.Request, v *shared.DocVersion, create bool) {
	ctx := r.Context()
	if code, msg := s.checkWrite(ctx, v); code != 0 {
		log.Printf("TỪ CHỐI ghi %s v%d: %s", v.DocID, v.Version, msg)
		shared.WriteErr(w, code, "%s", msg)
		return
	}
	var conflict string
	err := pgx.BeginFunc(ctx, s.db, func(tx pgx.Tx) error {
		if create {
			tag, err := tx.Exec(ctx, `INSERT INTO documents (doc_id, latest_version) VALUES ($1, 1) ON CONFLICT DO NOTHING`, v.DocID)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				conflict = "doc_id đã tồn tại"
				return nil
			}
		} else {
			// Optimistic locking: chỉ nhận nếu version = latest + 1.
			tag, err := tx.Exec(ctx, `UPDATE documents SET latest_version=$2 WHERE doc_id=$1 AND latest_version=$2-1`,
				v.DocID, v.Version)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				conflict = "đã có người sửa trước bạn, hãy tải lại tài liệu"
				return nil
			}
		}
		_, err := tx.Exec(ctx, `INSERT INTO document_versions (doc_id, version, read_policy_id, read_gen, wrapped_dek,
			nonce, ciphertext, write_policy_id, write_gen, signature) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			v.DocID, v.Version, v.ReadPolicyID, v.ReadGen, v.WrappedDEK, v.Nonce, v.Ciphertext,
			v.WritePolicyID, v.WriteGen, v.Signature)
		return err
	})
	switch {
	case err != nil:
		shared.WriteErr(w, http.StatusInternalServerError, "%v", err)
	case conflict != "":
		shared.WriteErr(w, http.StatusConflict, "%s", conflict)
	default:
		w.WriteHeader(http.StatusCreated)
	}
}

// rewrap: chế độ Eager, authority bọc lại DEK bằng Policy Key thế hệ mới.
func (s *server) rewrap(w http.ResponseWriter, r *http.Request) {
	var req shared.RewrapRequest
	if err := shared.ReadJSON(r, &req); err != nil {
		shared.WriteErr(w, http.StatusBadRequest, "dữ liệu không hợp lệ")
		return
	}
	ver, _ := strconv.Atoi(r.PathValue("v"))
	_, err := s.db.Exec(r.Context(), `UPDATE document_versions SET read_gen=$3, wrapped_dek=$4 WHERE doc_id=$1 AND version=$2`,
		r.PathValue("id"), ver, req.ReadGen, req.WrappedDEK)
	if err != nil {
		shared.WriteErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// demoTamper mô phỏng một cloud ĐỘC HẠI lật 1 bit trong bản mã (kịch bản E).
func (s *server) demoTamper(w http.ResponseWriter, r *http.Request) {
	ver, _ := strconv.Atoi(r.PathValue("v"))
	_, err := s.db.Exec(r.Context(), `UPDATE document_versions
		SET ciphertext = set_byte(ciphertext, 0, get_byte(ciphertext, 0) # 1) WHERE doc_id=$1 AND version=$2`,
		r.PathValue("id"), ver)
	if err != nil {
		shared.WriteErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	log.Printf("DEMO: cloud đã sửa trái phép bản mã %s v%d", r.PathValue("id"), ver)
	w.WriteHeader(http.StatusNoContent)
}
