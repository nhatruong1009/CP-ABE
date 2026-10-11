package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

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
	priv, _, err := s.openPrivCached(p, gen)
	return priv, err
}

// openPrivCached giống openPriv, trả thêm cờ "lấy từ cache" để hiển thị trong quy trình giải mã.
func (s *Session) openPrivCached(p *shared.Policy, gen int) ([]byte, bool, error) {
	k := p.Key(gen)
	if k == nil {
		return nil, false, fmt.Errorf("không có thế hệ %d", gen)
	}
	if len(k.ABEWrappedPriv) == 0 {
		return nil, false, ErrRetired
	}
	if s.ID.Key == nil || !shared.ABECouldDecrypt(s.ID.Attrs, k.ABEWrappedPriv) {
		return nil, false, ErrNoAccess
	}
	sum := sha256.Sum256(k.ABEWrappedPriv)
	ck := fmt.Sprintf("%s|%d|%x", s.ID.UserID, s.ID.Epoch, sum)
	s.v.mu.Lock()
	priv, ok := s.v.privCache[ck]
	s.v.mu.Unlock()
	if ok {
		return priv, true, nil
	}
	priv, err := shared.ABEDecrypt(s.ID.Key, k.ABEWrappedPriv)
	if err != nil {
		return nil, false, ErrNoAccess
	}
	s.v.mu.Lock()
	s.v.privCache[ck] = priv
	s.v.mu.Unlock()
	return priv, false, nil
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
	Trace        []*Step // quy trình giải mã từng bước, để hiển thị "bản thô"
}

func (r ReadResult) OK() bool { return r.Status == "ok" }

// Step: một bước trong quy trình giải mã.
type Step struct {
	N      int
	Title  string
	Where  string // dữ liệu lấy từ đâu / chạy ở đâu
	Desc   string
	Status string // ok | fail | skip
	Fields []Field
	Dur    string
}

type Field struct {
	K, V string
	Mono bool // hiển thị dạng mã (hex, chuỗi kỹ thuật)
	Bad  bool
}

func hexPrefix(b []byte, n int) string {
	if len(b) > n {
		return hex.EncodeToString(b[:n]) + "…"
	}
	return hex.EncodeToString(b)
}

func sizeOf(b []byte) string { return fmt.Sprintf("%d byte", len(b)) }

type tracer struct {
	steps []*Step
	t0    time.Time
}

func (t *tracer) begin(title, where, desc string) *Step {
	st := &Step{N: len(t.steps) + 1, Title: title, Where: where, Desc: desc, Status: "ok"}
	t.steps = append(t.steps, st)
	t.t0 = time.Now()
	return st
}

func (t *tracer) end(st *Step) {
	st.Dur = time.Since(t.t0).Round(10 * time.Microsecond).String()
}

func (st *Step) add(k, v string, mono bool) { st.Fields = append(st.Fields, Field{K: k, V: v, Mono: mono}) }
func (st *Step) bad(k, v string)            { st.Fields = append(st.Fields, Field{K: k, V: v, Bad: true}) }

var attrPairRe = regexp.MustCompile(`\(([A-Za-z0-9_]+): ([A-Za-z0-9_]+)\)`)

// matchAttrs so từng thuộc tính trong chính sách thật với thuộc tính trong khóa của user.
func (st *Step) matchAttrs(compiled string, attrs map[string]string) {
	for _, m := range attrPairRe.FindAllStringSubmatch(compiled, -1) {
		name, want := m[1], m[2]
		have, ok := attrs[name]
		switch {
		case ok && have == want:
			st.add(name+": "+want, "✔ khóa có "+name+": "+have, false)
		case ok:
			st.bad(name+": "+want, "✖ khóa có "+name+": "+have+" (version CŨ, thuộc tính đã bị thu hồi/xoay vòng)")
		default:
			// Không tô đỏ: với "or", thiếu một nhánh vẫn có thể thỏa. Kết luận ở dòng cuối.
			st.add(name+": "+want, "– khóa không có thuộc tính này", false)
		}
	}
}

func (s *Session) Read(v shared.DocVersion) (res ReadResult) {
	res = ReadResult{V: v}
	t := &tracer{}
	defer func() { res.Trace = t.steps }() // gắn quy trình vào kết quả ở mọi nhánh return
	skip := func(titles ...string) {
		for _, title := range titles {
			st := t.begin(title, "", "Không thực hiện vì bước trước thất bại.")
			st.Status = "skip"
		}
	}

	// 1. Bản ghi thô trên cloud.
	st := t.begin("Tải bản ghi tài liệu từ cloud", "cloud-api · bảng document_versions",
		"Cloud chỉ có các trường dưới đây: toàn bộ là bản mã hoặc định danh, không có tiêu đề hay nội dung.")
	st.add("doc_id · version", fmt.Sprintf("%s · v%d", v.DocID, v.Version), true)
	st.add("read_policy_id · read_gen", fmt.Sprintf("%s · thế hệ %d", v.ReadPolicyID, v.ReadGen), true)
	st.add("write_policy_id · write_gen", fmt.Sprintf("%s · thế hệ %d", v.WritePolicyID, v.WriteGen), true)
	st.add("wrapped_dek ("+sizeOf(v.WrappedDEK)+")", hexPrefix(v.WrappedDEK, 24), true)
	st.add("nonce ("+sizeOf(v.Nonce)+")", hexPrefix(v.Nonce, 12), true)
	st.add("ciphertext ("+sizeOf(v.Ciphertext)+")", hexPrefix(v.Ciphertext, 32), true)
	st.add("signature ("+sizeOf(v.Signature)+")", hexPrefix(v.Signature, 24), true)
	st.add("created_at", v.CreatedAt.Local().Format("02/01/2006 15:04:05"), false)
	t.end(st)

	// 2. Header chính sách đọc + kiểm chữ ký authority.
	st = t.begin("Tải header chính sách đọc & kiểm chữ ký authority", "cloud-api · bảng policies + policy_keys",
		"App kiểm chữ ký của authority (khóa công khai lấy trực tiếp từ authority) để chắc chắn cloud không tráo Policy Key.")
	rp, err := s.Policy(v.ReadPolicyID)
	if err != nil {
		st.Status = "fail"
		st.bad("Lỗi", err.Error())
		t.end(st)
		res.Status, res.Msg = "error", err.Error()
		return res
	}
	wp, err := s.Policy(v.WritePolicyID)
	if err != nil {
		st.Status = "fail"
		st.bad("Lỗi write policy", err.Error())
		t.end(st)
		res.Status, res.Msg = "error", err.Error()
		return res
	}
	res.ReadLogical, res.WriteLogical = rp.Logical, wp.Logical
	res.CurReadGen, res.CurWriteGen = rp.CurrentGen, wp.CurrentGen
	res.CanWrite = s.CanWrite(v.WritePolicyID)
	rk := rp.Key(v.ReadGen)
	st.add("Chính sách logic", rp.Logical, true)
	st.add("Thế hệ hiện hành / của phiên bản này", fmt.Sprintf("%d / %d", rp.CurrentGen, v.ReadGen), false)
	st.add("header_sig (authority)", hexPrefix(rp.Sig, 16)+"  ✔ hợp lệ", true)
	if rk != nil {
		st.add(fmt.Sprintf("Thế hệ %d · chính sách thật", v.ReadGen), rk.Compiled, true)
		st.add(fmt.Sprintf("Thế hệ %d · public key X25519", v.ReadGen), hexPrefix(rk.PublicKey, 32), true)
		if len(rk.ABEWrappedPriv) > 0 {
			st.add(fmt.Sprintf("Thế hệ %d · abe_wrapped_priv (%s)", v.ReadGen, sizeOf(rk.ABEWrappedPriv)),
				hexPrefix(rk.ABEWrappedPriv, 24), true)
		} else {
			st.bad(fmt.Sprintf("Thế hệ %d · abe_wrapped_priv", v.ReadGen), "đã hủy (chế độ Eager)")
		}
		st.add("key_sig (authority)", hexPrefix(rk.Sig, 16)+"  ✔ hợp lệ", true)
	}
	t.end(st)
	if rk == nil {
		st.Status = "fail"
		res.Status, res.Msg = "error", "không có thế hệ khóa"
		return res
	}

	// 3. Đối chiếu thuộc tính.
	st = t.begin("Đối chiếu thuộc tính trong khóa với chính sách", "app · keystore của "+s.ID.Name,
		fmt.Sprintf("Khóa ABE epoch %d của %s. CP-ABE chỉ giải mã được nếu tổ hợp thuộc tính (đúng cả version) thỏa chính sách.", s.ID.Epoch, s.ID.Name))
	if rk.Compiled != "" {
		st.matchAttrs(rk.Compiled, s.ID.Attrs)
	}
	could := len(rk.ABEWrappedPriv) > 0 && s.ID.Key != nil && shared.ABECouldDecrypt(s.ID.Attrs, rk.ABEWrappedPriv)
	if could {
		st.add("Kết luận", "✔ thỏa chính sách", false)
	} else {
		st.Status = "fail"
		st.bad("Kết luận", "✖ không thỏa chính sách: "+rp.Logical)
	}
	t.end(st)

	// 4. Tầng 1: CP-ABE.
	st = t.begin("Tầng 1 · Giải mã CP-ABE lấy private key của Policy", "app · CIRCL tkn20 Decrypt",
		"Đầu vào: abe_wrapped_priv (bản mã CP-ABE trên cloud) + khóa ABE của user. Đầu ra: private key X25519 của Policy Key.")
	priv, cached, err := s.openPrivCached(rp, v.ReadGen)
	switch {
	case errors.Is(err, ErrNoAccess):
		st.Status = "fail"
		st.bad("Kết quả", "✖ Decrypt thất bại: thuộc tính không thỏa")
		t.end(st)
		skip("Tầng 2 · Mở DEK", "Tầng 3 · Giải mã nội dung AES-256-GCM")
		s.traceSignature(t, &res, wp, v)
		res.Status, res.Msg = "noaccess", "Không đủ thuộc tính để đọc"
		return res
	case errors.Is(err, ErrRetired):
		st.Status = "fail"
		st.bad("Kết quả", "✖ thế hệ khóa đã bị hủy")
		t.end(st)
		skip("Tầng 2 · Mở DEK", "Tầng 3 · Giải mã nội dung AES-256-GCM")
		s.traceSignature(t, &res, wp, v)
		res.Status, res.Msg = "retired", "Thế hệ khóa đã bị hủy"
		return res
	case err != nil:
		st.Status = "fail"
		st.bad("Lỗi", err.Error())
		t.end(st)
		res.Status, res.Msg = "error", err.Error()
		return res
	}
	if cached {
		st.add("Nguồn", "cache trong phiên (đã giải mã CP-ABE chính sách này trước đó, mỗi chính sách chỉ tốn 1 lần)", false)
	} else {
		st.add("Nguồn", "vừa chạy CP-ABE Decrypt", false)
	}
	st.add("Policy private key (32 byte)", hexPrefix(priv, 6)+" (che bớt)", true)
	t.end(st)

	// 5. Tầng 2: mở DEK.
	st = t.begin("Tầng 2 · Mở DEK bằng private key của Policy", "app · X25519 sealed box (nacl/box)",
		"wrapped_dek = 32 byte khóa tạm (ephemeral) + 32 byte DEK mã hóa + 16 byte MAC. Chỉ private key của Policy mở được.")
	st.add("Đầu vào wrapped_dek", hexPrefix(v.WrappedDEK, 24), true)
	dek, err := shared.UnwrapDEK(rk.PublicKey, priv, v.WrappedDEK)
	if err != nil {
		st.Status = "fail"
		st.bad("Kết quả", "✖ "+err.Error())
		t.end(st)
		skip("Tầng 3 · Giải mã nội dung AES-256-GCM")
		s.traceSignature(t, &res, wp, v)
		res.Status, res.Msg = "tampered", "Bản mã trên cloud đã bị sửa đổi"
		return res
	}
	st.add("DEK AES-256 (32 byte)", hexPrefix(dek, 6)+" (che bớt)", true)
	st.add("Ghi chú", "DEK sinh mới cho mỗi phiên bản: sửa tài liệu = DEK mới = lazy re-encryption", false)
	t.end(st)

	// 6. Tầng 3: AES-GCM.
	st = t.begin("Tầng 3 · Giải mã nội dung AES-256-GCM", "app · crypto/aes + cipher.GCM",
		"Đầu vào: DEK + nonce + ciphertext + AAD. AES-GCM vừa giải mã vừa kiểm tính toàn vẹn: sửa 1 bit là thất bại.")
	st.add("AAD (gắn bản mã với tài liệu)", string(v.AAD()), true)
	payload, plain, err := shared.OpenPayloadRaw(dek, v.Nonce, v.Ciphertext, v.AAD())
	if err != nil {
		st.Status = "fail"
		st.bad("Kết quả", "✖ "+err.Error())
		t.end(st)
		s.traceSignature(t, &res, wp, v)
		res.Status, res.Msg = "tampered", "Bản mã trên cloud đã bị sửa đổi (AES-GCM không hợp lệ)"
		if !errors.Is(err, shared.ErrIntegrity) {
			res.Status, res.Msg = "error", "Lỗi giải mã: "+err.Error()
		}
		return res
	}
	raw := string(plain)
	if len(raw) > 400 {
		raw = raw[:400] + "…"
	}
	st.add(fmt.Sprintf("Plaintext thô (%s, JSON)", sizeOf(plain)), raw, true)
	t.end(st)
	res.Payload = payload

	s.traceSignature(t, &res, wp, v)
	res.Status = "ok"
	if !res.SigOK {
		res.Msg = "Chữ ký ghi không hợp lệ"
	}
	return res
}

// traceSignature: kiểm chữ ký ghi. Không cần khóa bí mật nào, ai cũng kiểm được (kể cả cloud).
func (s *Session) traceSignature(t *tracer, res *ReadResult, wp *shared.Policy, v shared.DocVersion) {
	st := t.begin("Kiểm chữ ký ghi (Ed25519)", "app · public Write Key từ cloud",
		"Chữ ký được tạo bằng private Write Key, thứ chỉ người thỏa write policy mới mở được qua CP-ABE. Kiểm bằng public key, không cần bí mật.")
	st.add("Write policy", wp.Logical, true)
	st.add("Thế hệ ký / hiện hành", fmt.Sprintf("%d / %d", v.WriteGen, wp.CurrentGen), false)
	wk := wp.Key(v.WriteGen)
	if wk == nil {
		st.Status = "fail"
		st.bad("Kết quả", "✖ không có public key của thế hệ này")
		t.end(st)
		return
	}
	st.add("Public key Ed25519", hexPrefix(wk.PublicKey, 32), true)
	st.add("Thông điệp được ký = SHA-256(doc_id, version, policy, write_gen, nonce, ciphertext)", hex.EncodeToString(v.SignedBytes()), true)
	st.add("signature", hexPrefix(v.Signature, 32), true)
	res.SigOK = shared.Verify(wk.PublicKey, v.SignedBytes(), v.Signature)
	if res.SigOK {
		st.add("Kết quả", "✔ chữ ký hợp lệ: phiên bản do người có quyền ghi tạo, chưa bị sửa", false)
	} else {
		st.Status = "fail"
		st.bad("Kết quả", "✖ chữ ký KHÔNG hợp lệ: dữ liệu đã bị sửa sau khi ký")
	}
	if res.CanWrite {
		st.add("Quyền ghi của "+s.ID.Name, "✔ mở được Write Key thế hệ hiện hành, được tạo phiên bản mới", false)
	} else {
		st.add("Quyền ghi của "+s.ID.Name, "✖ không mở được Write Key, cloud sẽ từ chối nếu ghi", false)
	}
	t.end(st)
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
