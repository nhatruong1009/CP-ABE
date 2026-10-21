// bench (C1): đo chi phí thu hồi / đọc, và kiểm kịch bản "user đã lưu DEK".
//
//	bench micro               đo thao tác mật mã + mô phỏng thu hồi theo số tài liệu D (không cần Docker stack)
//	bench e2e -docs D -mode M thêm D tài liệu vào stack đang chạy rồi thu hồi dept_finance của Bình, đo thời gian
//	bench dek -mode M         Bình đọc Báo cáo Q3 và lưu DEK + Policy Key, bị thu hồi, rồi thử đọc lại
//
// Kết quả in dạng bảng Markdown.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"time"

	"cpabe-demo/shared"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("dùng: bench micro | e2e | dek")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	docs := fs.Int("docs", 100, "số tài liệu thêm vào (e2e)")
	mode := fs.String("mode", "lazy", "lazy | eager | twophase | rekey")
	reps := fs.Int("reps", 30, "số lần lặp mỗi phép đo (micro)")
	_ = fs.Parse(os.Args[2:])
	var err error
	switch os.Args[1] {
	case "micro":
		err = micro(*reps)
	case "e2e":
		err = e2e(*docs, *mode)
	case "dek":
		err = dekScenario(*mode)
	default:
		err = fmt.Errorf("lệnh không hợp lệ: %s", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

// ---------------- micro ----------------

// median chạy f reps lần, trả trung vị.
func median(reps int, f func()) time.Duration {
	ds := make([]time.Duration, reps)
	for i := range ds {
		t := time.Now()
		f()
		ds[i] = time.Since(t)
	}
	slices.Sort(ds)
	return ds[reps/2]
}

func ms(d time.Duration) string { return fmt.Sprintf("%.3f", float64(d.Microseconds())/1000) }

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

const (
	readPol  = "(dept_finance: v2) or (role_director: v1)"
	writePol = "(dept_finance: v2) and (role_manager: v1)"
)

var sample = shared.Payload{Title: "Báo cáo tài chính Q3", Body: strings.Repeat("Doanh thu, lợi nhuận, dòng tiền. ", 30), Author: "An"}

func micro(reps int) error {
	pk, msk := must2(shared.ABESetup())
	attrs := map[string]string{"dept_finance": "v2", "role_manager": "v1", "proj_alpha": "v1"}
	ukey := must(shared.ABEKeyGen(msk, attrs))
	rpub, rpriv := must2(shared.NewReadKeypair())
	_, wpriv := must2(shared.NewWriteKeypair())
	abeCt := must(shared.ABEEncrypt(pk, readPol, rpriv))
	dek := shared.RandomBytes(32)
	wrapped := must(shared.WrapDEK(rpub, dek))
	aad := []byte("doc:1")
	nonce, ct, _ := shared.SealPayload(dek, sample, aad)
	msg := shared.RandomBytes(32)
	sig := must(shared.Sign(wpriv, msg))
	wpub := wpriv[32:]

	c := map[string]time.Duration{
		"abe_enc":  median(reps, func() { must(shared.ABEEncrypt(pk, readPol, rpriv)) }),
		"abe_dec":  median(reps, func() { must(shared.ABEDecrypt(ukey, abeCt)) }),
		"keygen":   median(reps, func() { must(shared.ABEKeyGen(msk, attrs)) }),
		"seal":     median(reps*10, func() { must(shared.WrapDEK(rpub, dek)) }),
		"open":     median(reps*10, func() { must(shared.UnwrapDEK(rpub, rpriv, wrapped)) }),
		"aead_enc": median(reps*10, func() { shared.SealPayload(dek, sample, aad) }),
		"aead_dec": median(reps*10, func() { must(shared.OpenPayload(dek, nonce, ct, aad)) }),
		"sign":     median(reps*10, func() { must(shared.Sign(wpriv, msg)) }),
		"verify":   median(reps*10, func() { shared.Verify(wpub, msg, sig) }),
	}
	fmt.Printf("## Chi phí từng thao tác (trung vị %d lần, ms)\n\n", reps)
	fmt.Println("| Thao tác | Ký hiệu | ms |\n|---|---|---|")
	rows := [][3]string{
		{"CP-ABE Encrypt private key 32 byte, chính sách 2 thuộc tính", "c_abe", "abe_enc"},
		{"CP-ABE Decrypt", "c_abe_dec", "abe_dec"},
		{"CP-ABE KeyGen, 3 thuộc tính", "c_keygen", "keygen"},
		{"Bọc DEK (X25519 sealed box)", "c_seal", "seal"},
		{"Mở DEK (X25519 sealed box)", "c_open", "open"},
		{fmt.Sprintf("AES-256-GCM mã hóa nội dung (%d byte)", len(ct)), "c_aead", "aead_enc"},
		{"AES-256-GCM giải mã", "c_aead_dec", "aead_dec"},
		{"Ed25519 ký", "c_sign", "sign"},
		{"Ed25519 kiểm", "c_verify", "verify"},
	}
	for _, r := range rows {
		fmt.Printf("| %s | %s | %s |\n", r[0], r[1], ms(c[r[2]]))
	}
	fmt.Printf("\nTỉ lệ c_abe / c_seal ≈ %.0f lần.\n", float64(c["abe_enc"])/float64(c["seal"]))

	// Mô phỏng thu hồi 1 thuộc tính bằng chính các thao tác trên (không gồm mạng, DB).
	// Dữ liệu mẫu: thuộc tính nằm trong P_read = 2 chính sách đọc, P_write = 1 chính sách ghi, U = 2 user cấp lại khóa.
	const pRead, pWrite, users = 2, 1, 2
	fmt.Printf("\n## Thu hồi 1 thuộc tính theo số tài liệu D (chạy thật, ms; P_read=%d, P_write=%d, U=%d)\n\n", pRead, pWrite, users)
	fmt.Println("| D | Cách cũ: U KeyGen + D × CP-ABE | Lazy, L=0 | Lazy, L=3 | Eager | Hai pha + re-key (pha 2) |\n|---|---|---|---|---|---|")
	for _, d := range []int{4, 10, 100, 1000} {
		old := timeIt(func() {
			for i := 0; i < users; i++ {
				must(shared.ABEKeyGen(msk, attrs))
			}
			for i := 0; i < d; i++ {
				must(shared.ABEEncrypt(pk, readPol, dek))
			}
		})
		lazy := func(l int) time.Duration {
			return timeIt(func() {
				for i := 0; i < users; i++ {
					must(shared.ABEKeyGen(msk, attrs))
				}
				for i := 0; i < pRead*(1+l)+pWrite; i++ {
					must(shared.ABEEncrypt(pk, readPol, rpriv))
				}
			})
		}
		l0, l3 := lazy(0), lazy(3)
		eager := l0 + timeIt(func() {
			for i := 0; i < d; i++ {
				must(shared.WrapDEK(rpub, must(shared.UnwrapDEK(rpub, rpriv, wrapped))))
			}
		})
		rekey := timeIt(func() {
			for i := 0; i < d; i++ {
				k := must(shared.UnwrapDEK(rpub, rpriv, wrapped))
				p := must(shared.OpenPayload(k, nonce, ct, aad))
				k2 := shared.RandomBytes(32)
				_, ct2, _ := shared.SealPayload(k2, p, aad)
				must(shared.WrapDEK(rpub, k2))
				must(shared.Sign(wpriv, ct2[:32]))
			}
		})
		fmt.Printf("| %d | %s | %s | %s | %s | %s (pha 1 = Lazy L=0) |\n", d, ms(old), ms(l0), ms(l3), ms(eager), ms(rekey))
	}
	fmt.Printf("\nĐiểm hòa vốn số lần CP-ABE: D > P_read·(1+L) + P_write = %d (L=0), %d (L=3).\n", pRead+pWrite, pRead*4+pWrite)

	fmt.Println("\n## Đọc N tài liệu cùng chính sách (ms)\n\n| N | Không cache: N × (CP-ABE + mở) | Có cache: 1 CP-ABE + N × mở |\n|---|---|---|")
	readOne := func() {
		k := must(shared.UnwrapDEK(rpub, rpriv, wrapped))
		must(shared.OpenPayload(k, nonce, ct, aad))
		shared.Verify(wpub, msg, sig)
	}
	for _, n := range []int{1, 10, 100} {
		nocache := timeIt(func() {
			for i := 0; i < n; i++ {
				must(shared.ABEDecrypt(ukey, abeCt))
				readOne()
			}
		})
		cache := timeIt(func() {
			must(shared.ABEDecrypt(ukey, abeCt))
			for i := 0; i < n; i++ {
				readOne()
			}
		})
		fmt.Printf("| %d | %s | %s |\n", n, ms(nocache), ms(cache))
	}
	return nil
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}

func timeIt(f func()) time.Duration {
	t := time.Now()
	f()
	return time.Since(t)
}

// ---------------- dùng stack Docker đang chạy ----------------

type env struct {
	auth  *shared.AuthClient
	cloud *shared.CloudClient
	pub   []byte
}

func newEnv() (*env, error) {
	e := &env{
		auth:  &shared.AuthClient{Base: getenv("AUTHORITY_URL", "http://authority:8081")},
		cloud: &shared.CloudClient{Base: getenv("CLOUD_URL", "http://cloud-api:8082")},
	}
	var err error
	e.pub, err = e.auth.System()
	return e, err
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// as trả client cloud mang access token của uid.
func (e *env) as(uid string) (*shared.CloudClient, error) {
	tok, err := e.auth.Token(uid)
	return e.cloud.As(tok), err
}

// openPolicyPriv mở private key thế hệ gen của chính sách bằng khóa ABE của user.
func (e *env) openPolicyPriv(key *shared.UserKey, pid string, gen int) (*shared.Policy, []byte, error) {
	p, err := e.cloud.GetPolicy(pid)
	if err != nil {
		return nil, nil, err
	}
	if err := shared.VerifyPolicy(p, e.pub); err != nil {
		return nil, nil, err
	}
	k := p.Key(gen)
	if k == nil || len(k.ABEWrappedPriv) == 0 {
		return p, nil, errors.New("thế hệ đã hủy")
	}
	priv, err := shared.ABEDecrypt(key.Key, k.ABEWrappedPriv)
	return p, priv, err
}

// q3 trả id chính sách đọc / ghi của Báo cáo tài chính Q3 (đăng ký lại là idempotent).
func (e *env) q3() (string, string, error) {
	rid, err := e.auth.RegisterPolicy(shared.KindRead, "dept_finance or role_director")
	if err != nil {
		return "", "", err
	}
	wid, err := e.auth.RegisterPolicy(shared.KindWrite, "dept_finance and role_manager")
	return rid, wid, err
}

func e2e(docs int, mode string) error {
	e, err := newEnv()
	if err != nil {
		return err
	}
	rid, wid, err := e.q3()
	if err != nil {
		return err
	}
	an, err := e.auth.UserKey("an")
	if err != nil {
		return err
	}
	wp, err := e.cloud.GetPolicy(wid)
	if err != nil {
		return err
	}
	_, wpriv, err := e.openPolicyPriv(an, wid, wp.CurrentGen)
	if err != nil {
		return fmt.Errorf("An mở Write Key: %w", err)
	}
	rp, err := e.cloud.GetPolicy(rid)
	if err != nil {
		return err
	}
	cl, err := e.as("an")
	if err != nil {
		return err
	}
	t0 := time.Now()
	for i := 0; i < docs; i++ {
		v, err := shared.BuildVersion(shared.NewDocID(), 1, sample, rid, rp.Key(rp.CurrentGen), wid, wp.CurrentGen, wpriv)
		if err != nil {
			return err
		}
		if err := cl.CreateDocument(v); err != nil {
			return err
		}
	}
	log.Printf("đã thêm %d tài liệu trong %v", docs, time.Since(t0).Round(time.Millisecond))

	t0 = time.Now()
	msg, err := e.auth.Revoke("binh", "dept_finance", mode)
	if err != nil {
		return err
	}
	phase1 := time.Since(t0)
	phase2 := time.Duration(0)
	if mode == "twophase" || mode == "rekey" {
		for {
			au, err := e.auth.Audit()
			if err != nil {
				return err
			}
			if len(au) > 0 && au[0].Action == "revoke.phase2" {
				phase2 = time.Since(t0)
				msg += " || " + au[0].Detail
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	fmt.Printf("| %d | %s | %s | %s |\n", docs+4, mode, ms(phase1), map[bool]string{true: ms(phase2), false: "—"}[phase2 > 0])
	log.Println(msg)
	return nil
}

// dekScenario: Bình đọc Báo cáo Q3 v1, lưu lại DEK, private Policy Key và bản mã; sau đó bị thu hồi dept_finance.
func dekScenario(mode string) error {
	e, err := newEnv()
	if err != nil {
		return err
	}
	rid, _, err := e.q3()
	if err != nil {
		return err
	}
	binh, err := e.auth.UserKey("binh")
	if err != nil {
		return err
	}
	cl, err := e.as("binh")
	if err != nil {
		return err
	}
	all, err := cl.ListDocuments()
	if err != nil {
		return err
	}
	var target *shared.DocVersion
	for i := range all {
		if all[i].ReadPolicyID == rid {
			target = &all[i]
		}
	}
	if target == nil {
		return errors.New("không thấy tài liệu Q3")
	}
	_, polPriv, err := e.openPolicyPriv(binh, rid, target.ReadGen)
	if err != nil {
		return fmt.Errorf("Bình mở Policy Key trước thu hồi: %w", err)
	}
	pubOld := mustPolicyPub(e, rid, target.ReadGen)
	savedDEK, err := shared.UnwrapDEK(pubOld, polPriv, target.WrappedDEK)
	if err != nil {
		return err
	}
	saved := *target
	if _, err := e.auth.Revoke("binh", "dept_finance", mode); err != nil {
		return err
	}
	if mode == "twophase" || mode == "rekey" {
		for {
			au, _ := e.auth.Audit()
			if len(au) > 0 && au[0].Action == "revoke.phase2" {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	yes := func(ok bool) string { return map[bool]string{true: "ĐỌC ĐƯỢC", false: "không"}[ok] }
	// (1) bản mã đã tải trước khi bị thu hồi + DEK đã lưu.
	_, err = shared.OpenPayload(savedDEK, saved.Nonce, saved.Ciphertext, saved.AAD())
	r1 := yes(err == nil)
	// (2) tải lại từ cloud bằng token mới của Bình.
	cl, err = e.as("binh")
	if err != nil {
		return err
	}
	vs, err := cl.Versions(saved.DocID)
	if err != nil {
		return err
	}
	var now *shared.DocVersion
	for i := range vs {
		if vs[i].Version == saved.Version {
			now = &vs[i]
		}
	}
	r2, r3, r4 := "cloud không trả bản mã", "—", "—"
	if now != nil && !now.Withheld {
		r2 = "cloud trả bản mã"
		changed := !bytes.Equal(now.Ciphertext, saved.Ciphertext)
		// (3) DEK đã lưu + bản mã tải lại.
		_, err = shared.OpenPayload(savedDEK, now.Nonce, now.Ciphertext, now.AAD())
		r3 = yes(err == nil)
		if changed {
			r3 += " (bản mã đã đổi)"
		}
		// (4) private Policy Key cũ đã lưu + wrapped_dek tải lại.
		_, err = shared.UnwrapDEK(pubOld, polPriv, now.WrappedDEK)
		r4 = yes(err == nil)
	}
	fmt.Printf("| %s | %s | %s | %s | %s |\n", mode, r1, r2, r3, r4)
	return nil
}

func mustPolicyPub(e *env, pid string, gen int) []byte {
	p := must(e.cloud.GetPolicy(pid))
	return p.Key(gen).PublicKey
}
