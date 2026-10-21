package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"cpabe-demo/shared"
)

// WriteCheck: quy trình xem xét quyền SỬA một tài liệu (chạy khi mở trang Sửa, chưa ghi gì).
func (s *Session) WriteCheck(cur shared.DocVersion, canRead bool) (steps []*Step, allowed bool) {
	t := &tracer{}
	defer func() { steps = t.steps }()

	st := t.begin("Tải phiên bản mới nhất từ cloud", "cloud-api · bảng document_versions",
		"Phiên bản mới phải nối tiếp đúng phiên bản mới nhất (optimistic locking).")
	st.add("doc_id", cur.DocID, true)
	st.add("Phiên bản mới nhất → phiên bản sẽ tạo", fmt.Sprintf("v%d → v%d", cur.Version, cur.Version+1), false)
	st.add("read_policy_id · read_gen", fmt.Sprintf("%s · thế hệ %d", cur.ReadPolicyID, cur.ReadGen), true)
	st.add("write_policy_id · write_gen", fmt.Sprintf("%s · thế hệ %d", cur.WritePolicyID, cur.WriteGen), true)
	t.end(st)

	st = t.begin("Tải header write policy & kiểm chữ ký authority", "cloud-api · bảng policies + policy_keys",
		"Write Key là cặp khóa Ed25519 của chính sách ghi. Private key chỉ có ở dạng bản mã CP-ABE.")
	wp, err := s.Policy(cur.WritePolicyID)
	if err != nil {
		st.Status = "fail"
		st.bad("Lỗi", err.Error())
		t.end(st)
		return
	}
	wk := wp.Key(wp.CurrentGen)
	st.add("Chính sách ghi (logic)", wp.Logical, true)
	st.add("Thế hệ hiện hành", fmt.Sprintf("%d", wp.CurrentGen), false)
	if cur.WriteGen != wp.CurrentGen {
		st.add("Lưu ý", fmt.Sprintf("Phiên bản hiện tại được ký bằng thế hệ %d (cũ). Bản mới bắt buộc ký bằng thế hệ %d.",
			cur.WriteGen, wp.CurrentGen), false)
	}
	st.add(fmt.Sprintf("Thế hệ %d · chính sách thật", wp.CurrentGen), wk.Compiled, true)
	st.add(fmt.Sprintf("Thế hệ %d · public Write Key Ed25519", wp.CurrentGen), hx(wk.PublicKey), true)
	st.add(fmt.Sprintf("Thế hệ %d · abe_wrapped_priv (%s)", wp.CurrentGen, sizeOf(wk.ABEWrappedPriv)), hx(wk.ABEWrappedPriv), true)
	st.add("Kiểm header_sig, key_sig", "✔ hợp lệ với public key của authority", false)
	t.end(st)

	st = t.begin("Đối chiếu thuộc tính trong khóa với write policy", "app · keystore của "+s.ID.Name,
		fmt.Sprintf("Khóa ABE epoch %d của %s.", s.ID.Epoch, s.ID.Name))
	st.matchAttrs(wk.Compiled, s.ID.Attrs)
	if s.ID.Key != nil && shared.ABECouldDecrypt(s.ID.Attrs, wk.ABEWrappedPriv) {
		st.add("Kết luận", "✔ thỏa write policy", false)
	} else {
		st.Status = "fail"
		st.bad("Kết luận", "✖ không thỏa write policy: "+wp.Logical)
	}
	t.end(st)

	st = t.begin("Tầng 1 · Giải mã CP-ABE lấy private Write Key", "app · CIRCL tkn20 Decrypt",
		"Có private Write Key thì mới tạo được chữ ký mà cloud chấp nhận.")
	priv, cached, err := s.openPrivCached(wp, wp.CurrentGen)
	if err != nil {
		st.Status = "fail"
		st.bad("Kết quả", "✖ "+err.Error())
		t.end(st)
		st = t.begin("Kết luận", "", "")
		st.Status = "fail"
		st.bad("Quyền sửa", "✖ KHÔNG được sửa. Nếu cố gửi bản ghi (ký bằng khóa tự tạo), cloud sẽ trả 403.")
		return
	}
	st.add("Nguồn", map[bool]string{true: "cache trong phiên", false: "vừa chạy CP-ABE Decrypt"}[cached], false)
	st.add("Private Write Key Ed25519 (64 byte)", hx(priv), true)
	t.end(st)

	st = t.begin("Chuẩn bị bọc DEK cho phiên bản mới", "cloud-api · Policy Key đọc",
		"Nội dung mới được mã hóa bằng DEK mới, DEK bọc bằng PUBLIC key của Policy đọc (thế hệ hiện hành). Không cần quyền đọc.")
	rp, err := s.Policy(cur.ReadPolicyID)
	if err != nil {
		st.Status = "fail"
		st.bad("Lỗi", err.Error())
		t.end(st)
		return
	}
	st.add("Chính sách đọc", rp.Logical, true)
	st.add(fmt.Sprintf("Public key X25519 thế hệ %d", rp.CurrentGen), hx(rp.Key(rp.CurrentGen).PublicKey), true)
	if canRead {
		st.add("Quyền đọc nội dung hiện tại", "✔ có, nội dung cũ được nạp vào form", false)
	} else {
		st.add("Quyền đọc nội dung hiện tại", "– không có (ghi mà không đọc): form để trống, nội dung mới thay thế nội dung cũ", false)
	}
	t.end(st)

	st = t.begin("Cloud sẽ kiểm gì khi nhận bản ghi", "cloud-api · checkWrite",
		"Cloud không có khóa bí mật nào, chỉ dùng public key để kiểm.")
	st.add("1. Số phiên bản", fmt.Sprintf("phải đúng v%d (nếu người khác lưu trước → 409)", cur.Version+1), false)
	st.add("2. Chính sách", "read/write policy giữ nguyên như phiên bản trước", false)
	st.add("3. Thế hệ Write Key", fmt.Sprintf("write_gen phải = %d (thế hệ cũ đã bị thu hồi → 403)", wp.CurrentGen), false)
	st.add("4. Chữ ký", "Ed25519 verify bằng public Write Key ở bước 2 (sai → 403)", false)
	t.end(st)

	st = t.begin("Kết luận", "", "")
	st.add("Quyền sửa", "✔ ĐƯỢC sửa: "+s.ID.Name+" mở được Write Key thế hệ hiện hành", false)
	t.end(st)
	return t.steps, true
}

// Write tạo phiên bản mới và ghi lại từng bước (hiển thị sau khi lưu).
// forge = true: kịch bản D, không có Write Key nên ký bằng một khóa tự sinh. Cloud phải từ chối.
func (s *Session) Write(docID string, version int, readPID, writePID string, p shared.Payload, forge bool) (steps []*Step, err error) {
	t := &tracer{}
	defer func() { steps = t.steps }()
	fail := func(st *Step, e error) ([]*Step, error) {
		st.Status = "fail"
		st.bad("Lỗi", e.Error())
		t.end(st)
		return nil, e
	}

	rp, err := s.Policy(readPID)
	if err != nil {
		return nil, err
	}
	wp, err := s.Policy(writePID)
	if err != nil {
		return nil, err
	}
	v := &shared.DocVersion{DocID: docID, Version: version, ReadPolicyID: readPID, ReadGen: rp.CurrentGen,
		WritePolicyID: writePID, WriteGen: wp.CurrentGen}

	// 1. Write Key.
	var wpriv []byte
	if forge {
		st := t.begin("Lấy khóa ký: GIẢ MẠO", "app",
			"Không mở được Write Key qua CP-ABE nên tự sinh một cặp Ed25519 bất kỳ để ký.")
		_, wpriv, err = shared.NewWriteKeypair()
		if err != nil {
			return fail(st, err)
		}
		st.Status = "fail"
		st.bad("Private key tự sinh (64 byte)", hx(wpriv))
		t.end(st)
	} else {
		st := t.begin("Tầng 1 · Mở private Write Key bằng CP-ABE", "app · CIRCL tkn20 Decrypt",
			fmt.Sprintf("Write policy: %s · thế hệ %d", wp.Logical, wp.CurrentGen))
		var cached bool
		wpriv, cached, err = s.openPrivCached(wp, wp.CurrentGen)
		if err != nil {
			return fail(st, fmt.Errorf("không có quyền ghi (%s): %w", wp.Logical, err))
		}
		st.add("Nguồn", map[bool]string{true: "cache trong phiên", false: "vừa chạy CP-ABE Decrypt"}[cached], false)
		st.add("Private Write Key Ed25519 (64 byte)", hx(wpriv), true)
		t.end(st)
	}

	// 2. DEK + AES-GCM.
	st := t.begin("Tầng 3 · Sinh DEK mới và mã hóa nội dung AES-256-GCM", "app · crypto/rand + AES-GCM",
		"Mỗi phiên bản có DEK riêng. Đây là lý do sửa tài liệu tự động là lazy re-encryption.")
	dek := shared.RandomBytes(32)
	plain, _ := json.Marshal(p)
	st.add("DEK mới (32 byte)", hx(dek), true)
	st.add(fmt.Sprintf("Plaintext (%s, JSON)", sizeOf(plain)), string(plain), true)
	st.add("AAD", string(v.AAD()), true)
	if v.Nonce, v.Ciphertext, err = shared.SealPayload(dek, p, v.AAD()); err != nil {
		return fail(st, err)
	}
	st.add("nonce ("+sizeOf(v.Nonce)+")", hx(v.Nonce), true)
	st.add("ciphertext ("+sizeOf(v.Ciphertext)+")", hx(v.Ciphertext), true)
	t.end(st)

	// 3. Bọc DEK.
	st = t.begin("Tầng 2 · Bọc DEK bằng public key của Policy đọc", "app · X25519 sealed box",
		fmt.Sprintf("Read policy: %s · thế hệ hiện hành %d. Chỉ người thỏa read policy mới mở lại được.", rp.Logical, rp.CurrentGen))
	rk := rp.Key(rp.CurrentGen)
	st.add("Public key X25519", hx(rk.PublicKey), true)
	if v.WrappedDEK, err = shared.WrapDEK(rk.PublicKey, dek); err != nil {
		return fail(st, err)
	}
	st.add("wrapped_dek ("+sizeOf(v.WrappedDEK)+")", hx(v.WrappedDEK), true)
	t.end(st)

	// 4. Ký.
	signTitle := "Ký phiên bản bằng Write Key"
	if forge {
		signTitle = "Ký phiên bản bằng KHÓA GIẢ (không phải Write Key)"
	}
	st = t.begin(signTitle, "app · Ed25519",
		"Thông điệp ký = SHA-256(doc_id, version, read/write policy, write_gen, nonce, ciphertext).")
	if forge {
		st.Status = "fail"
	}
	st.add("Thông điệp được ký", hx(v.SignedBytes()), true)
	if v.Signature, err = shared.Sign(wpriv, v.SignedBytes()); err != nil {
		return fail(st, err)
	}
	st.add("signature (64 byte)", hx(v.Signature), true)
	t.end(st)

	// 5. Gửi cloud.
	method, path := "POST", "/documents"
	if version > 1 {
		path = "/documents/" + docID + "/versions"
	}
	st = t.begin("Gửi bản mã lên cloud", "cloud-api · "+method+" "+path,
		"Cloud kiểm số phiên bản, thế hệ Write Key và chữ ký trước khi lưu.")
	st.add("Gửi đi", fmt.Sprintf("v%d · read_gen %d · write_gen %d · %d byte ciphertext · KHÔNG có plaintext, KHÔNG có khóa",
		v.Version, v.ReadGen, v.WriteGen, len(v.Ciphertext)), false)
	if version == 1 {
		err = s.cloud.CreateDocument(v)
	} else {
		err = s.cloud.AddVersion(v)
	}
	var he *shared.HTTPError
	switch {
	case err == nil:
		st.add("Phản hồi", fmt.Sprintf("%d Created: cloud chấp nhận, đã lưu v%d", http.StatusCreated, version), false)
	case errors.As(err, &he):
		st.Status = "fail"
		st.bad("Phản hồi", fmt.Sprintf("%d %s: %s", he.Status, http.StatusText(he.Status), he.Msg))
	default:
		st.Status = "fail"
		st.bad("Lỗi", err.Error())
	}
	t.end(st)
	return nil, err
}
