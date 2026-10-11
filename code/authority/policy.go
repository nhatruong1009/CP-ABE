package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"cpabe-demo/shared"
)

var (
	tokenRe = regexp.MustCompile(`[A-Za-z0-9_]+|[()]|\S`)
	identRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
)

// tokenize tách chính sách logic, vd. "(dept_hr and role_manager) or role_director".
// Trả về các token đã chuẩn hóa và danh sách thuộc tính xuất hiện.
func (a *Authority) tokenize(logical string) (tokens, attrs []string, err error) {
	for _, t := range tokenRe.FindAllString(logical, -1) {
		lt := strings.ToLower(t)
		switch {
		case t == "(" || t == ")":
			tokens = append(tokens, t)
		case lt == "and" || lt == "or":
			tokens = append(tokens, lt)
		case lt == "not":
			return nil, nil, fmt.Errorf("không hỗ trợ 'not' (xung đột với cơ chế phiên bản thuộc tính)")
		case identRe.MatchString(t):
			if _, ok := a.st.Attributes[t]; !ok {
				return nil, nil, fmt.Errorf("thuộc tính không tồn tại: %s", t)
			}
			tokens = append(tokens, t)
			if !slices.Contains(attrs, t) {
				attrs = append(attrs, t)
			}
		default:
			return nil, nil, fmt.Errorf("ký tự không hợp lệ: %q", t)
		}
	}
	if len(attrs) == 0 {
		return nil, nil, fmt.Errorf("chính sách rỗng")
	}
	return tokens, attrs, nil
}

// compile biến chính sách logic thành chính sách thật với version hiện hành:
// "dept_finance or role_director" → "(dept_finance: v3) or (role_director: v1)".
func (a *Authority) compile(logical string) (string, error) {
	tokens, _, err := a.tokenize(logical)
	if err != nil {
		return "", err
	}
	out := make([]string, len(tokens))
	for i, t := range tokens {
		if at, ok := a.st.Attributes[t]; ok {
			out[i] = fmt.Sprintf("(%s: v%d)", t, at.Version)
		} else {
			out[i] = t
		}
	}
	compiled := strings.Join(out, " ")
	if err := shared.ABEValidatePolicy(compiled); err != nil {
		return "", fmt.Errorf("cú pháp chính sách sai: %w", err)
	}
	return compiled, nil
}

func (a *Authority) usesAttr(p *PolicyRec, attr string) bool {
	_, attrs, err := a.tokenize(p.Logical)
	return err == nil && slices.Contains(attrs, attr)
}

func policyID(kind string, tokens []string) string {
	sum := sha256.Sum256([]byte(kind + ":" + strings.Join(tokens, " ")))
	return kind[:1] + "_" + hex.EncodeToString(sum[:5])
}

// registerPolicy: trả về policy_id; nếu chính sách mới thì tạo thế hệ 1 và đăng lên cloud.
func (a *Authority) registerPolicy(kind, logical string) (string, error) {
	if kind != shared.KindRead && kind != shared.KindWrite {
		return "", fmt.Errorf("kind phải là read hoặc write")
	}
	tokens, _, err := a.tokenize(logical)
	if err != nil {
		return "", err
	}
	id := policyID(kind, tokens)
	if _, ok := a.st.Policies[id]; ok {
		return id, nil
	}
	p := &PolicyRec{ID: id, Kind: kind, Logical: strings.Join(tokens, " "), Gens: map[int]*GenRec{}}
	if err := a.newGen(p); err != nil {
		return "", err
	}
	if err := a.publish(p); err != nil {
		return "", err
	}
	a.st.Policies[id] = p
	a.st.audit("policy.create", fmt.Sprintf("%s [%s] %s", id, kind, p.Logical))
	return id, nil
}

// newGen sinh cặp khóa thế hệ mới; private key được mã hóa CP-ABE theo chính sách đã gắn version.
func (a *Authority) newGen(p *PolicyRec) error {
	compiled, err := a.compile(p.Logical)
	if err != nil {
		return err
	}
	var pub, priv []byte
	if p.Kind == shared.KindRead {
		pub, priv, err = shared.NewReadKeypair()
	} else {
		pub, priv, err = shared.NewWriteKeypair()
	}
	if err != nil {
		return err
	}
	ct, err := shared.ABEEncrypt(a.st.PK, compiled, priv)
	if err != nil {
		return err
	}
	p.CurrentGen++
	p.Gens[p.CurrentGen] = &GenRec{Pub: pub, Priv: priv, Compiled: compiled, ABECt: ct}
	return nil
}

// reencryptOldGens: sau khi tăng version thuộc tính, mã hóa lại các thế hệ cũ theo version mới,
// để khóa cũ (version cũ) không còn mở được bất kỳ bản mã CP-ABE nào trên cloud.
// Write Key thế hệ cũ không còn dùng để ký nên bị hủy hẳn.
func (a *Authority) reencryptOldGens(p *PolicyRec) error {
	compiled, err := a.compile(p.Logical)
	if err != nil {
		return err
	}
	for gen, g := range p.Gens {
		if gen == p.CurrentGen || g.ABECt == nil {
			continue
		}
		if p.Kind == shared.KindWrite {
			g.ABECt, g.Compiled = nil, "(đã hủy)"
			continue
		}
		if g.ABECt, err = shared.ABEEncrypt(a.st.PK, compiled, g.Priv); err != nil {
			return err
		}
		g.Compiled = compiled
	}
	return nil
}

// publish đăng toàn bộ chính sách (có chữ ký authority) lên cloud.
func (a *Authority) publish(p *PolicyRec) error {
	out := &shared.Policy{PolicyHeader: shared.PolicyHeader{
		PolicyID: p.ID, Kind: p.Kind, Logical: p.Logical, CurrentGen: p.CurrentGen,
	}}
	out.Sig = shared.MustSign(a.st.SignKey, out.PolicyHeader.SignedBytes())
	for gen := 1; gen <= p.CurrentGen; gen++ {
		g, ok := p.Gens[gen]
		if !ok {
			continue
		}
		k := shared.PolicyKey{PolicyID: p.ID, Gen: gen, Compiled: g.Compiled, PublicKey: g.Pub, ABEWrappedPriv: g.ABECt}
		k.Sig = shared.MustSign(a.st.SignKey, k.SignedBytes(p.Kind))
		out.Keys = append(out.Keys, k)
	}
	return a.cloud.PutPolicy(out)
}
