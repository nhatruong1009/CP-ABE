package shared

import (
	"fmt"
	"net/http"
	"net/url"
)

// CloudClient gọi cloud-api. Token chỉ authority có (để đăng chính sách / bọc lại DEK).
// User là access token của người đang gọi (C2), gửi kèm các lời gọi đọc / ghi tài liệu.
type CloudClient struct {
	Base  string
	Token string
	User  string
}

// As trả bản sao client gửi kèm access token của một user.
func (c *CloudClient) As(userToken string) *CloudClient {
	cp := *c
	cp.User = userToken
	return &cp
}

// auth: authority dùng admin token; app dùng access token của user.
func (c *CloudClient) auth() string {
	if c.Token != "" {
		return c.Token
	}
	return c.User
}

func (c *CloudClient) url(format string, args ...any) string {
	for i, a := range args {
		if s, ok := a.(string); ok {
			args[i] = url.PathEscape(s)
		}
	}
	return c.Base + fmt.Sprintf(format, args...)
}

func (c *CloudClient) Health() error {
	return DoJSON(http.MethodGet, c.url("/healthz"), "", nil, nil)
}

func (c *CloudClient) GetPolicy(id string) (*Policy, error) {
	var p Policy
	err := DoJSON(http.MethodGet, c.url("/policies/%s", id), "", nil, &p)
	return &p, err
}

func (c *CloudClient) ListPolicies() ([]Policy, error) {
	var ps []Policy
	err := DoJSON(http.MethodGet, c.url("/policies"), "", nil, &ps)
	return ps, err
}

// PutPolicy ghi đè toàn bộ header + các thế hệ khóa của một chính sách.
func (c *CloudClient) PutPolicy(p *Policy) error {
	return DoJSON(http.MethodPut, c.url("/policies/%s", p.PolicyID), c.Token, p, nil)
}

// ListDocuments trả phiên bản mới nhất của mọi tài liệu.
func (c *CloudClient) ListDocuments() ([]DocVersion, error) {
	var vs []DocVersion
	err := DoJSON(http.MethodGet, c.url("/documents"), c.auth(), nil, &vs)
	return vs, err
}

// AllVersions trả mọi phiên bản của mọi tài liệu (cho chế độ Eager và trang "Góc nhìn Cloud").
func (c *CloudClient) AllVersions() ([]DocVersion, error) {
	var vs []DocVersion
	err := DoJSON(http.MethodGet, c.url("/versions"), c.auth(), nil, &vs)
	return vs, err
}

func (c *CloudClient) Versions(docID string) ([]DocVersion, error) {
	var vs []DocVersion
	err := DoJSON(http.MethodGet, c.url("/documents/%s/versions", docID), c.auth(), nil, &vs)
	return vs, err
}

func (c *CloudClient) CreateDocument(v *DocVersion) error {
	return DoJSON(http.MethodPost, c.url("/documents"), c.auth(), v, nil)
}

func (c *CloudClient) AddVersion(v *DocVersion) error {
	return DoJSON(http.MethodPost, c.url("/documents/%s/versions", v.DocID), c.auth(), v, nil)
}

type RewrapRequest struct {
	ReadGen    int    `json:"read_gen"`
	WrappedDEK []byte `json:"wrapped_dek"`
}

func (c *CloudClient) Rewrap(docID string, version, gen int, wrapped []byte) error {
	return DoJSON(http.MethodPut, c.url("/documents/%s/versions/%d/wrap", docID, version), c.Token,
		RewrapRequest{ReadGen: gen, WrappedDEK: wrapped}, nil)
}

// ReplaceVersion (C3, content re-key): authority thay một phiên bản bằng bản mã mới (DEK mới, ký lại).
func (c *CloudClient) ReplaceVersion(v *DocVersion) error {
	return DoJSON(http.MethodPut, c.url("/documents/%s/versions/%d", v.DocID, v.Version), c.Token, v, nil)
}

// PutAuthorityKey: authority đăng public key dùng để kiểm access token (C2).
func (c *CloudClient) PutAuthorityKey(pub []byte) error {
	return DoJSON(http.MethodPut, c.url("/authority-key"), c.Token, map[string][]byte{"public_key": pub}, nil)
}

// DemoTamper: mô phỏng cloud độc hại sửa 1 byte bản mã (kịch bản E).
func (c *CloudClient) DemoTamper(docID string, version int) error {
	return DoJSON(http.MethodPost, c.url("/_demo/tamper/%s/%d", docID, version), "", nil, nil)
}
