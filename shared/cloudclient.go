package shared

import (
	"fmt"
	"net/http"
	"net/url"
)

// CloudClient gọi cloud-api. Token chỉ authority có (để đăng chính sách / bọc lại DEK).
type CloudClient struct {
	Base  string
	Token string
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
	err := DoJSON(http.MethodGet, c.url("/documents"), "", nil, &vs)
	return vs, err
}

// AllVersions trả mọi phiên bản của mọi tài liệu (cho chế độ Eager và trang "Góc nhìn Cloud").
func (c *CloudClient) AllVersions() ([]DocVersion, error) {
	var vs []DocVersion
	err := DoJSON(http.MethodGet, c.url("/versions"), "", nil, &vs)
	return vs, err
}

func (c *CloudClient) Versions(docID string) ([]DocVersion, error) {
	var vs []DocVersion
	err := DoJSON(http.MethodGet, c.url("/documents/%s/versions", docID), "", nil, &vs)
	return vs, err
}

func (c *CloudClient) CreateDocument(v *DocVersion) error {
	return DoJSON(http.MethodPost, c.url("/documents"), "", v, nil)
}

func (c *CloudClient) AddVersion(v *DocVersion) error {
	return DoJSON(http.MethodPost, c.url("/documents/%s/versions", v.DocID), "", v, nil)
}

type RewrapRequest struct {
	ReadGen    int    `json:"read_gen"`
	WrappedDEK []byte `json:"wrapped_dek"`
}

func (c *CloudClient) Rewrap(docID string, version, gen int, wrapped []byte) error {
	return DoJSON(http.MethodPut, c.url("/documents/%s/versions/%d/wrap", docID, version), c.Token,
		RewrapRequest{ReadGen: gen, WrappedDEK: wrapped}, nil)
}

// DemoTamper: mô phỏng cloud độc hại sửa 1 byte bản mã (kịch bản E).
func (c *CloudClient) DemoTamper(docID string, version int) error {
	return DoJSON(http.MethodPost, c.url("/_demo/tamper/%s/%d", docID, version), "", nil, nil)
}
