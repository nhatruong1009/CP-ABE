package shared

import (
	"net/http"
	"net/url"
	"time"
)

// Các kiểu dữ liệu authority trả về (dùng chung cho authority và app).

type UserView struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Attrs    []string          `json:"attrs"`
	KeyEpoch int               `json:"key_epoch"`
	KeyAttrs map[string]string `json:"key_attrs"`
}

type UserKey struct {
	UserID string            `json:"user_id"`
	Epoch  int               `json:"epoch"`
	Attrs  map[string]string `json:"attrs"`
	Key    []byte            `json:"key"`
}

type PolicyView struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Logical    string `json:"logical"`
	CurrentGen int    `json:"current_gen"`
	Compiled   string `json:"compiled"`
}

type AttributeView struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	Desc    string `json:"desc"`
}

type AuditView struct {
	Time   time.Time `json:"time"`
	Action string    `json:"action"`
	Detail string    `json:"detail"`
}

// AuthClient: app gọi authority (cả hai cùng nằm trong vùng tin cậy).
type AuthClient struct{ Base string }

func (c *AuthClient) System() ([]byte, error) {
	var out struct {
		AuthorityPub []byte `json:"authority_pub"`
	}
	err := DoJSON(http.MethodGet, c.Base+"/system", "", nil, &out)
	return out.AuthorityPub, err
}

func (c *AuthClient) Users() ([]UserView, error) {
	var out []UserView
	return out, DoJSON(http.MethodGet, c.Base+"/users", "", nil, &out)
}

func (c *AuthClient) UserKey(uid string) (*UserKey, error) {
	var out UserKey
	return &out, DoJSON(http.MethodGet, c.Base+"/users/"+url.PathEscape(uid)+"/key", "", nil, &out)
}

func (c *AuthClient) Attributes() ([]AttributeView, error) {
	var out []AttributeView
	return out, DoJSON(http.MethodGet, c.Base+"/attributes", "", nil, &out)
}

func (c *AuthClient) Policies() ([]PolicyView, error) {
	var out []PolicyView
	return out, DoJSON(http.MethodGet, c.Base+"/policies", "", nil, &out)
}

func (c *AuthClient) Audit() ([]AuditView, error) {
	var out []AuditView
	return out, DoJSON(http.MethodGet, c.Base+"/audit", "", nil, &out)
}

func (c *AuthClient) RegisterPolicy(kind, logical string) (string, error) {
	var out struct {
		PolicyID string `json:"policy_id"`
	}
	err := DoJSON(http.MethodPost, c.Base+"/policies", "", map[string]string{"kind": kind, "logical": logical}, &out)
	return out.PolicyID, err
}

type messageResp struct {
	Message string `json:"message"`
}

func (c *AuthClient) Grant(uid, attr string) (string, error) {
	var out messageResp
	err := DoJSON(http.MethodPost, c.Base+"/users/"+url.PathEscape(uid)+"/attributes", "", map[string]string{"attr": attr}, &out)
	return out.Message, err
}

func (c *AuthClient) Revoke(uid, attr, mode string) (string, error) {
	var out messageResp
	err := DoJSON(http.MethodDelete, c.Base+"/users/"+url.PathEscape(uid)+"/attributes/"+url.PathEscape(attr)+
		"?mode="+url.QueryEscape(mode), "", nil, &out)
	return out.Message, err
}
