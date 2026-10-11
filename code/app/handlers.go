package main

import (
	"fmt"
	"sort"
	"strconv"

	"cpabe-demo/shared"
)

// ---------------- Kho tài liệu ----------------

func (s *Server) handleIndex(c *ctx) (string, error) {
	c.page.Title, c.page.Nav = "Kho tài liệu", "index"
	docs, err := s.cloud.ListDocuments()
	if err != nil {
		return "index.html", err
	}
	rows := make([]ReadResult, 0, len(docs))
	for _, d := range docs {
		rows = append(rows, c.sess.Read(d))
	}
	c.page.Data = rows
	return "index.html", nil
}

type docData struct {
	Latest   ReadResult
	Selected ReadResult // phiên bản đang xem quy trình giải mã (?v=N, mặc định mới nhất)
	History  []ReadResult
}

func (s *Server) handleDoc(c *ctx) (string, error) {
	c.page.Title, c.page.Nav = "Tài liệu", "index"
	vs, err := s.cloud.Versions(c.r.PathValue("id"))
	if err != nil {
		return "doc.html", err
	}
	if len(vs) == 0 {
		return "doc.html", fmt.Errorf("không có tài liệu")
	}
	d := docData{}
	for _, v := range vs {
		d.History = append(d.History, c.sess.Read(v))
	}
	d.Latest, d.Selected = d.History[0], d.History[0]
	if n, err := strconv.Atoi(c.r.URL.Query().Get("v")); err == nil {
		for _, h := range d.History {
			if h.V.Version == n {
				d.Selected = h
			}
		}
	}
	c.page.Data = d
	return "doc.html", nil
}

// ---------------- Tạo / sửa ----------------

type formData struct {
	IsNew        bool
	DocID        string
	BaseVersion  int
	Title, Body  string
	ReadLogical  string
	WriteLogical string
	CanRead      bool
	Attributes   []shared.AttributeView
	ReadOptions  []string
	WriteOptions []string
}

func (s *Server) formOptions(f *formData) {
	f.Attributes, _ = s.auth.Attributes()
	pols, _ := s.auth.Policies()
	for _, p := range pols {
		if p.Kind == shared.KindRead {
			f.ReadOptions = append(f.ReadOptions, p.Logical)
		} else {
			f.WriteOptions = append(f.WriteOptions, p.Logical)
		}
	}
}

func (s *Server) handleNewForm(c *ctx) (string, error) {
	c.page.Title, c.page.Nav = "Tạo tài liệu", "new"
	f := &formData{IsNew: true, ReadLogical: "dept_finance or role_director", WriteLogical: "dept_finance and role_manager"}
	s.formOptions(f)
	c.page.Data = f
	return "form.html", nil
}

func (s *Server) handleNew(c *ctx) (string, error) {
	f := &formData{IsNew: true, Title: c.r.FormValue("title"), Body: c.r.FormValue("body"),
		ReadLogical: c.r.FormValue("read"), WriteLogical: c.r.FormValue("write")}
	fail := func(err error) (string, error) {
		c.page.Title, c.page.Nav = "Tạo tài liệu", "new"
		s.formOptions(f)
		c.page.Data = f
		return "form.html", fmt.Errorf("%s", friendly(err))
	}
	rid, err := s.auth.RegisterPolicy(shared.KindRead, f.ReadLogical)
	if err != nil {
		return fail(fmt.Errorf("read policy: %w", err))
	}
	wid, err := s.auth.RegisterPolicy(shared.KindWrite, f.WriteLogical)
	if err != nil {
		return fail(fmt.Errorf("write policy: %w", err))
	}
	id := shared.NewDocID()
	err = c.sess.Write(id, 1, rid, wid, shared.Payload{Title: f.Title, Body: f.Body, Author: c.page.Me.Name})
	if err != nil {
		return fail(err)
	}
	return c.redirect("/doc/"+id, "Đã mã hóa và tải lên cloud: "+f.Title, "")
}

func (s *Server) handleEditForm(c *ctx) (string, error) {
	c.page.Title, c.page.Nav = "Sửa tài liệu", "index"
	vs, err := s.cloud.Versions(c.r.PathValue("id"))
	if err != nil || len(vs) == 0 {
		return c.redirect("/", "", "Không tìm thấy tài liệu")
	}
	r := c.sess.Read(vs[0])
	f := &formData{DocID: vs[0].DocID, BaseVersion: vs[0].Version, ReadLogical: r.ReadLogical,
		WriteLogical: r.WriteLogical, CanRead: r.OK(), Title: r.Payload.Title, Body: r.Payload.Body}
	c.page.Data = f
	if !r.CanWrite {
		return "form.html", fmt.Errorf("Bạn không thỏa write policy (%s), cloud sẽ từ chối khi lưu", r.WriteLogical)
	}
	return "form.html", nil
}

func (s *Server) handleEdit(c *ctx) (string, error) {
	id := c.r.PathValue("id")
	base, _ := strconv.Atoi(c.r.FormValue("base_version"))
	vs, err := s.cloud.Versions(id)
	if err != nil || len(vs) == 0 {
		return c.redirect("/", "", "Không tìm thấy tài liệu")
	}
	cur := vs[0]
	err = c.sess.Write(id, base+1, cur.ReadPolicyID, cur.WritePolicyID,
		shared.Payload{Title: c.r.FormValue("title"), Body: c.r.FormValue("body"), Author: c.page.Me.Name})
	if err != nil {
		return c.redirect("/doc/"+id, "", friendly(err))
	}
	return c.redirect("/doc/"+id, fmt.Sprintf("Đã lưu phiên bản %d (DEK mới, Policy Key thế hệ hiện hành)", base+1), "")
}

func (s *Server) handleForge(c *ctx) (string, error) {
	id := c.r.PathValue("id")
	vs, err := s.cloud.Versions(id)
	if err != nil || len(vs) == 0 {
		return c.redirect("/", "", "Không tìm thấy tài liệu")
	}
	err = c.sess.Forge(id, vs[0].Version+1, vs[0].ReadPolicyID, vs[0].WritePolicyID)
	if err != nil {
		return c.redirect("/doc/"+id, "", "Thử ghi trái phép thất bại đúng như mong đợi. "+friendly(err))
	}
	return c.redirect("/doc/"+id, "", "CẢNH BÁO: cloud đã CHẤP NHẬN bản ghi giả mạo!")
}

// ---------------- Quản trị thuộc tính ----------------

type adminData struct {
	Users      []shared.UserView
	Attributes []shared.AttributeView
	Policies   []shared.PolicyView
	Audit      []shared.AuditView
}

func (s *Server) handleAdmin(c *ctx) (string, error) {
	c.page.Title, c.page.Nav = "Quản trị thuộc tính", "admin"
	d := adminData{Users: c.page.Users}
	var err error
	if d.Attributes, err = s.auth.Attributes(); err != nil {
		return "admin.html", err
	}
	if d.Policies, err = s.auth.Policies(); err != nil {
		return "admin.html", err
	}
	d.Audit, err = s.auth.Audit()
	c.page.Data = d
	return "admin.html", err
}

func (s *Server) handleGrant(c *ctx) (string, error) {
	msg, err := s.auth.Grant(c.r.FormValue("user"), c.r.FormValue("attr"))
	if err != nil {
		return c.redirect("/admin", "", friendly(err))
	}
	return c.redirect("/admin", msg, "")
}

func (s *Server) handleRevoke(c *ctx) (string, error) {
	msg, err := s.auth.Revoke(c.r.FormValue("user"), c.r.FormValue("attr"), c.r.FormValue("mode"))
	if err != nil {
		return c.redirect("/admin", "", friendly(err))
	}
	return c.redirect("/admin", msg, "")
}

// ---------------- Góc nhìn Cloud ----------------

type cloudData struct {
	Policies []shared.Policy
	Versions []shared.DocVersion
}

func (s *Server) handleCloud(c *ctx) (string, error) {
	c.page.Title, c.page.Nav = "Góc nhìn Cloud", "cloud"
	d := cloudData{}
	var err error
	if d.Policies, err = s.cloud.ListPolicies(); err != nil {
		return "cloud.html", err
	}
	if d.Versions, err = s.cloud.AllVersions(); err != nil {
		return "cloud.html", err
	}
	sort.SliceStable(d.Versions, func(i, j int) bool { return d.Versions[i].CreatedAt.Before(d.Versions[j].CreatedAt) })
	c.page.Data = d
	return "cloud.html", nil
}

func (s *Server) handleTamper(c *ctx) (string, error) {
	id := c.r.FormValue("doc")
	v, _ := strconv.Atoi(c.r.FormValue("version"))
	if err := s.cloud.DemoTamper(id, v); err != nil {
		return c.redirect("/cloud", "", friendly(err))
	}
	return c.redirect("/doc/"+id, fmt.Sprintf("Cloud vừa sửa trái phép 1 bit của phiên bản %d. Xem app phát hiện thế nào.", v), "")
}
