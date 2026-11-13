// nolint
package ldapAuth

import (
	"context"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
)

func TestEncodeHeaderValue(t *testing.T) {
	// ASCII is never changed, with or without encoding
	for _, enc := range []string{"", HeaderEncodingRFC2047} {
		if got := encodeHeaderValue("m.lukac@example.local", enc); got != "m.lukac@example.local" {
			t.Fatalf("enc %q: ASCII changed to %q", enc, got)
		}
	}

	// raw mode leaves non-ASCII as is
	if got := encodeHeaderValue("Matěj", ""); got != "Matěj" {
		t.Fatalf("raw: got %q", got)
	}

	// rfc2047: ASCII-only output that decodes back
	got := encodeHeaderValue("Matěj", HeaderEncodingRFC2047)
	if !isASCII(got) || !strings.HasPrefix(got, "=?UTF-8?b?") && !strings.HasPrefix(got, "=?UTF-8?B?") {
		t.Fatalf("rfc2047: got %q", got)
	}
	dec, err := new(mime.WordDecoder).DecodeHeader(got)
	if err != nil || dec != "Matěj" {
		t.Fatalf("rfc2047 round trip: got %q, err %v", dec, err)
	}
}

func TestEncodeHeaderValueLong(t *testing.T) {
	// long values are split into several encoded-words, still ASCII and decodable
	long := strings.Repeat("Žluťoučký kůň ", 10)
	got := encodeHeaderValue(long, HeaderEncodingRFC2047)
	if !isASCII(got) || strings.Contains(got, "|") {
		t.Fatalf("long: not ASCII or contains separator: %q", got)
	}
	dec, err := new(mime.WordDecoder).DecodeHeader(got)
	if err != nil || dec != long {
		t.Fatalf("long round trip: got %q, err %v", dec, err)
	}
}

func TestEncodeGroupsValue(t *testing.T) {
	v := "Technici|Správci sítě|NetBox_Admin"

	if got := encodeGroupsValue(v, "|", ""); got != v {
		t.Fatalf("raw: got %q", got)
	}

	got := encodeGroupsValue(v, "|", HeaderEncodingRFC2047)
	if !isASCII(got) {
		t.Fatalf("not ASCII: %q", got)
	}
	parts := strings.Split(got, "|")
	if len(parts) != 3 || parts[0] != "Technici" || parts[2] != "NetBox_Admin" {
		t.Fatalf("split: got %q", parts)
	}
	dec, err := new(mime.WordDecoder).DecodeHeader(parts[1])
	if err != nil || dec != "Správci sítě" {
		t.Fatalf("group round trip: got %q, err %v", dec, err)
	}
}

func TestNewInvalidHeaderEncoding(t *testing.T) {
	cfg := CreateConfig()
	cfg.ForwardHeaderEncoding = "base64"
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	if _, err := New(context.Background(), next, cfg, "test"); err == nil {
		t.Fatal("expected error for invalid forwardHeaderEncoding")
	}
}

func TestServeAuthenticatedEncodesHeaders(t *testing.T) {
	cfg := forwardConfig()
	cfg.ForwardExtraLdapHeaders = true
	cfg.ForwardHeaderEncoding = HeaderEncodingRFC2047
	la, received := newTestHandler(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	session := sessions.NewSession(store, la.config.CacheCookieName)
	session.Values["username"] = "user1"
	session.Values["ldap-dn"] = "CN=Matěj Lukáč,OU=Users,DC=example,DC=local"
	session.Values["ldap-cn"] = "Matěj Lukáč"
	session.Values["ldap-email"] = "user1@example.local"
	session.Values["ldap-firstname"] = "Matěj"
	session.Values["ldap-lastname"] = "Lukáč"
	session.Values["ldap-groups"] = "Správci|Technici"

	ServeAuthenicated(la, session, httptest.NewRecorder(), req)

	wd := new(mime.WordDecoder)
	want := map[string]string{
		"X-Remote-User":          "user1",
		"Remote-User-Email":      "user1@example.local",
		"Remote-User-First-Name": "Matěj",
		"Remote-User-Last-Name":  "Lukáč",
		"Ldap-Extra-Attr-CN":     "Matěj Lukáč",
		"Ldap-Extra-Attr-DN":     "CN=Matěj Lukáč,OU=Users,DC=example,DC=local",
	}
	for h, v := range want {
		raw := received.Get(h)
		if vals, ok := (*received)[h]; ok && len(vals) > 0 {
			raw = vals[0] // Ldap-Extra-Attr-* are set with non-canonical keys by the plugin
		}
		if !isASCII(raw) {
			t.Errorf("%s: not ASCII on the wire: %q", h, raw)
		}
		dec, err := wd.DecodeHeader(raw)
		if err != nil || dec != v {
			t.Errorf("%s: decoded %q (raw %q, err %v), want %q", h, dec, raw, err, v)
		}
	}

	groups := strings.Split(received.Get("Remote-User-Group"), "|")
	if len(groups) != 2 || groups[1] != "Technici" {
		t.Fatalf("groups: %q", groups)
	}
	if dec, _ := wd.DecodeHeader(groups[0]); dec != "Správci" {
		t.Fatalf("group decoded %q", dec)
	}
}

func TestIsASCII(t *testing.T) {
	if !isASCII("abc-123_ |=?") || isASCII("č") || !isASCII("") {
		t.Fatal("isASCII")
	}
}
