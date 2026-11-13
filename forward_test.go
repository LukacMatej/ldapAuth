// nolint
package ldapAuth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/gorilla/sessions"
)

func TestGroupNamesFromDNs(t *testing.T) {
	dns := []string{
		"CN=NetBox_Admin,OU=Groups,DC=example,DC=local",
		"CN=Domain Users,CN=Users,DC=example,DC=local",
		`CN=NetBox_Ops\, Team,OU=Groups,DC=example,DC=local`, // escaped comma inside CN
		"CN=NetBox_Admin,OU=Other,DC=example,DC=local",       // duplicate name
		"CN=Alpha,OU=Groups,DC=example,DC=local",
	}

	got := GroupNamesFromDNs(dns, nil)
	want := []string{"Alpha", "Domain Users", "NetBox_Admin", "NetBox_Ops, Team"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("no filter: got %q, want %q", got, want)
	}

	got = GroupNamesFromDNs(dns, regexp.MustCompile("^NetBox_"))
	want = []string{"NetBox_Admin", "NetBox_Ops, Team"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filter: got %q, want %q", got, want)
	}

	got = GroupNamesFromDNs(nil, nil)
	if len(got) != 0 {
		t.Fatalf("empty input: got %q", got)
	}
}

func TestUserInfoAttributes(t *testing.T) {
	cfg := CreateConfig()
	if got := userInfoAttributes(cfg); !reflect.DeepEqual(got, []string{"dn", "cn"}) {
		t.Fatalf("defaults: got %q", got)
	}

	cfg.ForwardUserInfo = true
	cfg.ForwardGroups = true
	want := []string{"dn", "cn", "mail", "givenName", "sn", "memberOf"}
	if got := userInfoAttributes(cfg); !reflect.DeepEqual(got, want) {
		t.Fatalf("user info + groups: got %q, want %q", got, want)
	}

	// nested groups are searched separately, memberOf is not needed
	cfg.ForwardGroupsNested = true
	want = []string{"dn", "cn", "mail", "givenName", "sn"}
	if got := userInfoAttributes(cfg); !reflect.DeepEqual(got, want) {
		t.Fatalf("nested: got %q, want %q", got, want)
	}
}

func TestLdapGetUserGroupsMemberOf(t *testing.T) {
	cfg := CreateConfig()
	cfg.ForwardGroups = true

	entry := ldap.NewEntry("CN=user1,OU=Users,DC=example,DC=local", map[string][]string{
		"memberOf": {
			"CN=NetBox_Users,OU=Groups,DC=example,DC=local",
			"CN=VPN,OU=Groups,DC=example,DC=local",
		},
	})

	// memberOf mode does not touch the connection
	got, err := LdapGetUserGroups(nil, cfg, entry, regexp.MustCompile("^NetBox_"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"NetBox_Users"}) {
		t.Fatalf("got %q", got)
	}
}

func TestNewInvalidGroupsFilter(t *testing.T) {
	cfg := CreateConfig()
	cfg.ForwardGroups = true
	cfg.ForwardGroupsFilter = "([invalid"

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	if _, err := New(context.Background(), next, cfg, "test"); err == nil {
		t.Fatal("expected error for invalid forwardGroupsFilter")
	}
}

// newTestHandler builds the middleware and returns it with the headers the backend received.
func newTestHandler(t *testing.T, cfg *Config) (*LdapAuth, *http.Header) {
	t.Helper()
	received := &http.Header{}
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		*received = req.Header.Clone()
	})
	h, err := New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatal(err)
	}
	return h.(*LdapAuth), received
}

func forwardConfig() *Config {
	cfg := CreateConfig()
	cfg.SearchFilter = "(&(objectClass=user)(sAMAccountName={{.Username}}))"
	cfg.ForwardUsernameHeader = "X-Remote-User"
	cfg.ForwardUserInfo = true
	cfg.ForwardGroups = true
	cfg.CacheKey = "0123456789abcdef0123456789abcdef"
	return cfg
}

func TestServeAuthenticatedForwardsHeaders(t *testing.T) {
	la, received := newTestHandler(t, forwardConfig())

	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	session := sessions.NewSession(store, la.config.CacheCookieName)
	session.Values["username"] = "user1"
	session.Values["ldap-dn"] = "CN=User One,OU=Users,DC=example,DC=local"
	session.Values["ldap-cn"] = "User One"
	session.Values["ldap-email"] = "user1@example.local"
	session.Values["ldap-firstname"] = "User"
	session.Values["ldap-lastname"] = "One"
	session.Values["ldap-groups"] = "NetBox_Admin|NetBox_Users"

	ServeAuthenicated(la, session, httptest.NewRecorder(), req)

	want := map[string]string{
		"X-Remote-User":          "user1",
		"Remote-User-Email":      "user1@example.local",
		"Remote-User-First-Name": "User",
		"Remote-User-Last-Name":  "One",
		"Remote-User-Group":      "NetBox_Admin|NetBox_Users",
	}
	for h, v := range want {
		if got := received.Get(h); got != v {
			t.Errorf("%s: got %q, want %q", h, got, v)
		}
	}
}

func TestServeAuthenticatedOldSessionWithoutNewKeys(t *testing.T) {
	// A cookie issued by an older plugin version has no ldap-email/ldap-groups keys: must not panic.
	la, received := newTestHandler(t, forwardConfig())

	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	session := sessions.NewSession(store, la.config.CacheCookieName)
	session.Values["username"] = "user1"

	ServeAuthenicated(la, session, httptest.NewRecorder(), req)

	if received.Get("X-Remote-User") != "user1" {
		t.Fatalf("username not forwarded")
	}
	for _, h := range []string{"Remote-User-Email", "Remote-User-Group"} {
		if _, ok := (*received)[h]; ok {
			t.Errorf("%s should not be set", h)
		}
	}
}

func TestSpoofedHeadersAreStripped(t *testing.T) {
	// Valid cached session + client-supplied identity headers: backend must only see the values from LDAP.
	la, received := newTestHandler(t, forwardConfig())

	// Issue a session cookie for user1 with no groups/email.
	rec := httptest.NewRecorder()
	issue := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	session, _ := store.Get(issue, la.config.CacheCookieName)
	session.Values["username"] = "user1"
	session.Values["authenticated"] = true
	if err := session.Save(issue, rec); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	req.SetBasicAuth("user1", "irrelevant-session-is-cached")
	req.Header.Set("X-Remote-User", "admin")
	req.Header.Set("Remote-User-Email", "evil@example.local")
	req.Header.Set("Remote-User-Group", "NetBox_Admin")
	req.Header.Set("Ldap-Extra-Attr-CN", "Admin")

	la.ServeHTTP(httptest.NewRecorder(), req)

	if got := received.Get("X-Remote-User"); got != "user1" {
		t.Fatalf("X-Remote-User: got %q, want user1", got)
	}
	for _, h := range []string{"Remote-User-Email", "Remote-User-Group", "Ldap-Extra-Attr-CN"} {
		if v := received.Get(h); v != "" {
			t.Errorf("%s spoofed value passed to backend: %q", h, v)
		}
	}
}

func TestForwardedHeadersDisabledByDefault(t *testing.T) {
	cfg := CreateConfig()
	got := forwardedHeaders(cfg)
	if !reflect.DeepEqual(got, []string{"Ldap-Extra-Attr-DN", "Ldap-Extra-Attr-CN", "Username"}) {
		t.Fatalf("defaults: got %q", got)
	}
}
