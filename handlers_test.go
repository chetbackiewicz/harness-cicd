package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestServer(t *testing.T) (*Server, *sql.DB) {
	t.Helper()
	db, err := InitDB(":memory:")
	if err != nil {
		t.Fatalf("init db: %v", err)
	}
	if err := SeedDB(db); err != nil {
		t.Fatalf("seed db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewServer(db), db
}

func doJSON(t *testing.T, srv http.Handler, method, target string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, target, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func TestHealth_ReturnsOK(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/health", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["status"] != "ok" {
		t.Fatalf("unexpected body %v", body)
	}
}

func TestHealth_RejectsNothingButReturnsJSONContentType(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/health", nil)
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("content-type = %q", got)
	}
}

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

func TestRegister_CreatesUser(t *testing.T) {
	srv, db := newTestServer(t)
	rec := doJSON(t, srv, http.MethodPost, "/register", credentials{
		Username: "carol", Password: "s3cret",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (%s)", rec.Code, rec.Body)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE username = 'carol'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected user persisted, count=%d", n)
	}
}

func TestRegister_StoresMD5HashedPassword(t *testing.T) {
	srv, db := newTestServer(t)
	doJSON(t, srv, http.MethodPost, "/register", credentials{Username: "dave", Password: "hello"})
	var stored string
	if err := db.QueryRow(`SELECT password FROM users WHERE username = 'dave'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != weakHash("hello") {
		t.Fatalf("unexpected hash %q", stored)
	}
}

func TestRegister_RejectsMissingFields(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodPost, "/register", credentials{Username: "", Password: ""})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestRegister_RejectsDuplicateUsername(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodPost, "/register", credentials{Username: "admin", Password: "x"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestRegister_RejectsNonPOST(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/register", nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

func TestLogin_ValidCredentialsIssuesToken(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodPost, "/login", credentials{
		Username: "admin", Password: "admin123",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["token"] == "" {
		t.Fatalf("expected token, got %v", body)
	}
	if body["role"] != "admin" {
		t.Fatalf("expected admin role, got %q", body["role"])
	}
}

func TestLogin_InvalidPasswordRejected(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodPost, "/login", credentials{
		Username: "admin", Password: "wrong",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

// Demonstrates the SQL injection vulnerability in handleLogin.
// The payload ' OR '1'='1 closes the username string and short-circuits
// authentication regardless of password.
func TestLogin_SQLInjectionBypassesAuth(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodPost, "/login", credentials{
		Username: "admin' OR '1'='1' --",
		Password: "anything",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("SQLi should have succeeded; got %d (%s)", rec.Code, rec.Body)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["token"] == "" {
		t.Fatalf("expected token from SQLi bypass")
	}
}

func TestLogin_RejectsMalformedJSON(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestLogin_RejectsNonPOST(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/login", nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Get user
// ---------------------------------------------------------------------------

func TestGetUser_ReturnsRecord(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/users/1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var body map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["username"] != "admin" {
		t.Fatalf("unexpected body %v", body)
	}
}

func TestGetUser_UnknownIDReturns404(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/users/9999", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

// Demonstrates SQLi on /users/{id}.
// A UNION select returns attacker-chosen rows from the same query.
func TestGetUser_SQLInjectionReturnsCraftedRow(t *testing.T) {
	srv, _ := newTestServer(t)
	// "0 UNION SELECT 42, 'pwned', 'admin'" — URL-encoded to keep spaces/quotes
	// from confusing http.NewRequest's path parser.
	payload := "0%20UNION%20SELECT%2042,%20%27pwned%27,%20%27admin%27"
	rec := doJSON(t, srv, http.MethodGet, "/users/"+payload, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 from SQLi, got %d (%s)", rec.Code, rec.Body)
	}
	var body map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["username"] != "pwned" {
		t.Fatalf("expected injected row, got %v", body)
	}
}

func TestGetUser_MissingIDReturns400(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/users/", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Notes
// ---------------------------------------------------------------------------

func TestNotes_CreateAndList(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodPost, "/notes", note{
		UserID: 1, Title: "first", Body: "hello world",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (%s)", rec.Code, rec.Body)
	}
	rec = doJSON(t, srv, http.MethodGet, "/notes", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list want 200, got %d", rec.Code)
	}
	var notes []note
	_ = json.Unmarshal(rec.Body.Bytes(), &notes)
	if len(notes) != 1 || notes[0].Title != "first" {
		t.Fatalf("unexpected list: %v", notes)
	}
}

func TestNotes_SearchFiltersByTitle(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, title := range []string{"apple pie", "banana bread", "apple sauce"} {
		doJSON(t, srv, http.MethodPost, "/notes", note{UserID: 1, Title: title, Body: "x"})
	}
	rec := doJSON(t, srv, http.MethodGet, "/notes?q=apple", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var notes []note
	_ = json.Unmarshal(rec.Body.Bytes(), &notes)
	if len(notes) != 2 {
		t.Fatalf("expected 2 apple notes, got %d", len(notes))
	}
}

// Demonstrates SQLi via the search query parameter.
func TestNotes_SearchSQLInjectionLeaksAll(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, title := range []string{"a", "b", "c"} {
		doJSON(t, srv, http.MethodPost, "/notes", note{UserID: 1, Title: title, Body: "x"})
	}
	// "zzz%' OR 1=1 --" terminates the LIKE pattern and comments out the rest.
	rec := doJSON(t, srv, http.MethodGet, "/notes?q=zzz%25%27+OR+1%3D1+--+", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body)
	}
	var notes []note
	_ = json.Unmarshal(rec.Body.Bytes(), &notes)
	if len(notes) != 3 {
		t.Fatalf("expected SQLi to leak all 3 notes, got %d", len(notes))
	}
}

func TestNotes_RejectsUnsupportedMethod(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodDelete, "/notes", nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Files (path traversal)
// ---------------------------------------------------------------------------

func TestFiles_ServesAllowedFile(t *testing.T) {
	dir := t.TempDir()
	// Override the /tmp/files root by symlinking the temp dir; instead we
	// place a file at the expected location for this test.
	_ = os.MkdirAll("/tmp/files", 0o755)
	path := filepath.Join("/tmp/files", "ok.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Skipf("cannot write to /tmp/files: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	_ = dir

	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/files?path=ok.txt", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body)
	}
	if got := rec.Body.String(); got != "hello" {
		t.Fatalf("body = %q", got)
	}
}

func TestFiles_RequiresPath(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/files", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// Demonstrates path traversal — ../../etc/passwd escapes the /tmp/files root.
func TestFiles_PathTraversalEscapesRoot(t *testing.T) {
	target := "/tmp/files-secret.txt"
	if err := os.WriteFile(target, []byte("topsecret"), 0o644); err != nil {
		t.Skipf("cannot write target: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(target) })

	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/files?path=../files-secret.txt", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("traversal should have succeeded; got %d (%s)", rec.Code, rec.Body)
	}
	if got := rec.Body.String(); got != "topsecret" {
		t.Fatalf("body = %q", got)
	}
}

// ---------------------------------------------------------------------------
// Exec (command injection)
// ---------------------------------------------------------------------------

func TestExec_RunsSimpleCommand(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/exec?cmd=echo+hello", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if !strings.Contains(body["output"], "hello") {
		t.Fatalf("unexpected output %q", body["output"])
	}
}

// Demonstrates command injection: a chained command runs in the same shell.
func TestExec_CommandInjectionChainsExtraCommand(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/exec?cmd=echo+safe%3B+echo+pwned", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if !strings.Contains(body["output"], "pwned") {
		t.Fatalf("injection did not run; output=%q", body["output"])
	}
}

func TestExec_RequiresCmd(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/exec", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Fetch (SSRF)
// ---------------------------------------------------------------------------

func TestFetch_ProxiesUpstreamResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "from-upstream")
	}))
	t.Cleanup(upstream.Close)

	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/fetch?url="+upstream.URL, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if rec.Body.String() != "from-upstream" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestFetch_RequiresURL(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/fetch", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// Demonstrates SSRF: there is no allowlist, so the server happily fetches
// any URL the caller supplies — including an internal "metadata" endpoint
// simulated here by a local httptest server.
func TestFetch_SSRFReachesInternalEndpoint(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "internal-secret")
	}))
	t.Cleanup(internal.Close)

	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/fetch?url="+internal.URL, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "internal-secret") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Render (reflected XSS)
// ---------------------------------------------------------------------------

func TestRender_EchoesMessage(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/render?msg=hello", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "hello") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

// Demonstrates reflected XSS: the script tag is written into the HTML body
// without escaping.
func TestRender_ReflectsScriptTagUnescaped(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/render?msg=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<script>alert(1)</script>") {
		t.Fatalf("XSS payload was sanitized; body=%q", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Redirect (open redirect)
// ---------------------------------------------------------------------------

func TestRedirect_RedirectsToTarget(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/redirect?to=https://example.com/safe", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("want 302, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://example.com/safe" {
		t.Fatalf("location = %q", got)
	}
}

func TestRedirect_OpenRedirectToExternalDomain(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/redirect?to=https://evil.example/phish", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("want 302, got %d", rec.Code)
	}
	if !strings.HasPrefix(rec.Header().Get("Location"), "https://evil.example") {
		t.Fatalf("open redirect blocked unexpectedly; location=%q", rec.Header().Get("Location"))
	}
}

// ---------------------------------------------------------------------------
// Admin (broken access control)
// ---------------------------------------------------------------------------

// Demonstrates broken access control: /admin/users requires no authentication.
func TestAdminUsers_AccessibleWithoutAuth(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/admin/users", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body)
	}
	var users []map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &users)
	if len(users) < 3 {
		t.Fatalf("expected seeded users, got %d", len(users))
	}
}

// ---------------------------------------------------------------------------
// Config (YAML deserialization)
// ---------------------------------------------------------------------------

func TestConfig_ParsesYAML(t *testing.T) {
	srv, _ := newTestServer(t)
	body := []byte("log_level: debug\nfeature_flags:\n  beta: true\n")
	req := httptest.NewRequest(http.MethodPost, "/config", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "debug") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestConfig_RejectsMalformedYAML(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(":\n:\n\t- bad"))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestConfig_RejectsNonPOST(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/config", nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

func TestWeakHash_DeterministicMD5(t *testing.T) {
	if weakHash("hello") != "5d41402abc4b2a76b9719d911017c592" {
		t.Fatalf("weakHash mismatch: %s", weakHash("hello"))
	}
}

func TestIssueAndParseToken_RoundTrip(t *testing.T) {
	tok, err := issueToken("admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := parseToken(tok)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if claims["sub"] != "admin" || claims["role"] != "admin" {
		t.Fatalf("unexpected claims: %v", claims)
	}
}

func TestParseToken_RejectsGarbage(t *testing.T) {
	if _, err := parseToken("not-a-token"); err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// DB
// ---------------------------------------------------------------------------

func TestInitDB_CreatesSchema(t *testing.T) {
	db, err := InitDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('users','notes')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected 2 tables, got %d", n)
	}
}

func TestSeedDB_InsertsExpectedUsers(t *testing.T) {
	db, err := InitDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := SeedDB(db); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("expected 3 seeded users, got %d", n)
	}
}

func TestSeedDB_IsIdempotent(t *testing.T) {
	db, err := InitDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := SeedDB(db); err != nil {
		t.Fatal(err)
	}
	if err := SeedDB(db); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("expected idempotent seed (3 users), got %d", n)
	}
}
