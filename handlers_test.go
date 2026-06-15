package main

import (
	"bytes"
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

func newTestServer(t *testing.T) (*Server, *Store) {
	t.Helper()
	st := NewStore()
	st.Seed()
	return NewServer(st), st
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

func TestHealth_SetsJSONContentType(t *testing.T) {
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
	srv, st := newTestServer(t)
	rec := doJSON(t, srv, http.MethodPost, "/register", credentials{
		Username: "carol", Password: "s3cret",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (%s)", rec.Code, rec.Body)
	}
	if _, err := st.Authenticate("carol", "s3cret"); err != nil {
		t.Fatalf("user not persisted: %v", err)
	}
}

func TestRegister_StoresMD5HashedPassword(t *testing.T) {
	srv, st := newTestServer(t)
	doJSON(t, srv, http.MethodPost, "/register", credentials{Username: "dave", Password: "hello"})
	u, err := st.Authenticate("dave", "hello")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if u.Password != weakHash("hello") {
		t.Fatalf("unexpected hash %q", u.Password)
	}
}

func TestRegister_RejectsMissingFields(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodPost, "/register", credentials{})
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
	if body["token"] == "" || body["role"] != "admin" {
		t.Fatalf("unexpected body %v", body)
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

func TestLogin_UnknownUserRejected(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodPost, "/login", credentials{
		Username: "ghost", Password: "x",
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
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
	var u User
	_ = json.Unmarshal(rec.Body.Bytes(), &u)
	if u.Username != "admin" {
		t.Fatalf("unexpected user %+v", u)
	}
}

func TestGetUser_UnknownIDReturns404(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/users/9999", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestGetUser_NonIntegerIDRejected(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/users/abc", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
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
	rec := doJSON(t, srv, http.MethodPost, "/notes", Note{UserID: 1, Title: "first", Body: "hello"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("want 201, got %d (%s)", rec.Code, rec.Body)
	}
	rec = doJSON(t, srv, http.MethodGet, "/notes", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list want 200, got %d", rec.Code)
	}
	var notes []Note
	_ = json.Unmarshal(rec.Body.Bytes(), &notes)
	if len(notes) != 1 || notes[0].Title != "first" {
		t.Fatalf("unexpected list: %v", notes)
	}
}

func TestNotes_SearchFiltersByTitle(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, title := range []string{"apple pie", "banana bread", "apple sauce"} {
		doJSON(t, srv, http.MethodPost, "/notes", Note{UserID: 1, Title: title, Body: "x"})
	}
	rec := doJSON(t, srv, http.MethodGet, "/notes?q=apple", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var notes []Note
	_ = json.Unmarshal(rec.Body.Bytes(), &notes)
	if len(notes) != 2 {
		t.Fatalf("expected 2 apple notes, got %d", len(notes))
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
// Notes regex search (ReDoS surface)
// ---------------------------------------------------------------------------

func TestNotesSearch_RegexMatches(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, title := range []string{"alpha", "beta", "gamma"} {
		doJSON(t, srv, http.MethodPost, "/notes", Note{UserID: 1, Title: title, Body: "x"})
	}
	rec := doJSON(t, srv, http.MethodGet, "/notes/search?pattern=^a", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var notes []Note
	_ = json.Unmarshal(rec.Body.Bytes(), &notes)
	if len(notes) != 1 || notes[0].Title != "alpha" {
		t.Fatalf("unexpected notes: %v", notes)
	}
}

func TestNotesSearch_RejectsInvalidRegex(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/notes/search?pattern=%5B", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestNotesSearch_RequiresPattern(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/notes/search", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// Files (path traversal)
// ---------------------------------------------------------------------------

func TestFiles_ServesAllowedFile(t *testing.T) {
	_ = os.MkdirAll("/tmp/files", 0o755)
	path := filepath.Join("/tmp/files", "ok.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Skipf("cannot write to /tmp/files: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })

	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/files?path=ok.txt", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rec.Code, rec.Body)
	}
	if rec.Body.String() != "hello" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestFiles_RequiresPath(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/files", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// Demonstrates path traversal — `../` escapes the /tmp/files root.
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
	if rec.Body.String() != "topsecret" {
		t.Fatalf("body = %q", rec.Body.String())
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

// Demonstrates SSRF: no allowlist, server fetches arbitrary URL — simulated
// here by a local httptest server standing in for an internal endpoint.
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
	if !strings.HasPrefix(rec.Header().Get("Location"), "https://evil.example") {
		t.Fatalf("open redirect blocked unexpectedly; location=%q", rec.Header().Get("Location"))
	}
}

// ---------------------------------------------------------------------------
// Admin (broken access control)
// ---------------------------------------------------------------------------

func TestAdminUsers_AccessibleWithoutAuth(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/admin/users", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var users []User
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
// CSRF token (insecure random)
// ---------------------------------------------------------------------------

func TestCSRFToken_ReturnsToken(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv, http.MethodGet, "/csrf", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body["token"]) != 16 {
		t.Fatalf("expected 16-char token, got %q", body["token"])
	}
}

// Demonstrates insecure random: the seed is constant, so the token sequence
// is deterministic and recoverable by an attacker.
func TestCSRFToken_IsPredictable(t *testing.T) {
	srv, _ := newTestServer(t)
	// Reset the RNG to the documented seed so the first emitted token
	// matches a known precomputed value.
	insecureRNG.Seed(1)
	rec := doJSON(t, srv, http.MethodGet, "/csrf", nil)
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["token"] == "" {
		t.Fatal("missing token")
	}
	insecureRNG.Seed(1)
	rec = doJSON(t, srv, http.MethodGet, "/csrf", nil)
	var body2 map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body2)
	if body["token"] != body2["token"] {
		t.Fatalf("tokens should be reproducible: %q vs %q", body["token"], body2["token"])
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
// Store
// ---------------------------------------------------------------------------

func TestStore_SeedsExpectedUsers(t *testing.T) {
	st := NewStore()
	st.Seed()
	if got := len(st.ListUsers()); got != 3 {
		t.Fatalf("expected 3 seeded users, got %d", got)
	}
}

func TestStore_DuplicateCreateReturnsErr(t *testing.T) {
	st := NewStore()
	if _, err := st.CreateUser("x", "p", "user"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser("x", "p", "user"); err == nil {
		t.Fatal("expected duplicate error")
	}
}

func TestStore_SearchNotesEmptyQueryReturnsAll(t *testing.T) {
	st := NewStore()
	st.CreateNote(1, "a", "x")
	st.CreateNote(1, "b", "x")
	if got := len(st.SearchNotes("")); got != 2 {
		t.Fatalf("expected 2 notes, got %d", got)
	}
}
