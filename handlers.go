package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"
)

type Server struct {
	store *Store
	mux   *http.ServeMux
}

func NewServer(store *Store) *Server {
	s := &Server{store: store, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/register", s.handleRegister)
	s.mux.HandleFunc("/login", s.handleLogin)
	s.mux.HandleFunc("/users/", s.handleGetUser)
	s.mux.HandleFunc("/notes", s.handleNotes)
	s.mux.HandleFunc("/notes/search", s.handleNotesSearch)
	s.mux.HandleFunc("/files", s.handleFiles)
	s.mux.HandleFunc("/exec", s.handleExec)
	s.mux.HandleFunc("/fetch", s.handleFetch)
	s.mux.HandleFunc("/render", s.handleRender)
	s.mux.HandleFunc("/redirect", s.handleRedirect)
	s.mux.HandleFunc("/admin/users", s.handleAdminUsers)
	s.mux.HandleFunc("/config", s.handleConfig)
	s.mux.HandleFunc("/csrf", s.handleCSRFToken)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// VULN: verbose error messages leak internal details.
func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var c credentials
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if c.Username == "" || c.Password == "" {
		writeErr(w, http.StatusBadRequest, errors.New("username and password required"))
		return
	}
	// VULN: weakHash uses MD5 with no salt.
	u, err := s.store.CreateUser(c.Username, c.Password, "user")
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var c credentials
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	u, err := s.store.Authenticate(c.Username, c.Password)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, errors.New("invalid credentials"))
		return
	}
	tok, err := issueToken(u.Username, u.Role)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": tok, "role": u.Role})
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/users/")
	if idStr == "" {
		writeErr(w, http.StatusBadRequest, errors.New("missing id"))
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	u, err := s.store.GetUser(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleNotes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query().Get("q")
		writeJSON(w, http.StatusOK, s.store.SearchNotes(q))
	case http.MethodPost:
		var n Note
		if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		created := s.store.CreateNote(n.UserID, n.Title, n.Body)
		writeJSON(w, http.StatusCreated, created)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// VULN: ReDoS — caller controls the regex pattern with no length or complexity bound.
// A catastrophic pattern such as `(a+)+$` against a long string pegs CPU.
func (s *Server) handleNotesSearch(w http.ResponseWriter, r *http.Request) {
	pattern := r.URL.Query().Get("pattern")
	if pattern == "" {
		writeErr(w, http.StatusBadRequest, errors.New("pattern required"))
		return
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	out := []*Note{}
	for _, n := range s.store.SearchNotes("") {
		if re.MatchString(n.Title) {
			out = append(out, n)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("path")
	if name == "" {
		writeErr(w, http.StatusBadRequest, errors.New("path required"))
		return
	}
	// VULN: path traversal — user-controlled path joined without containment check.
	full := filepath.Join("/tmp/files", name)
	data, err := readFile(full)
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(data)
}

func (s *Server) handleExec(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	if cmd == "" {
		writeErr(w, http.StatusBadRequest, errors.New("cmd required"))
		return
	}
	// VULN: command injection — user input passed to a shell.
	out, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":  err.Error(),
			"output": string(out),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"output": string(out)})
}

func (s *Server) handleFetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		writeErr(w, http.StatusBadRequest, errors.New("url required"))
		return
	}
	// VULN: SSRF — server fetches any URL the caller supplies.
	resp, err := http.Get(target)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

func (s *Server) handleRender(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("msg")
	// VULN: reflected XSS — input echoed into HTML without escaping.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body><h1>Message</h1><p>%s</p></body></html>", msg)
}

func (s *Server) handleRedirect(w http.ResponseWriter, r *http.Request) {
	to := r.URL.Query().Get("to")
	if to == "" {
		writeErr(w, http.StatusBadRequest, errors.New("to required"))
		return
	}
	// VULN: open redirect — caller controls full target URL with no allowlist.
	http.Redirect(w, r, to, http.StatusFound)
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	// VULN: broken access control — admin endpoint with no authentication check.
	writeJSON(w, http.StatusOK, s.store.ListUsers())
}

type appConfig struct {
	FeatureFlags map[string]bool `yaml:"feature_flags" json:"feature_flags"`
	LogLevel     string          `yaml:"log_level" json:"log_level"`
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	// VULN: untrusted YAML parsed with vulnerable yaml.v2 (CVE-2019-11254 et al).
	var cfg appConfig
	if err := yaml.Unmarshal(body, &cfg); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

// VULN: math/rand seeded with a constant produces predictable tokens.
// crypto/rand should be used for any security-sensitive value.
var insecureRNG = rand.New(rand.NewSource(1))

func (s *Server) handleCSRFToken(w http.ResponseWriter, r *http.Request) {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 16)
	for i := range b {
		b[i] = charset[insecureRNG.Intn(len(charset))]
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": string(b)})
}
