package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

type Server struct {
	db  *sql.DB
	mux *http.ServeMux
}

func NewServer(db *sql.DB) *Server {
	s := &Server{db: db, mux: http.NewServeMux()}
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
	s.mux.HandleFunc("/files", s.handleFiles)
	s.mux.HandleFunc("/exec", s.handleExec)
	s.mux.HandleFunc("/fetch", s.handleFetch)
	s.mux.HandleFunc("/render", s.handleRender)
	s.mux.HandleFunc("/redirect", s.handleRedirect)
	s.mux.HandleFunc("/admin/users", s.handleAdminUsers)
	s.mux.HandleFunc("/config", s.handleConfig)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// VULN: verbose error messages leak internal information.
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
		writeErr(w, http.StatusBadRequest, fmt.Errorf("username and password required"))
		return
	}
	// VULN: weakHash uses MD5 with no salt.
	_, err := s.db.Exec(
		`INSERT INTO users (username, password, role) VALUES (?, ?, 'user')`,
		c.Username, weakHash(c.Password),
	)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"username": c.Username})
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
	// VULN: SQL injection via string concatenation in the WHERE clause.
	query := fmt.Sprintf(
		"SELECT id, username, role FROM users WHERE username = '%s' AND password = '%s'",
		c.Username, weakHash(c.Password),
	)
	row := s.db.QueryRow(query)
	var id int
	var username, role string
	if err := row.Scan(&id, &username, &role); err != nil {
		writeErr(w, http.StatusUnauthorized, fmt.Errorf("invalid credentials: %w", err))
		return
	}
	tok, err := issueToken(username, role)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": tok, "role": role})
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/users/")
	if id == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("missing id"))
		return
	}
	// VULN: SQL injection via path parameter concatenation.
	query := "SELECT id, username, role FROM users WHERE id = " + id
	row := s.db.QueryRow(query)
	var uid int
	var username, role string
	if err := row.Scan(&uid, &username, &role); err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id": uid, "username": username, "role": role,
	})
}

type note struct {
	ID     int    `json:"id"`
	UserID int    `json:"user_id"`
	Title  string `json:"title"`
	Body   string `json:"body"`
}

func (s *Server) handleNotes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// VULN: search parameter concatenated into LIKE clause (SQLi).
		q := r.URL.Query().Get("q")
		query := "SELECT id, user_id, title, body FROM notes"
		if q != "" {
			query += " WHERE title LIKE '%" + q + "%'"
		}
		rows, err := s.db.Query(query)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		defer rows.Close()
		notes := []note{}
		for rows.Next() {
			var n note
			if err := rows.Scan(&n.ID, &n.UserID, &n.Title, &n.Body); err != nil {
				writeErr(w, http.StatusInternalServerError, err)
				return
			}
			notes = append(notes, n)
		}
		writeJSON(w, http.StatusOK, notes)
	case http.MethodPost:
		var n note
		if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		res, err := s.db.Exec(
			`INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)`,
			n.UserID, n.Title, n.Body,
		)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		id, _ := res.LastInsertId()
		n.ID = int(id)
		writeJSON(w, http.StatusCreated, n)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("path")
	if name == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("path required"))
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
		writeErr(w, http.StatusBadRequest, fmt.Errorf("cmd required"))
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
		writeErr(w, http.StatusBadRequest, fmt.Errorf("url required"))
		return
	}
	// VULN: SSRF — server fetches an arbitrary URL supplied by the caller.
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
	// VULN: reflected XSS — user input written directly into an HTML response.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<html><body><h1>Message</h1><p>%s</p></body></html>", msg)
}

func (s *Server) handleRedirect(w http.ResponseWriter, r *http.Request) {
	to := r.URL.Query().Get("to")
	if to == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("to required"))
		return
	}
	// VULN: open redirect — caller controls full target URL with no allowlist.
	http.Redirect(w, r, to, http.StatusFound)
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	// VULN: broken access control — admin endpoint with no authentication check.
	rows, err := s.db.Query(`SELECT id, username, role FROM users ORDER BY id`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	defer rows.Close()
	type u struct {
		ID   int    `json:"id"`
		Name string `json:"username"`
		Role string `json:"role"`
	}
	users := []u{}
	for rows.Next() {
		var x u
		if err := rows.Scan(&x.ID, &x.Name, &x.Role); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		users = append(users, x)
	}
	writeJSON(w, http.StatusOK, users)
}

type appConfig struct {
	FeatureFlags map[string]bool `yaml:"feature_flags"`
	LogLevel     string          `yaml:"log_level"`
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
	// VULN: unmarshalling untrusted YAML with vulnerable yaml.v2 (CVE-2019-11254 et al).
	var cfg appConfig
	if err := yaml.Unmarshal(body, &cfg); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}
