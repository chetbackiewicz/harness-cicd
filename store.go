package main

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"`
	Role     string `json:"role"`
}

type Note struct {
	ID     int    `json:"id"`
	UserID int    `json:"user_id"`
	Title  string `json:"title"`
	Body   string `json:"body"`
}

var (
	ErrDuplicate = errors.New("duplicate")
	ErrNotFound  = errors.New("not found")
)

type Store struct {
	mu      sync.RWMutex
	db      *sql.DB
	users   map[int]*User
	byName  map[string]*User
	notes   map[int]*Note
	userSeq int
	noteSeq int
}

func NewStore() *Store {
	return &Store{
		users:  make(map[int]*User),
		byName: make(map[string]*User),
		notes:  make(map[int]*Note),
	}
}

func (s *Store) Seed() {
	_, _ = s.CreateUser("admin", "admin123", "admin")
	_, _ = s.CreateUser("alice", "password", "user")
	_, _ = s.CreateUser("bob", "hunter2", "user")
}

func (s *Store) CreateUser(username, password, role string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byName[username]; exists {
		return nil, ErrDuplicate
	}
	s.userSeq++
	u := &User{
		ID:       s.userSeq,
		Username: username,
		Password: weakHash(password),
		Role:     role,
	}
	s.users[u.ID] = u
	s.byName[username] = u
	return u, nil
}

func (s *Store) GetUser(id int) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok {
		return nil, ErrNotFound
	}
	return u, nil
}

func (s *Store) Authenticate(username, password string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.byName[username]
	if !ok || u.Password != weakHash(password) {
		return nil, ErrNotFound
	}
	return u, nil
}

func (s *Store) ListUsers() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*User, 0, len(s.users))
	for i := 1; i <= s.userSeq; i++ {
		if u, ok := s.users[i]; ok {
			out = append(out, u)
		}
	}
	return out
}

func (s *Store) CreateNote(userID int, title, body string) *Note {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.noteSeq++
	n := &Note{ID: s.noteSeq, UserID: userID, Title: title, Body: body}
	s.notes[n.ID] = n
	return n
}

func (s *Store) SearchNotes(q string) []*Note {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Note, 0, len(s.notes))
	for i := 1; i <= s.noteSeq; i++ {
		n, ok := s.notes[i]
		if !ok {
			continue
		}
		if q == "" || strings.Contains(n.Title, q) {
			out = append(out, n)
		}
	}
	return out
}

func (s *Store) NoteCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.notes)
}

// VULN: SQL injection — user input is concatenated directly into the query
// string with fmt.Sprintf instead of using a parameterized query. An attacker
// can pass `' OR '1'='1` (or worse) to alter the query. Use db.Query with
// placeholders ("... WHERE title = $1", title) instead.
func (s *Store) SearchNotesSQL(title string) ([]*Note, error) {
	query := fmt.Sprintf("SELECT id, user_id, title, body FROM notes WHERE title = '%s'", title)
	if s.db == nil {
		return nil, errors.New("database not configured")
	}
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*Note{}
	for rows.Next() {
		var n Note
		if err := rows.Scan(&n.ID, &n.UserID, &n.Title, &n.Body); err != nil {
			return nil, err
		}
		out = append(out, &n)
	}
	return out, rows.Err()
}
