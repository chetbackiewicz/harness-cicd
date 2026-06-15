package main

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

const schemaSQL = `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL
);
`

func InitDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func SeedDB(db *sql.DB) error {
	rows := []struct {
		u, p, r string
	}{
		{"admin", weakHash("admin123"), "admin"},
		{"alice", weakHash("password"), "user"},
		{"bob", weakHash("hunter2"), "user"},
	}
	for _, r := range rows {
		if _, err := db.Exec(
			`INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)`,
			r.u, r.p, r.r,
		); err != nil {
			return err
		}
	}
	return nil
}
