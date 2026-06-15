package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		dsn = "file:vuln-notes.db?cache=shared&mode=rwc"
	}
	db, err := InitDB(dsn)
	if err != nil {
		log.Fatalf("init db: %v", err)
	}
	defer db.Close()
	if err := SeedDB(db); err != nil {
		log.Fatalf("seed db: %v", err)
	}

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	srv := NewServer(db)
	log.Printf("vuln-notes-api listening on %s", addr)
	if err := http.ListenAndServe(addr, srv); err != nil {
		log.Fatal(err)
	}
}
