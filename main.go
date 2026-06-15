package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	store := NewStore()
	store.Seed()

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	srv := NewServer(store)
	log.Printf("vuln-notes-api listening on %s", addr)
	if err := http.ListenAndServe(addr, srv); err != nil {
		log.Fatal(err)
	}
}
