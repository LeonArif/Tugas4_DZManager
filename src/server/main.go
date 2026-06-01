package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"tugas4_dzmanager/internal/api"
	"tugas4_dzmanager/internal/storage"
)

func main() {
	dbPath := flag.String("db", "data/vaults.db", "path to sqlite db file")
	addr := flag.String("addr", ":8080", "http listen address")
	flag.Parse()

	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o755); err != nil {
		log.Fatalf("create db dir: %v", err)
	}

	store, err := storage.NewServerStore(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	srv := api.NewServer(store)
	mux := srv.Router()

	fmt.Printf("Server listening on %s\n", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
