package main

import (
	"log"
	"net/http"
	"time"

	"github.com/david-tobi-peter/bolt-lock/internal/api"
	"github.com/david-tobi-peter/bolt-lock/internal/audit"
	"github.com/david-tobi-peter/bolt-lock/internal/config"
	"github.com/david-tobi-peter/bolt-lock/internal/database"
)

func main() {
	db, err := database.NewDB(config.DefaultDBPath)
	if err != nil {
		log.Fatalf("Database initialization error: %v", err)
	}
	defer db.Close()

	if err := database.BootstrapDB(db); err != nil {
		log.Fatalf("Database bootstrap error: %v", err)
	}

	logger, err := audit.NewAuditLogger(db)
	if err != nil {
		log.Fatalf("Audit logger initialization error: %v", err)
	}

	dummySensitiveData := []byte(`{"action_details": "Initial boot checkpoint token generated", "result_status": "success"}`)

	encryptedPayload, err := audit.EncryptPayload(dummySensitiveData, logger.Keys.LogDEK)
	if err != nil {
		log.Fatalf("Failed to execute data encryption phase: %v", err)
	}

	entry, err := logger.WriteAppendOnly(
		"root",
		"boot",
		"sys/init",
		encryptedPayload,
	)
	if err != nil {
		log.Fatalf("Failed to commit entry to ledger: %v", err)
	}

	log.Printf("Log row successfully written to bbolt with hash: %s", entry.Hash)

	handler := api.NewAuditHandler(logger)

	mux := http.NewServeMux()
	mux.HandleFunc("/audit", handler.QueryEntries)
	mux.HandleFunc("/audit/verify", handler.VerifyCurrentBlock)

	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Printf("bolt-lock server listening on :8080")

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server HTTP Runtime Error: %v", err)
	}
}
