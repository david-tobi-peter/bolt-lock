package main

import (
	"log"

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

	if err := logger.VerifyCurrentBlock(); err != nil {
		log.Fatalf("Failed to verify current block: %v", err)
	}

	log.Println("Ledger structural health verified successfully.")
}
