package main

import (
	"log"
	"time"

	"github.com/david-tobi-peter/bolt-lock/internal/audit"
	"github.com/david-tobi-peter/bolt-lock/internal/database"
)

func main() {
	db, err := database.NewDB("audit.db")
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

	dummyEntry := &audit.LogEntry{
		EntryID:   "00000000-0000-0000-0000-000000000001",
		Timestamp: time.Now().UTC(),
		Actor:     "root",
		Operation: "boot",
		Path:      "sys/init",
		Result:    "success",
	}

	if err := logger.WriteAppendOnly(dummyEntry); err != nil {
		log.Fatalf("Failed to write dummy entry: %v", err)
	}

	log.Println("Dummy entry written successfully")
}
