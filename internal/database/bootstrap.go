package database

import (
	"fmt"
	"time"

	"go.etcd.io/bbolt"
)

var AuditBucketName = []byte("audit_log_chain")

func NewDB(path string) (*bbolt.DB, error) {
	db, err := bbolt.Open(path, 0600, &bbolt.Options{
		Timeout: 3 * time.Second,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to open bbolt instance: %w", err)
	}

	return db, nil
}

func BootstrapDB(db *bbolt.DB) error {
	return db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(AuditBucketName); err != nil {
			return fmt.Errorf("failed to create bucket: %w", err)
		}
		return nil
	})
}
