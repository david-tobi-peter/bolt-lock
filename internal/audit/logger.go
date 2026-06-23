package audit

import (
	"errors"
	"fmt"
	"time"

	"go.etcd.io/bbolt"
)

var (
	BucketName        = []byte("audit_log_chain")
	ErrUninitialized  = errors.New("audit log initialization failed: target bucket does not exist")
	ErrWriteViolation = errors.New("audit log invariant violation: existing entries are immutable")
	ErrInvalidBucket  = errors.New("audit log store failed: target bucket uninitialized")
)

type AuditLogger struct {
	db *bbolt.DB
}

func NewAuditLogger(db *bbolt.DB) (*AuditLogger, error) {
	err := db.View(func(tx *bbolt.Tx) error {
		if bucket := tx.Bucket(BucketName); bucket == nil {
			return ErrUninitialized
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return &AuditLogger{db: db}, nil
}

func (auditLogger *AuditLogger) WriteAppendOnly(logEntry *LogEntry) error {
	keyString := fmt.Sprintf("%s-%s", logEntry.Timestamp.Format(time.RFC3339Nano), logEntry.EntryID)
	key := []byte(keyString)

	return auditLogger.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(BucketName)
		if bucket == nil {
			return ErrInvalidBucket
		}

		if existing := bucket.Get(key); existing != nil {
			return ErrWriteViolation
		}

		value, err := logEntry.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal log entry: %w", err)
		}

		if err := bucket.Put(key, value); err != nil {
			return fmt.Errorf("failed to write log entry: %w", err)
		}

		return nil
	})
}
