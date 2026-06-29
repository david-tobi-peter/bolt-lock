package audit

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/david-tobi-peter/bolt-lock/internal/config"
	"go.etcd.io/bbolt"
)

type ConfiguredKeys struct {
	HMACKey []byte
	LogDEK  []byte
}

type AuditLogger struct {
	db   *bbolt.DB
	Keys ConfiguredKeys
}

func NewAuditLogger(db *bbolt.DB) (*AuditLogger, error) {
	err := db.View(func(tx *bbolt.Tx) error {
		if bucket := tx.Bucket(config.AuditBucketName); bucket == nil {
			return config.ErrBucketUninitialized
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	if config.AuditHMACKeyStr == "" || config.AuditDEKKeyStr == "" {
		return nil, fmt.Errorf("audit HMAC and DEK keys must be set")
	}

	hmacKey, err := hex.DecodeString(config.AuditHMACKeyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode HMAC key: %w", err)
	}

	dekKey, err := hex.DecodeString(config.AuditDEKKeyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode DEK key: %w", err)
	}

	return &AuditLogger{
		db: db,
		Keys: ConfiguredKeys{
			HMACKey: hmacKey,
			LogDEK:  dekKey,
		},
	}, nil
}

func (al *AuditLogger) WriteAppendOnly(actor, operation, path, encryptedPayload string) (*LogEntry, error) {
	var finalizedEntry *LogEntry

	err := al.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(config.AuditBucketName)
		if bucket == nil {
			return config.ErrBucketUninitialized
		}

		cursor := bucket.Cursor()
		lastKey, lastValue := cursor.Last()

		var previousHash string = ""
		var nextSequence uint64 = 1

		if lastKey != nil && lastValue != nil {
			lastEntry, err := UnmarshalLogEntry(lastValue)
			if err != nil {
				return fmt.Errorf("failed to parse previous block tail link: %w", err)
			}

			previousHash = lastEntry.Hash

			if len(lastKey) == 8 {
				nextSequence = binary.BigEndian.Uint64(lastKey) + 1
			}
		}

		now := time.Now().UTC()
		le := &LogEntry{
			EntryID:          fmt.Sprintf("log_%d_%s", now.UnixNano(), actor),
			Timestamp:        now,
			Actor:            actor,
			Operation:        operation,
			Path:             path,
			PreviousHash:     previousHash,
			EncryptedPayload: encryptedPayload,
		}

		le.Hash = le.ComputeHMAC(al.Keys.HMACKey)

		storageKey := make([]byte, 8)
		binary.BigEndian.PutUint64(storageKey, nextSequence)

		value, err := le.MarshalLogEntry()
		if err != nil {
			return fmt.Errorf("failed to marshal log entry: %w", err)
		}

		if err := bucket.Put(storageKey, value); err != nil {
			return fmt.Errorf("failed to write log entry: %w", err)
		}

		finalizedEntry = le
		return nil
	})

	if err != nil {
		return nil, err
	}

	return finalizedEntry, nil
}

func (al *AuditLogger) VerifyCurrentBlock() error {
	return al.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(config.AuditBucketName)
		if bucket == nil {
			return config.ErrBucketUninitialized
		}

		cursor := bucket.Cursor()
		var expectedPreviousHash string = ""
		var recordCount int

		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			recordCount++

			entry, err := UnmarshalLogEntry(v)
			if err != nil {
				return fmt.Errorf("scan canceled; unmarshal breakdown at key %s: %w", k, err)
			}

			if entry.PreviousHash != expectedPreviousHash {
				return fmt.Errorf("scan canceled; previous hash mismatch at key %s", k)
			}

			recalculatedHash := entry.ComputeHMAC(al.Keys.HMACKey)
			if entry.Hash != recalculatedHash {
				return fmt.Errorf("%w at record %s: cryptographic hash is invalid", config.ErrTamperDetected, entry.EntryID)
			}

			expectedPreviousHash = entry.Hash
		}

		fmt.Printf("Validation complete: %d records confirmed unmutated.\n", recordCount)
		return nil
	})
}
