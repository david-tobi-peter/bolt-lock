package config

import (
	"errors"
	"os"
)

var (
	AuditBucketName = []byte("audit_log_chain")
	DefaultDBPath   = "audit.db"

	AuditHMACKeyStr = os.Getenv("AUDIT_HMAC_KEY")
	AuditDEKKeyStr  = os.Getenv("AUDIT_DEK_KEY")

	ErrBucketUninitialized = errors.New("audit log initialization failed: target bucket does not exist")
	ErrWriteViolation      = errors.New("audit log invariant violation: existing entries are immutable")
	ErrLineageBreach       = errors.New("cryptographic lineage broken: sequential pointers mismatch")
	ErrTamperDetected      = errors.New("data payload mutation detected: calculated hash mismatch")
)
