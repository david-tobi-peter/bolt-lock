package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

type LogEntry struct {
	EntryID          string    `json:"entry_id"`
	Timestamp        time.Time `json:"timestamp"`
	Actor            string    `json:"actor"`
	Operation        string    `json:"operation"`
	Path             string    `json:"path"`
	PreviousHash     string    `json:"previous_hash"`
	Hash             string    `json:"hash"`
	EncryptedPayload string    `json:"encrypted_payload"`
}

func (le *LogEntry) ComputeHMAC(hmacKey []byte) string {
	mac := hmac.New(sha256.New, hmacKey)

	mac.Write([]byte(le.EntryID))
	mac.Write([]byte(le.Timestamp.Format(time.RFC3339Nano)))
	mac.Write([]byte(le.Actor))
	mac.Write([]byte(le.Path))
	mac.Write([]byte(le.Operation))
	mac.Write([]byte(le.PreviousHash))
	mac.Write([]byte(le.EncryptedPayload))

	return hex.EncodeToString(mac.Sum(nil))
}

func (le *LogEntry) MarshalLogEntry() ([]byte, error) {
	return json.Marshal(le)
}

func UnmarshalLogEntry(data []byte) (*LogEntry, error) {
	var logEntry LogEntry
	if err := json.Unmarshal(data, &logEntry); err != nil {
		return nil, err
	}
	return &logEntry, nil
}
