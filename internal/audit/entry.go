package audit

import (
	"encoding/json"
	"time"
)

type LogEntry struct {
	EntryID   string    `json:"entry_id"`
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`
	Operation string    `json:"operation"`
	Path      string    `json:"path"`
	Result    string    `json:"result"`
}

func (le *LogEntry) Marshal() ([]byte, error) {
	return json.Marshal(le)
}

func (le *LogEntry) Unmarshal(data []byte) (*LogEntry, error) {
	var logEntry LogEntry
	if err := json.Unmarshal(data, &logEntry); err != nil {
		return nil, err
	}
	return &logEntry, nil
}
