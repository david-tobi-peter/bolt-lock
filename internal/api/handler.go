package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/david-tobi-peter/bolt-lock/internal/audit"
)

type AuditHandler struct {
	logger *audit.AuditLogger
}

func NewAuditHandler(logger *audit.AuditLogger) *AuditHandler {
	return &AuditHandler{logger: logger}
}

func (h *AuditHandler) VerifyCurrentBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	res, err := h.logger.VerifyCurrentBlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func (h *AuditHandler) QueryEntries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	filters := audit.QueryFilters{
		Actor: q.Get("actor"),
		Path:  q.Get("path"),
	}

	if fromStr := q.Get("from"); fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			filters.From = t.UTC()
		}
	}

	if toStr := q.Get("to"); toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			filters.To = t.UTC()
		}
	}

	entries, err := h.logger.QueryEntries(filters)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}
