package proxy

import (
	"encoding/json"
	"net/http"
	"strings"
)

// DenyBody returns a standard JSON error body for deny/API responses: {"errors":[{"message":"..."}]}.
// Used for consistent response shaping; escape message for safe JSON.
func DenyBody(statusCode int, message string) []byte {
	msg := message
	msg = strings.ReplaceAll(msg, `\`, `\\`)
	msg = strings.ReplaceAll(msg, `"`, `\"`)
	b, _ := json.Marshal(map[string]any{
		"errors": []map[string]any{{"message": msg}},
	})
	return b
}

// WriteDenyResponse writes statusCode and a standard JSON error body to w.
func WriteDenyResponse(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(DenyBody(statusCode, message))
}
