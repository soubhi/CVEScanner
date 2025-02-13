package api

import (
	// "vuln-scanner/api"

	"encoding/json"
	"net/http"
	"vuln-scanner/services"

	_ "github.com/mattn/go-sqlite3"
)

func QueryHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Filters map[string]string `json:"filters"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	severity, ok := req.Filters["severity"]
	if !ok {
		http.Error(w, "Missing severity filter", http.StatusBadRequest)
		return
	}
	results, err := services.QueryVulnerabilities(severity)
	if err != nil {
		http.Error(w, "Database query error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}
