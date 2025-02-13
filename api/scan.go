package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"vuln-scanner/services"
)

type ScanRequest struct {
	Repo  string   `json:"repo"`
	Files []string `json:"files"`
}

func ScanHandler(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if req.Repo == "" || len(req.Files) == 0 {
		http.Error(w, "Missing repo or files", http.StatusBadRequest)
		return
	}
	parts := strings.SplitN(req.Repo, "/", 2)
	if len(parts) != 2 {
		http.Error(w, "Invalid repo format. Expected 'owner/repository'", http.StatusBadRequest)
		return
	}
	repoOwner, repoName := parts[0], parts[1]
	totalVulnCount := services.MainScanner(repoOwner, repoName)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := map[string]interface{}{
		"message":               "Scan completed successfully",
		"repo":                  req.Repo,
		"files":                 req.Files,
		"total_vulnerabilities": totalVulnCount,
	}
	json.NewEncoder(w).Encode(response)
}
