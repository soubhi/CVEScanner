package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Mock function
func mockMainScanner(owner, repo string) int {
	return 5 // Fake vulnerability count
}

// Custom wrapper for testing
func scanHandlerWithMock(mockFunc func(string, string) int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		totalVulnCount := mockFunc(repoOwner, repoName)

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
}

func TestScanHandler(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    map[string]interface{}
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name: "Valid Request",
			requestBody: map[string]interface{}{
				"repo":  "velancio/vulnerability_scans",
				"files": []string{"vulnscan1.json", "vulnscan2.json"},
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"message":               "Scan completed successfully",
				"repo":                  "velancio/vulnerability_scans",
				"files":                 []string{"vulnscan1.json", "vulnscan2.json"},
				"total_vulnerabilities": 5, // Mocked return value
			},
		},
		{
			name: "Invalid Request - Missing Repo",
			requestBody: map[string]interface{}{
				"files": []string{"vulnscan1.json"},
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Invalid Request - Missing Files",
			requestBody: map[string]interface{}{
				"repo": "velancio/vulnerability_scans",
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Invalid Repo Format",
			requestBody: map[string]interface{}{
				"repo":  "invalidformat",
				"files": []string{"vulnscan1.json"},
			},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.requestBody)
			req, err := http.NewRequest("POST", "/scan", bytes.NewBuffer(body))
			assert.NoError(t, err)

			rr := httptest.NewRecorder()
			handler := scanHandlerWithMock(mockMainScanner) // Use the mock
			handler.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			if tc.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				err = json.Unmarshal(rr.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedBody["message"], response["message"])
			}
		})
	}
}
