package services

import (
	"testing"
	"vuln-scanner/database"

	"github.com/stretchr/testify/assert"
)

func TestQueryVulnerabilities(t *testing.T) {
	database.InitDB()
	_, err := database.DB.Exec(`INSERT or IGNORE INTO vulnerabilities (id, severity, package_name) VALUES ('CVE-2024-1234', 'HIGH', 'openssl')`)
	assert.NoError(t, err, "Test vulnerability should be inserted")

	results, err := QueryVulnerabilities("HIGH")
	assert.NoError(t, err, "Query should not return an error")
	assert.Len(t, results, 1, "Should return one vulnerability")
	assert.Equal(t, "CVE-2024-1234", results[0]["id"])
}
