package database

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitDB(t *testing.T) {
	DB, err := InitDB()
	assert.NoError(t, err, "Database should initialize without error")
	assert.NotNil(t, DB, "Database should be initialized")
}

func TestInsertAndQueryVulnerability(t *testing.T) {
	InitDB()

	_, err := DB.Exec(`INSERT OR IGNORE INTO vulnerabilities (id, severity, package_name) VALUES ('CVE-2024-1234', 'HIGH', 'openssl')`)
	assert.NoError(t, err, "Insert should be successful")

	var id, severity, packageName string
	err = DB.QueryRow(`SELECT id, severity, package_name FROM vulnerabilities WHERE id='CVE-2024-1234'`).Scan(&id, &severity, &packageName)
	assert.NoError(t, err, "Query should return a result")
	assert.Equal(t, "CVE-2024-1234", id)
	assert.Equal(t, "HIGH", severity)
	assert.Equal(t, "openssl", packageName)
}

func TestInsertDuplicateVulnerability(t *testing.T) {
	InitDB()
	DB.Exec(`DELETE FROM vulnerabilities WHERE id='CVE-2024-1111'`)

	_, err := DB.Exec(`INSERT INTO vulnerabilities (id, severity) VALUES ('CVE-2024-1111', 'MEDIUM')`)
	assert.NoError(t, err)

	_, err = DB.Exec(`INSERT INTO vulnerabilities (id, severity) VALUES ('CVE-2024-1111', 'LOW')`)
	assert.Error(t, err, "Should return error for duplicate primary key")
}
