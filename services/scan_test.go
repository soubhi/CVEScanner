package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type MockRepoFetcher struct{}

func TestMarshalRiskFactors(t *testing.T) {
	input := []interface{}{"Remote Code Execution", "High CVSS Score"}
	expected := `["Remote Code Execution","High CVSS Score"]`

	result := MarshalRiskFactors(input)
	assert.Equal(t, expected, result, "Risk factors should be marshaled correctly")
}

func TestFetchAndStoreJSON_Failure(t *testing.T) {
	count := FetchAndStoreJSON("invalid_owner", "invalid_repo", "invalid.json")
	assert.Equal(t, 0, count, "Should return 0 for non-existent files")
}

func TestFetchAndStoreJSON_EmptyFile(t *testing.T) {
	count := FetchAndStoreJSON("velancio", "vulnerability_scans", "empty.json")
	assert.Equal(t, 0, count, "Should return 0 for empty JSON")
}
