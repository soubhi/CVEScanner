package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

const repoOwner = "velancio"
const repoName = "vulnerability_scans"

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./vulnerabilities.db")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS vulnerabilities (
		id TEXT PRIMARY KEY,
		severity TEXT,
		cvss REAL,
		status TEXT,
		package_name TEXT,
		current_version TEXT,
		fixed_version TEXT,
		description TEXT,
		published_date TEXT,
		link TEXT,
		risk_factors TEXT,
		source_file TEXT,
		scan_time TEXT, 
		scan_id TEXT, 
		resource_type TEXT, 
		resource_name TEXT
	)`)

	if err != nil {
		panic(err)
	}
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	totalVulnCount := mainScan()
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Scan completed. Total vulnerabilities: %d", totalVulnCount)
}
func queryHandler(w http.ResponseWriter, r *http.Request) {
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

	rows, err := db.Query("SELECT id, severity, cvss, status, package_name, current_version, fixed_version, description, published_date, link, risk_factors, source_file, scan_time, scan_id, resource_type, resource_name FROM vulnerabilities WHERE severity = ?", severity)
	if err != nil {
		http.Error(w, "Database query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	//fmt.Println(rows)
	var results []map[string]interface{}
	for rows.Next() {
		var (
			id, severity, status, packageName, currentVersion, fixedVersion, description, publishedDate, link, riskFactors, sourceFile, scanTime, scanId, resourceType, resourceName sql.NullString
			cvss                                                                                                                                                                     sql.NullFloat64
		)
		if err := rows.Scan(&id, &severity, &cvss, &status, &packageName, &currentVersion, &fixedVersion, &description, &publishedDate, &link, &riskFactors, &sourceFile, &scanTime, &scanId, &resourceType, &resourceName); err != nil {
			fmt.Print(err)
			http.Error(w, "Error scanning database results", http.StatusInternalServerError)
			return
		}
		result := map[string]interface{}{
			"id":              nullStringToString(id),
			"severity":        nullStringToString(severity),
			"cvss":            nullFloatToFloat(cvss),
			"status":          nullStringToString(status),
			"package_name":    nullStringToString(packageName),
			"current_version": nullStringToString(currentVersion),
			"fixed_version":   nullStringToString(fixedVersion),
			"description":     nullStringToString(description),
			"published_date":  nullStringToString(publishedDate),
			"link":            nullStringToString(link),
			"risk_factors":    parseRiskFactors(nullStringToString(riskFactors)),
			"source_file":     nullStringToString(sourceFile),
			"scan_time":       nullStringToString(scanTime),
			"scan_id":         nullStringToString(scanId),
			"resource_type":   nullStringToString(resourceType),
			"resource_name":   nullStringToString(resourceName),
		}
		results = append(results, result)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func nullStringToString(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return "" // Return empty string for null values
}

func nullFloatToFloat(nf sql.NullFloat64) interface{} {
	if nf.Valid {
		return nf.Float64
	}
	return nil // Return nil for null floats
}

func parseRiskFactors(riskFactors string) []string {
	var parsed []string
	err := json.Unmarshal([]byte(riskFactors), &parsed)
	if err != nil {
		// If it's a plain string with spaces, convert it to a slice
		return []string{riskFactors}
	}
	return parsed
}

func mainScan() int {
	totalVulnCount := 0
	files, err := getRepoFiles(repoOwner, repoName)
	if err != nil {
		fmt.Println("Error fetching repository files:", err)
		return 0
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 3)
	for _, file := range files {
		if file["type"] == "file" {
			fileName := file["name"].(string)
			if len(fileName) > 5 && fileName[len(fileName)-5:] == ".json" {
				wg.Add(1)
				sem <- struct{}{} // Acquire a slot
				go func(fileName string) {
					defer wg.Done()
					countVul := fetchAndStoreJSON(repoOwner, repoName, fileName)
					totalVulnCount += countVul
					<-sem // Release the slot
				}(fileName)
			}
		}
	}
	wg.Wait()
	return totalVulnCount
}

func main() {
	initDB()
	http.HandleFunc("/scan", scanHandler)
	http.HandleFunc("/query", queryHandler)

	fmt.Println("Server running on port 8081...")
	http.ListenAndServe(":8081", nil)
}
