package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type ScanRequest struct {
	Repo  string   `json:"repo"`
	Files []string `json:"files"`
}

type QueryRequest struct {
	Filters map[string]string `json:"filters"`
}

type Vulnerability struct {
	ID             string   `json:"id"`
	Severity       string   `json:"severity"`
	CVSS           float64  `json:"cvss"`
	Status         string   `json:"status"`
	PackageName    string   `json:"package_name"`
	CurrentVersion string   `json:"current_version"`
	FixedVersion   string   `json:"fixed_version"`
	Description    string   `json:"description"`
	PublishedDate  string   `json:"published_date"`
	Link           string   `json:"link"`
	RiskFactors    []string `json:"risk_factors"`
	SourceFile     string   `json:"source_file"`
	ScanTime       string   `json:"scan_time"`
}

var db *sql.DB

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
		scan_time TEXT
	)`)

	if err != nil {
		panic(err)
	}
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 3)

	for _, file := range req.Files {
		wg.Add(1)
		sem <- struct{}{} // Limit concurrency
		go func(file string) {
			defer wg.Done()
			fetchAndStoreJSON(req.Repo, file)
			<-sem
		}(file)
	}
	wg.Wait()
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Scan completed")
}

func fetchAndStoreJSON(repo, file string) {
	url := fmt.Sprintf("https://raw.githubusercontent.com/%s/main/%s", repo, file)

	for i := 0; i < 2; i++ { // Retry mechanism
		resp, err := http.Get(url)
		if err != nil || resp.StatusCode != 200 {
			time.Sleep(2 * time.Second)
			continue
		}
		print(resp, "\n")
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()

		var vulnerabilities []Vulnerability
		if err := json.Unmarshal(body, &vulnerabilities); err != nil {
			return
		}
		print(body, "\n")
		print(vulnerabilities)

		timestamp := time.Now().Format(time.RFC3339)
		for _, v := range vulnerabilities {
			v.SourceFile = file
			v.ScanTime = timestamp
			storeVulnerability(v)
		}
		break
	}
}
func mustMarshal(data interface{}) string {
	result, err := json.Marshal(data)
	if err != nil {
		return "[]" // Return empty array as fallback
	}
	return string(result)
}

func storeVulnerability(v Vulnerability) {
	_, err := db.Exec(`INSERT INTO vulnerabilities (
		id, severity, cvss, status, package_name, current_version, fixed_version, 
		description, published_date, link, risk_factors, source_file, scan_time) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.Severity, v.CVSS, v.Status, v.PackageName, v.CurrentVersion, v.FixedVersion,
		v.Description, v.PublishedDate, v.Link, mustMarshal(v.RiskFactors), v.SourceFile, v.ScanTime)

	if err != nil {
		fmt.Println("DB Insert Error:", err)
	}
}

func queryHandler(w http.ResponseWriter, r *http.Request) {
	var req QueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	severity, ok := req.Filters["severity"]
	if !ok {
		http.Error(w, "Missing severity filter", http.StatusBadRequest)
		return
	}

	rows, err := db.Query("SELECT id, severity, cvss, status, package_name, current_version, fixed_version, description, published_date, link, risk_factors, source_file, scan_time FROM vulnerabilities WHERE severity = ?", severity)
	if err != nil {
		http.Error(w, "Database query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results []Vulnerability
	for rows.Next() {
		var v Vulnerability
		var riskFactorsStr string
		rows.Scan(&v.ID, &v.Severity, &v.CVSS, &v.Status, &v.PackageName, &v.CurrentVersion, &v.FixedVersion, &v.Description, &v.PublishedDate, &v.Link, &riskFactorsStr, &v.SourceFile, &v.ScanTime)
		json.Unmarshal([]byte(riskFactorsStr), &v.RiskFactors)
		results = append(results, v)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func main() {
	initDB()
	http.HandleFunc("/scan", scanHandler)
	http.HandleFunc("/query", queryHandler)

	fmt.Println("Server running on port 8081...")
	http.ListenAndServe(":8081", nil)
}
