package database

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

func InitDB() (*sql.DB, error) {
	var err error
	DB, err = sql.Open("sqlite3", "./vulnerabilities.db")
	if err != nil {
		panic(err)
	}

	_, err = DB.Exec(`CREATE TABLE IF NOT EXISTS vulnerabilities (
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
		return nil, err
	}

	return DB, nil
}
