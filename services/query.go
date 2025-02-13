package services

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"vuln-scanner/database"
)

func QueryVulnerabilities(severity string) ([]map[string]interface{}, error) {
	rows, err := database.DB.Query("SELECT id, severity, cvss, status, package_name, current_version, fixed_version, description, published_date, link, risk_factors, source_file, scan_time, scan_id, resource_type, resource_name FROM vulnerabilities WHERE severity = ?", severity)
	if err != nil {
		return nil, err
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
			return nil, err
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
	return results, nil
}

func nullStringToString(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

func nullFloatToFloat(nf sql.NullFloat64) interface{} {
	if nf.Valid {
		return nf.Float64
	}
	return nil
}

func parseRiskFactors(riskFactors string) []string {
	var parsed []string
	err := json.Unmarshal([]byte(riskFactors), &parsed)
	if err != nil {
		return []string{riskFactors}
	}
	return parsed
}
