package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func fetchJSON(url string) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error fetching JSON:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Println("Failed to fetch JSON, status code:", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}
	var jsonData []interface{}
	if err := json.Unmarshal(body, &jsonData); err != nil {
		fmt.Println("Error parsing JSON:", err)
		return
	}

	for _, item := range jsonData {
		// Assert each item as `map[string]interface{}`
		obj, ok := item.(map[string]interface{})
		if !ok {
			fmt.Println("Error: Element is not a JSON object")
			continue
		}

		// Extract and print "scanResults"
		scanResults, exists := obj["scanResults"].(map[string]interface{})
		if exists {
			//fmt.Println(scanResults)
		} else {
			fmt.Println("Key 'scanResults' not found")
		}

		for key, value := range scanResults {
			fmt.Println(key, ":", value)
		}
		vulResults, exists := scanResults["vulnerabilities"]
		if exists {
			fmt.Println("vulResults", vulResults)
		} else {
			fmt.Println("Key 'vulResults' not found")
		}

		vulArray, ok := vulResults.([]interface{})
		if !ok {
			fmt.Println("Error: vulnerabilities is not an array, actual type:", fmt.Sprintf("%T", vulResults))
			return

		}

		// Iterate over vulnerabilities
		for _, vulnItem := range vulArray {
			// Assert each vulnerability as a map
			vulnObj, ok := vulnItem.(map[string]interface{})
			if !ok {
				fmt.Println("Error: vulnerability item is not a JSON object")
				continue
			}

			// Print vulnerability details
			fmt.Printf("ID: %s\n", vulnObj["id"])
			fmt.Printf("Severity: %s\n", vulnObj["severity"])
			fmt.Printf("CVSS Score: %v\n", vulnObj["cvss"])
			fmt.Printf("Status: %s\n", vulnObj["status"])
			fmt.Printf("Package: %s\n", vulnObj["package_name"])
			fmt.Printf("Current Version: %s\n", vulnObj["current_version"])
			fmt.Printf("Fixed Version: %s\n", vulnObj["fixed_version"])
			fmt.Printf("Description: %s\n", vulnObj["description"])
			fmt.Printf("Published Date: %s\n", vulnObj["published_date"])
			fmt.Printf("Link: %s\n", vulnObj["link"])

			// Handle risk_factors, which is also an array
			if riskFactors, exists := vulnObj["risk_factors"].([]interface{}); exists {
				fmt.Printf("Risk Factors: %v\n", riskFactors)
			}
			fmt.Println("-----")
		}
	}
}

func main() {
	url := "https://raw.githubusercontent.com/velancio/vulnerability_scans/main/vulnscan1011.json"
	fetchJSON(url)
}
