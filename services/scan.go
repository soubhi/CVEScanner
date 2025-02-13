package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
	"vuln-scanner/database"
)

func MainScanner(repoOwner string, repoName string) int {
	totalVulnCount := 0
	files, err := GetRepoFiles(repoOwner, repoName)
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
					fmt.Println("Fetching file:", fileName)
					countVul := FetchAndStoreJSON(repoOwner, repoName, fileName)
					totalVulnCount += countVul
					<-sem // Release the slot
				}(fileName)
			}
		}
	}
	wg.Wait()
	return totalVulnCount
}

func GetRepoFiles(owner, repo string) ([]map[string]interface{}, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents", owner, repo)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to fetch files, status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var files []map[string]interface{}
	err = json.Unmarshal(body, &files)
	if err != nil {
		return nil, err
	}

	return files, nil
}
func FetchAndStoreJSON(owner, repo, fileName string) int {
	vulcount := 0
	if database.DB == nil {
		fmt.Printf("database is not initialized")
		return 0
	}
	url := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/main/%s", owner, repo, fileName)
	for attempt := 0; attempt < 2; attempt++ {
		fmt.Println("Attempt :", attempt, "fetching :", fileName)
		resp, err := http.Get(url)
		if err != nil {
			fmt.Println("Error fetching JSON (Attempt", attempt+1, "):", err)
			time.Sleep(2 * time.Second)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			fmt.Println("Failed to fetch JSON file:", fileName, "Status:", resp.StatusCode)
			time.Sleep(2 * time.Second)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("Error reading response body:", err)
			return 0
		}

		var jsonData []interface{}
		if err := json.Unmarshal(body, &jsonData); err != nil {
			fmt.Println("Error parsing JSON:", err)
			return 0
		}

		for _, item := range jsonData {
			obj, ok := item.(map[string]interface{})
			if !ok {
				fmt.Println("Error: Element is not a JSON object")
				continue
			}

			scanResults, exists := obj["scanResults"].(map[string]interface{})
			if exists {
				//fmt.Println(scanResults)
			} else {
				fmt.Println("Key 'scanResults' not found")
			}

			scanID, _ := scanResults["scan_id"].(string)
			resourceType, _ := scanResults["resource_type"].(string)
			resourceName, _ := scanResults["resource_name"].(string)
			timestamp, _ := scanResults["timestamp"].(string)

			for _, key := range []string{"vulnerabilities", "findings"} {
				if vulResults, found := scanResults[key]; found {
					vulArray, ok := vulResults.([]interface{})
					if !ok {
						fmt.Println("Error: ", key, " is not an array, actual type:", fmt.Sprintf("%T", vulResults))
						continue
					}

					for _, vulnItem := range vulArray {
						vulnObj, ok := vulnItem.(map[string]interface{})
						if !ok {
							fmt.Println("Error: vulnerability item is not a JSON object")
							continue
						}

						_, err := database.DB.Exec(`INSERT OR IGNORE INTO vulnerabilities (
							id, severity, cvss, status, package_name, current_version, fixed_version,
							description, published_date, link, risk_factors, source_file, scan_time, scan_id, resource_type, resource_name)
							VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
							vulnObj["id"], vulnObj["severity"], vulnObj["cvss"], vulnObj["status"],
							vulnObj["package_name"], vulnObj["current_version"], vulnObj["fixed_version"],
							vulnObj["description"], vulnObj["published_date"], vulnObj["link"],
							MarshalRiskFactors(vulnObj["risk_factors"]), fileName, timestamp, scanID, resourceType, resourceName)
						if err != nil {
							fmt.Println("DB Insert Error:", err)
						}
						fmt.Println("-----")
					}
					vulcount += len(vulArray)
				}
			}
		}
		break
	}
	return vulcount
}

func MarshalRiskFactors(riskFactors interface{}) string {
	if rf, ok := riskFactors.([]interface{}); ok {
		riskFactorsJSON, _ := json.Marshal(rf)
		return string(riskFactorsJSON)
	}
	return "[]"
}
