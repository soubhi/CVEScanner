# 🚀 Vulnerability Scanner API

This Go service scans a GitHub repository for JSON vulnerability reports, stores them in an SQLite database, and provides a query API to retrieve vulnerabilities based on severity.

---

## **📌 Features**
**Scan API (`/scan`)** - Fetches JSON files from a GitHub repository and stores vulnerability data.  
**Query API (`/query`)** - Retrieves stored vulnerabilities based on severity.  
**SQLite Database** - Persistent storage for scanned vulnerabilities.  
**Parallel File Processing** - Scans multiple files concurrently.  
**Error Handling & Retries** - Handles API failures with automatic retries.  
**Docker Support** - Runs inside a Docker container.  
**Unit Tests with High Coverage** - Ensures code reliability.  

---

## **📌 Prerequisites**
Ensure the following dependencies are installed on your machine:
- **Go 1.23+**
- **Docker**
- **Git**

---

## **📌 Installation**
### **🔹 1. Clone the Repository**
```sh
git clone https://github.com/yourusername/vuln-scanner.git
cd vuln-scanner
