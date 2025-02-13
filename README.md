# Vulnerability Scanner API

This Go service scans a **GitHub repository** for JSON vulnerability reports, **stores them in an SQLite database**, and provides a **query API** to retrieve vulnerabilities based on severity.

---

## Table of Contents

1. [Features](#features)  
2. [Prerequisites](#prerequisites)  
3. [Installation](#installation)  
4. [Running the Service](#running-the-service)  
5. [Dockerfile](#dockerfile)  
6. [API Usage](#api-usage)  
   - [Scan API (`POST /scan`)](#1-scan-api-post-scan)  
   - [Query API (`POST /query`)](#2-query-api-post-query)  
7. [Running Tests](#running-tests)  
8. [Project Structure](#project-structure)  
9. [Environment Variables](#environment-variables)  
10. [Contributing](#contributing)  
11. [License](#license)  

---

<a name="features"></a>
## Features

- **Scan API (`/scan`)**: Fetches JSON files from a GitHub repository and stores vulnerability data.  
- **Query API (`/query`)**: Retrieves stored vulnerabilities based on severity.  
- **SQLite Database**: Persistent storage for scanned vulnerabilities.  
- **Parallel File Processing**: Scans multiple files concurrently.  
- **Error Handling & Retries**: Handles API failures with automatic retries.  
- **Docker Support**: Runs inside a Docker container.  
- **Unit Tests with High Coverage**: Ensures code reliability.  

---

<a name="prerequisites"></a>
## Prerequisites

Ensure the following dependencies are installed:
- **Go 1.21+**  
- **Docker**  
- **Git**  

---

<a name="installation"></a>
## Installation

1. **Clone the Repository**:
   
       git clone https://github.com/soubhi/CVEScanner.git
       cd CVEScanner

2. **Install Dependencies**:
   
       go mod tidy

---

<a name="running-the-service"></a>
## Running the Service

### 1. **Run Locally (Without Docker)**

    go run main.go

The service will start on **http://localhost:8081**.

### 2. **Run with Docker**

1. **Build the Docker Image**:
   
       docker build -t vuln-scanner .

2. **Run the Container**:
   
       docker run -p 8081:8081 vuln-scanner

Now your service should be up and running at **http://localhost:8081**.

---

<a name="dockerfile"></a>
## Dockerfile

Below is a production-ready Dockerfile that installs all necessary dependencies to run this scanner (including CA certificates, `tzdata`, and `libsqlite3-dev` for SQLite support).

    FROM golang:1.21 AS builder

    # Create and switch to the /app directory
    WORKDIR /app

    # Copy go.mod and go.sum first for caching
    COPY go.mod go.sum ./
    RUN go mod tidy

    # Copy the entire project
    COPY . .

    # Build the Go application
    RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o server main.go

    # Final minimal image
    FROM ubuntu:22.04

    # Install required libraries
    RUN apt-get update && apt-get install -y \
        ca-certificates \
        tzdata \
        libsqlite3-dev && \
        rm -rf /var/lib/apt/lists/*

    WORKDIR /root/

    # Copy the compiled binary from the builder stage
    COPY --from=builder /app/server .

    # Expose port 8081
    EXPOSE 8081

    # Run the server
    CMD ["./server"]

---

<a name="api-usage"></a>
## API Usage

<a name="1-scan-api-post-scan"></a>
### 1. **Scan API (`POST /scan`)**

Fetches JSON vulnerability files from a GitHub repository and stores them.

- **Example Request**:

      curl -X POST http://localhost:8081/scan \
           -H "Content-Type: application/json" \
           -d '{
                 "repo": "velancio/vulnerability_scans",
                 "files": ["vulnscan1.json", "vulnscan2.json"]
               }'

- **Example Response**:

      {
        "message": "Scan completed successfully",
        "repo": "velancio/vulnerability_scans",
        "files": ["vulnscan1.json", "vulnscan2.json"],
        "total_vulnerabilities": 10
      }

---

<a name="2-query-api-post-query"></a>
### 2. **Query API (`POST /query`)**

Retrieves vulnerabilities matching the given severity.

- **Example Request**:

      curl -X POST http://localhost:8081/query \
           -H "Content-Type: application/json" \
           -d '{
                 "filters": {
                   "severity": "HIGH"
                 }
               }'

- **Example Response**:

      [
        {
          "id": "CVE-2024-1234",
          "severity": "HIGH",
          "cvss": 8.5,
          "status": "fixed",
          "package_name": "openssl",
          "current_version": "1.1.1t-r0",
          "fixed_version": "1.1.1u-r0",
          "description": "Buffer overflow vulnerability in OpenSSL",
          "published_date": "2024-01-15T00:00:00Z",
          "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
          "risk_factors": [
            "Remote Code Execution",
            "High CVSS Score",
            "Public Exploit Available"
          ]
        }
      ]

---

<a name="running-tests"></a>
## Running Tests

1. **Run All Tests** (with coverage):

       go test ./... -cover

2. **Run Specific Test File**:

       go test ./services/scan_test.go

3. **Check Coverage**:

       go test -coverprofile=coverage.out ./...
       go tool cover -func=coverage.out
       # Generate an HTML coverage report
       go tool cover -html=coverage.out -o coverage.html

---

<a name="project-structure"></a>
## Project Structure

    vuln-scanner
    ├── api
    │   ├── scan_handler.go         # Handles /scan API
    │   ├── query_handler.go        # Handles /query API
    │   └── route.go                # Defines routes
    ├── database
    │   ├── database.go             # SQLite setup & queries
    ├── services
    │   ├── scan.go                 # Fetch & store vulnerabilities
    │   ├── query.go                # Query vulnerabilities
    ├── main.go                     # Entry point
    ├── Dockerfile                  # Docker setup
    ├── go.mod                      # Go module dependencies
    ├── go.sum                      # Go dependency versions
    └── README.md                   # This documentation

---

<a name="environment-variables"></a>
## Environment Variables

You can add a `.env` file (optional) for environment-specific configs:

    PORT=8081
    DB_FILE=./vulnerabilities.db
    GITHUB_TOKEN=your_github_personal_access_token

To load environment variables, run:

    source .env
    go run main.go

---

<a name="contributing"></a>
## Contributing

1. **Fork this repository**  
2. **Create a feature branch**  
3. **Commit your changes**  
4. **Open a Pull Request**  

---

<a name="license"></a>
## License

MIT License

---

**Enjoy scanning for vulnerabilities!** If you have any questions or need further assistance, please open an issue or reach out to the maintainer. Thank you for using **Vulnerability Scanner API**.
