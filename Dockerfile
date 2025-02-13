# Use Go image with correct platform for Apple Silicon
FROM --platform=linux/arm64 golang:1.23.6 AS builder

WORKDIR /app

# Copy module files
COPY go.mod go.sum ./
RUN go mod tidy

# Copy source code
COPY . .

# ✅ Enable CGO & target ARM64 for Mac M1/M2/M3
RUN CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -o server main.go fetchfiles.go

# Use Ubuntu to avoid GLIBC issues
FROM --platform=linux/arm64 ubuntu:22.04

# Install dependencies needed for go-sqlite3
RUN apt update && apt install -y libc6 libsqlite3-dev

RUN apt update && apt install -y ca-certificates && update-ca-certificates && apt install -y tzdata

WORKDIR /root/
COPY --from=builder /app/server .

EXPOSE 8081
CMD ["./server"]
