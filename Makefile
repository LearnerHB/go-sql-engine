BINARY     := sql-engine
MODULE     := github.com/bingcs/sql-engine
BUILD_DIR  := build

.PHONY: build build-linux run clean vet

build:
	go build -o $(BUILD_DIR)/$(BINARY) .

build-linux:
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY)-linux-amd64 .
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY)-darwin-arm64 .

run:
	go run .

clean:
	rm -rf $(BUILD_DIR)

vet:
	go vet ./...
