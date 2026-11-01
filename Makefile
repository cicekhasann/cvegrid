.PHONY: all build run test lint clean

BINARY_NAME=bin/cvegrid

all: test build

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BINARY_NAME) cmd/cvegrid/main.go

run:
	go run cmd/cvegrid/main.go

test:
	go test -v -race ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/
