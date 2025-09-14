APP_NAME := zap-kb

.PHONY: build run test clean

build:
	go build -o bin/$(APP_NAME) ./cmd/$(APP_NAME)

run:
	go run ./cmd/$(APP_NAME)

test:
	go test ./...

clean:
	rm -rf bin
