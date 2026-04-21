APP_NAME := zap-kb

.PHONY: build run test e2e clean

build:
	go build -o bin/$(APP_NAME) ./cmd/$(APP_NAME)

run:
	go run ./cmd/$(APP_NAME)

test:
	go test ./...

e2e:
	go test -tags e2e ./e2e/...

clean:
	rm -rf bin
