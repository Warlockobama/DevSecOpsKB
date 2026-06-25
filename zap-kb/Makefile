APP_NAME := zap-kb
CONTAINER_IMAGE ?= devsecopskb/zap-kb-zap:local

.PHONY: build run test e2e container-build container-check clean

build:
	go build -o bin/$(APP_NAME) ./cmd/$(APP_NAME)

run:
	go run ./cmd/$(APP_NAME)

test:
	go test ./...

e2e:
	go test -tags e2e ./e2e/...

container-build:
	docker build -t $(CONTAINER_IMAGE) .

container-check:
	docker run --rm $(CONTAINER_IMAGE) -init -format entities -plugins 10038 -out /tmp/entities.json

clean:
	rm -rf bin
