APP_NAME := zap-kb
CONTAINER_IMAGE ?= devsecopskb/zap-kb-zap:local
VERSION ?= dev
REVISION ?= $(shell git rev-parse --verify HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= unknown
BUILDINFO_PKG := github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/buildinfo
LDFLAGS := -s -w -X $(BUILDINFO_PKG).Version=$(VERSION) -X $(BUILDINFO_PKG).Revision=$(REVISION) -X $(BUILDINFO_PKG).BuildTime=$(BUILD_TIME)

.PHONY: build run test test-cli-contract e2e test-offline-e2e test-forgejo-e2e container-build container-check clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(APP_NAME) ./cmd/$(APP_NAME)

run:
	go run ./cmd/$(APP_NAME)

test:
	go test ./...

test-cli-contract:
	go test ./cmd/$(APP_NAME)/...

e2e: test-offline-e2e

test-offline-e2e:
	go test -tags e2e ./e2e/...

test-forgejo-e2e:
	go test -tags e2e -count=1 -timeout 20m ./internal/e2e/forgejo/...

container-build:
	docker build --build-arg VERSION=$(VERSION) --build-arg REVISION=$(REVISION) --build-arg BUILD_TIME=$(BUILD_TIME) -t $(CONTAINER_IMAGE) .

container-check:
	docker run --rm $(CONTAINER_IMAGE) -init -format entities -plugins 10038 -out /tmp/entities.json

clean:
	rm -rf bin
