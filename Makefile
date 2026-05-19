.PHONY: build test cover race run demo clean fmt vet

BIN := bin
GO  ?= go

build:
	$(GO) build -o $(BIN)/aegisd ./cmd/aegisd
	$(GO) build -o $(BIN)/aegis-verify ./cmd/aegis-verify

test:
	$(GO) test ./... -count=1 -race

cover:
	$(GO) test ./... -count=1 -coverprofile=coverage.out
	$(GO) tool cover -func=coverage.out | tail -1

race:
	$(GO) test ./... -count=1 -race

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

run: build
	./$(BIN)/aegisd -addr :8080 -data ./data -rules configs/rules.json

demo: build
	./scripts/demo.sh

clean:
	rm -rf $(BIN) data coverage.out
