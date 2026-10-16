GO ?= go

.PHONY: dev-api dev-web install-web test check build

dev-api:
	$(GO) run ./cmd/kubegrant

install-web:
	npm --prefix web ci

dev-web:
	npm --prefix web run dev

test:
	$(GO) test -race ./...

check:
	$(GO) vet ./...
	npm --prefix web run check

build:
	npm --prefix web run build
	CGO_ENABLED=0 $(GO) build -trimpath -o bin/kubegrant ./cmd/kubegrant

