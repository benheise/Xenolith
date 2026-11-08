# xenolith-scan build helpers. The Go module lives in this directory; the fingerprint
# pack and the product registry snapshot are copied in from the repository so the
# binary embeds pinned copies (`make sync` refreshes them; tests check the pack copy).

BIN     ?= xenolith-scan
VERSION ?= $(shell git describe --tags --match 'scan/v*' --always 2>/dev/null | sed 's|^scan/||')
LDFLAGS  = -s -w -X main.Version=$(VERSION)

.PHONY: build sync test vet lint release-snapshot clean

build: sync
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/xenolith-scan

sync:
	cp ../catalog/fingerprints.yaml internal/fingerprint/pack.yaml
	@if [ -f ../docs/data/products.json ]; then python3 ../tools/export_registry.py; fi

test: sync
	go test ./...

vet:
	go vet ./...

release-snapshot:
	goreleaser release --snapshot --clean --skip=publish,sign

clean:
	rm -f $(BIN)
	rm -rf dist
