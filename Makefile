.PHONY: check test fuzz

check:
	@test -z "$$(gofmt -l keys stream utils)" || (gofmt -l keys stream utils; exit 1)
	go vet ./...
	$(MAKE) test

test:
	go test -race -count=1 -coverpkg=./... -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

fuzz:
	go test ./stream -run='^$$' -fuzz=FuzzDecryptV1 -fuzztime=30s -parallel=2
