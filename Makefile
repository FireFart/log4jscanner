.DEFAULT_GOAL := build

.PHONY: linux
linux:
	GOOS=linux GOARCH=amd64 go build -o log4jscanner

.PHONY: windows
windows:
	GOOS=windows GOARCH=amd64 go build -o log4jscanner.exe

.PHONY: release
release: update build test windows linux

.PHONY: update
update:
	go get -u
	go mod tidy

.PHONY: build
build: test
	go fmt ./...
	go vet ./...
	go build

.PHONY: lint
lint:
	"$$(go env GOPATH)/bin/golangci-lint" run ./...
	go mod tidy

.PHONY: lint-update
lint-update:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin
	$$(go env GOPATH)/bin/golangci-lint --version

.PHONY: test
test: build
	go test -race -cover ./...
