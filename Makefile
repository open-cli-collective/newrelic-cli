.PHONY: build clean test install release

BINARY_NAME=newrelic-cli
VERSION?=dev

build:
	go build -ldflags "-X github.com/piekstra/newrelic-cli/cmd.version=$(VERSION)" -o $(BINARY_NAME) .

clean:
	rm -f $(BINARY_NAME)
	rm -rf dist/

test:
	go test ./...

install: build
	mv $(BINARY_NAME) /usr/local/bin/

release:
	goreleaser release --clean

snapshot:
	goreleaser release --snapshot --clean
