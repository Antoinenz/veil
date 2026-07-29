GO      ?= go
BIN     := bin
LDFLAGS := -s -w

.PHONY: all build client server test vet fmt tidy clean cross

all: build

build: client server

client:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN)/veil ./cmd/veil

server:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN)/veil-server ./cmd/veil-server

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

tidy:
	$(GO) mod tidy

# Cross-compile the two primary v1 targets.
cross:
	GOOS=linux   GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN)/linux-amd64/veil        ./cmd/veil
	GOOS=linux   GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN)/linux-amd64/veil-server ./cmd/veil-server
	GOOS=windows GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN)/windows-amd64/veil.exe  ./cmd/veil

clean:
	rm -rf $(BIN)
