.PHONY: test cover lint build demo audit tidy clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-15s\033[0m %s\n",$$1,$$2}'

test: ## Run all unit tests with race detector
	go test ./... -v -race -count=1

cover: ## Run tests + open HTML coverage report
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	open coverage.html || xdg-open coverage.html

lint: ## Run golangci-lint
	golangci-lint run ./...

tidy: ## Tidy all modules
	go mod tidy
	cd examples/gqlgen-demo  && go mod tidy
	cd examples/audit-demo   && go mod tidy

build: ## Build all examples (smoke test)
	go build ./...
	cd examples/gqlgen-demo  && go build ./...
	cd examples/audit-demo   && go build ./...

demo: ## Start gqlgen-demo server + fire all attacks
	@echo "Starting gqlgen-demo on :8080 ..."
	@cd examples/gqlgen-demo && go run server.go &
	@sleep 2
	@bash examples/gqlgen-demo/attacks.sh

audit: ## Run Layer 3 resolver audit on insecure demo
	cd examples/audit-demo && go run main.go; true

install-cryptoguard: ## Install cryptoguard-go for deeper resolver auditing
	go install github.com/ravisastryk/cryptoguard-go/cmd/cryptoguard@latest

clean: ## Remove build artefacts
	rm -f coverage.out coverage.html
	go clean ./...
