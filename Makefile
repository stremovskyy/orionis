.PHONY: tidy fmt test run-auth run-billing run-orders

tidy:
	go mod tidy

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

test:
	go test ./...

run-auth:
	go run ./cmd/orionis-auth -config ./config/orionis.example.json

run-billing:
	go run ./examples/gin-billing-service

run-orders:
	go run ./examples/gin-orders-client
