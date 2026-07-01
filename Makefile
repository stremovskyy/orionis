.PHONY: tidy fmt test run-auth run-billing run-orders docker-build docker-up docker-demo docker-down

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

docker-build:
	docker build --build-arg TARGET=./cmd/orionis-auth -t orionis-auth:local .

docker-up:
	docker compose up --build --wait -d orionis-auth billing-api

docker-demo:
	docker compose run --rm orders-client

docker-down:
	docker compose down --remove-orphans
