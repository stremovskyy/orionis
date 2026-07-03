.PHONY: tidy fmt test run-auth run-billing run-orders run-java-client run-php-client docker-build docker-up docker-demo docker-down

JAVA_BUILD_DIR ?= /tmp/orionis-java-orders-client
JAVAC ?= javac
JAVA ?= java
PHP ?= php

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

run-java-client:
	@if [ -z "$(JAVA_BUILD_DIR)" ] || [ "$(JAVA_BUILD_DIR)" = "/" ]; then echo "JAVA_BUILD_DIR is unsafe: '$(JAVA_BUILD_DIR)'"; exit 1; fi
	rm -rf -- "$(JAVA_BUILD_DIR)"
	mkdir -p -- "$(JAVA_BUILD_DIR)"
	$(JAVAC) -d "$(JAVA_BUILD_DIR)" examples/java-orders-client/OrdersClient.java
	$(JAVA) -cp "$(JAVA_BUILD_DIR)" OrdersClient

run-php-client:
	$(PHP) examples/php-orders-client/orders_client.php

docker-build:
	docker build --build-arg TARGET=./cmd/orionis-auth -t orionis-auth:local .

docker-up:
	docker compose up --build --wait -d orionis-auth billing-api

docker-demo:
	docker compose run --rm orders-client

docker-down:
	docker compose down --remove-orphans
