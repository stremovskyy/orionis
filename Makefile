.PHONY: tools tidy fmt test verify verify-go verify-examples verify-docker run-auth run-billing run-orders run-java-client run-php-client docker-build docker-up docker-demo docker-down

JAVA_BUILD_DIR ?= /tmp/orionis-java-orders-client
JAVAC ?= javac
JAVA ?= java
PHP ?= php
GO_TOOLCHAIN ?= go$(shell awk '/^go / { print $$2; exit }' go.mod)
FORMAT_TOOLCHAIN ?= go1.26.7
TOOLS_BIN ?= $(CURDIR)/.tools/bin

tools:
	mkdir -p "$(TOOLS_BIN)"
	GOBIN="$(TOOLS_BIN)" GOTOOLCHAIN=$(FORMAT_TOOLCHAIN) go install github.com/stremovskyy/go-format@v0.5.0
	GOBIN="$(TOOLS_BIN)" GOTOOLCHAIN=$(GO_TOOLCHAIN) go install honnef.co/go/tools/cmd/staticcheck@v0.7.0
	GOBIN="$(TOOLS_BIN)" GOTOOLCHAIN=$(GO_TOOLCHAIN) go install golang.org/x/vuln/cmd/govulncheck@v1.5.0
	GOBIN="$(TOOLS_BIN)" GOTOOLCHAIN=$(GO_TOOLCHAIN) go install golang.org/x/exp/cmd/apidiff@v0.0.0-20260709172345-9ea1abe57597

tidy:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go mod tidy

fmt: | tools
	PATH="$(TOOLS_BIN):$$PATH" go-format --write ./...

test:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go test ./...

verify: verify-go verify-examples verify-docker

verify-go verify-examples verify-docker: | tools

verify-go:
	PATH="$(TOOLS_BIN):$$PATH" scripts/verify-go.sh

verify-examples:
	PATH="$(TOOLS_BIN):$$PATH" scripts/verify-examples.sh

verify-docker:
	PATH="$(TOOLS_BIN):$$PATH" scripts/verify-docker.sh

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
	$(JAVAC) --release 11 -d "$(JAVA_BUILD_DIR)" examples/java-orders-client/OrdersClient.java
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
