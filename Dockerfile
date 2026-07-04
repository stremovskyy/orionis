# syntax=docker/dockerfile:1

FROM golang:1.25.11-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGET=./cmd/orionis-auth
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/orionis ${TARGET}

FROM alpine:3.22

RUN apk add --no-cache ca-certificates \
	&& addgroup -S orionis \
	&& adduser -S -G orionis -h /app orionis \
	&& mkdir -p /app/config /app/var \
	&& chown -R orionis:orionis /app

WORKDIR /app

COPY --from=builder /out/orionis /usr/local/bin/orionis

USER orionis

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
	CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/orionis"]
CMD ["-config", "/app/config/orionis.json"]
