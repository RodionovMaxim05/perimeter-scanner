FROM golang:1.26-alpine AS builder

WORKDIR /app

ENV CGO_ENABLED=0
ENV GOOS=linux

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /app/scanner cmd/app/main.go

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    masscan \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/scanner .

COPY config/config.yaml ./config/config.yaml

ENTRYPOINT ["./scanner", "-config", "config/config.yaml"]
