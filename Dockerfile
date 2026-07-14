# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o adapter ./cmd/adapter

# Runtime stage
FROM scratch

COPY --from=builder /app/adapter /adapter

EXPOSE 8080 9090

ENTRYPOINT ["/adapter"]
