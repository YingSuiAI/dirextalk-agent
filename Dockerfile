# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev

# Copy application source after dependency resolution.
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o dirextalk-agent ./cmd/dirextalk-agent

# Final stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/dirextalk-agent .

# Create directories
RUN mkdir -p /app/data /app/certs /app/config

# Expose ports
EXPOSE 50051
EXPOSE 8080

# Run
CMD ["./dirextalk-agent"]
