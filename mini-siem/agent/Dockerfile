# agent-go/Dockerfile
# Multi-stage build for minimal production image

# ---- Stage 1: Builder ----
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Copy go mod files first (for better caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" \
    -o agent .

# ---- Stage 2: Final minimal image ----
FROM alpine:latest

# Add ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 -S agent && \
    adduser -u 1000 -S agent -G agent

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder --chown=agent:agent /app/agent .

# Copy config (optional - can be mounted as volume)
COPY --chown=agent:agent config.json .

# Switch to non-root user
USER agent

# Expose syslog port (UDP)
EXPOSE 514/udp

# Run agent
ENTRYPOINT ["./agent"]
CMD ["-config", "config.json"]