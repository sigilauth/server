# Sigil Server — Multi-stage Docker Build
#
# Stage 1: Build binary
# Stage 2: Runtime (minimal Alpine image)

# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go.mod and go.sum first (layer caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build binary (CGO disabled for static linking)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -o /build/sigil \
    ./cmd/sigil

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates wget

# Create non-root user
RUN addgroup -g 1000 sigil && \
    adduser -D -u 1000 -G sigil sigil

# Create data directory
RUN mkdir -p /var/lib/sigil/tls && \
    chown -R sigil:sigil /var/lib/sigil

# Copy binary from builder
COPY --from=builder /build/sigil /usr/local/bin/sigil

# Switch to non-root user
USER sigil

# Expose HTTPS port
EXPOSE 8443

# Health check
HEALTHCHECK --interval=10s --timeout=3s --retries=3 --start-period=10s \
    CMD wget --no-verbose --tries=1 --spider --no-check-certificate https://localhost:8443/health || exit 1

# Set working directory
WORKDIR /var/lib/sigil

# Run server
ENTRYPOINT ["/usr/local/bin/sigil"]
CMD ["serve"]
