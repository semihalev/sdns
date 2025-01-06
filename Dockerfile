# Stage 1: Build Stage using Alpine 3.19.4
FROM alpine:latest AS builder

# Install build dependencies, including the latest version of Go and other tools for optimization
RUN apk add --no-cache \
    ca-certificates \
    gcc \
    git \
    musl-dev \
    upx \
    curl \
    binutils-gold && \
    # Download and install the latest version of Go
    curl -sSL https://golang.org/dl/go1.23.4.linux-arm64.tar.gz | tar -C /usr/local -xz && \
    ln -s /usr/local/go/bin/go /usr/bin/go && \
    mkdir -p /src && \
    # Clean up apk cache to reduce image size
    rm -rf /var/cache/apk/*

# Set working directory
WORKDIR /src

# Copy Go module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Use ARG to support multi-arch builds
ARG TARGETARCH

# Build the sdns binary with static linking
RUN CGO_ENABLED=0 GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /sdns && \
    # Strip debug information from the binary
    strip /sdns && \
    # Compress the binary using UPX with maximum compression
    upx --ultra-brute /sdns && \
    # Clean up the source directory to reduce image size
    rm -rf /src

# Stage 2: Runtime Stage using scratch
FROM scratch

# Copy necessary files for runtime
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /sdns /sdns

# Expose necessary ports
EXPOSE 53/tcp
EXPOSE 53/udp
EXPOSE 853
EXPOSE 8053
EXPOSE 8080

# Set the entrypoint to run the binary
ENTRYPOINT ["/sdns"]
