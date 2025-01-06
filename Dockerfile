# Stage 1: Build Stage using Alpine latest
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
    # Define architecture as a build argument
    ARG TARGETARCH
    ENV GO_ARCH=${TARGETARCH} && \
    # Download and install Go sesuai arsitektur
    curl -sSL https://golang.org/dl/go1.23.4.linux-${GO_ARCH}.tar.gz | tar -C /usr/local -xz && \
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

# Build the sdns binary with static linking
RUN CGO_ENABLED=0 GOARCH=${GO_ARCH} go build -trimpath -ldflags="-s -w" -o /tmp/sdns && \
    # Strip debug information from the binary
    strip /tmp/sdns && \
    # Compress the binary using UPX with maximum compression
    upx --ultra-brute /tmp/sdns && \
    # Clean up the source directory to reduce image size
    rm -rf /src

# Stage 2: Runtime Stage using scratch
FROM scratch

# Copy necessary files for runtime
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /tmp/sdns /sdns

# Expose necessary ports
EXPOSE 53/tcp
EXPOSE 53/udp
EXPOSE 853
EXPOSE 8053
EXPOSE 8080

# Set the entrypoint to run the binary
ENTRYPOINT ["/sdns"]
