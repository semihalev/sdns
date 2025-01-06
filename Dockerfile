# Stage 1: Build Stage
FROM alpine:latest AS builder

# Build dependencies
RUN apk add --no-cache \
    ca-certificates \
    gcc \
    git \
    musl-dev \
    upx \
    curl

# Define architecture as a build argument
ARG TARGETARCH
ENV GO_ARCH=${TARGETARCH}

# Install Go sesuai arsitektur
RUN curl -sSL https://golang.org/dl/go1.23.4.linux-${GO_ARCH}.tar.gz | tar -C /usr/local -xz && \
    ln -s /usr/local/go/bin/go /usr/bin/go

# Set working directory
WORKDIR /src

# Copy module files dan download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy semua kode sumber
COPY . .

# Build binary
RUN CGO_ENABLED=0 GOARCH=${GO_ARCH} go build -trimpath -ldflags="-s -w" -o /tmp/sdns && \
    strip /tmp/sdns && \
    upx --ultra-brute /tmp/sdns

# Stage 2: Runtime Stage
FROM scratch

# Copy binary dan SSL certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /tmp/sdns /sdns

# Expose port
EXPOSE 53/tcp
EXPOSE 53/udp
EXPOSE 853
EXPOSE 8053
EXPOSE 8080

# Jalankan aplikasi
ENTRYPOINT ["/sdns"]
