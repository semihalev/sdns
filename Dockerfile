FROM golang:alpine@sha256:a76f153cff6a59112777c071b0cde1b6e4691ddc7f172be424228da1bfb7bbda AS builder

COPY . /go/src/github.com/semihalev/sdns/

WORKDIR /go/src/github.com/semihalev/sdns
RUN apk --no-cache add \
	ca-certificates \
	gcc \
	binutils-gold \
	git \
	musl-dev

RUN go build -ldflags "-linkmode external -extldflags -static -s -w" -o /tmp/sdns \
	&& strip --strip-all /tmp/sdns

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /tmp/sdns /sdns

EXPOSE 53/tcp
EXPOSE 53/udp
EXPOSE 853
EXPOSE 8053
EXPOSE 8080

ENTRYPOINT ["/sdns"]
