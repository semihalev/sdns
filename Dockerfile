ARG image=golang:1.11-alpine3.8

FROM $image AS builder

COPY . /go/src/github.com/semihalev/sdns/

WORKDIR /go/src/github.com/semihalev/sdns

RUN apk --update --no-cache add \
	ca-certificates \
	gcc \
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