FROM golang:1.11.1-alpine3.8

RUN mkdir -p /etc/sdns
RUN apk add --no-cache ca-certificates \
        gcc \
        git \
        bash
        
COPY sdns.toml /etc/sdns

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
RUN go get -v github.com/semihalev/sdns
WORKDIR $GOPATH

EXPOSE 53/tcp
EXPOSE 53/udp
EXPOSE 853/tcp
EXPOSE 8080/tcp

ENTRYPOINT ["sdns","-config","/etc/sdns/sdns.toml"]