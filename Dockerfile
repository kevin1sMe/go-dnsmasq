FROM golang:1.16-alpine
ENV TARGET_DIR github.com/soulteary/go-dnsmasq
WORKDIR /go/src/${TARGET_DIR}
COPY . .
ENV DNSMASQ_LISTEN=0.0.0.0
EXPOSE 53 53/udp
