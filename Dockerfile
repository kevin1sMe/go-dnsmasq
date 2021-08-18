FROM golang:1.14
ENV TARGET_DIR github.com/tomoyamachi/go-dnsmasq
WORKDIR /go/src/${TARGET_DIR}
COPY . .
ENV DNSMASQ_LISTEN=0.0.0.0
EXPOSE 53 53/udp
