FROM golang:1.16-alpine AS Builder
WORKDIR /app
COPY . .
RUN go env -w GO111MODULE=on && \
    go env -w GOPROXY=https://mirrors.aliyun.com/goproxy/,direct && \
    go mod download
ARG VERSION=1.1.0
RUN apk add upx
RUN go build -o dnsmasq -ldflags "-w -s -X main.Version=${VERSION}" -tags="netgo" -trimpath cmd/dnsmasq/main.go
RUN upx -9 -o dnsmasq.min dnsmasq

FROM scratch
COPY --from=Builder /app/dnsmasq.min /bin/dnsmasq
ENV DNSMASQ_LISTEN=0.0.0.0:53
EXPOSE 53 53/udp
CMD ["/bin/dnsmasq"]