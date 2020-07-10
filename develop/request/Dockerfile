FROM alpine:latest
RUN apk update && apk add curl bind-tools
COPY docker-entrypoint.sh /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]