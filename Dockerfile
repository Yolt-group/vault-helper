FROM alpine:3.15.0
COPY vault-helper /usr/local/bin/vault-helper
RUN apk add --no-cache --update ca-certificates && update-ca-certificates
ENTRYPOINT ["/usr/local/bin/vault-helper"]
