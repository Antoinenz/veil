# Build the veil-server binary.
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
# (no external deps yet; go.sum added when they appear)
RUN go mod download || true
COPY . .
ARG VERSION=0.0.0-dev
ARG COMMIT=unknown
RUN CGO_ENABLED=0 go build \
      -ldflags "-s -w -X github.com/veilvpn/veil/internal/buildinfo.Version=${VERSION} -X github.com/veilvpn/veil/internal/buildinfo.Commit=${COMMIT}" \
      -o /out/veil-server ./cmd/veil-server

FROM alpine:3.20
RUN apk add --no-cache iptables ca-certificates
COPY --from=build /out/veil-server /usr/local/bin/veil-server
VOLUME ["/var/lib/veil"]
# 443/tcp: TLS + WSS + control plane; 443/udp: UDP data-plane transport.
EXPOSE 443/tcp 443/udp
ENTRYPOINT ["veil-server"]
CMD ["run", "--config", "/var/lib/veil/server.json"]
