# The manager is cross-compiled on the build machine; only the final stage runs per architecture.
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY manager/ ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/sneaky .

# Home Assistant reads these labels from the image; its arch names differ from Docker's.
FROM alpine:3.22 AS runtime-amd64
LABEL io.hass.arch="amd64"
FROM alpine:3.22 AS runtime-arm64
LABEL io.hass.arch="aarch64"

FROM runtime-${TARGETARCH}
ARG BUILD_VERSION=dev
LABEL io.hass.type="addon" \
      io.hass.version="${BUILD_VERSION}" \
      io.hass.name="sneakytorrents" \
      io.hass.description="qBittorrent with all of its traffic locked to a VPN"
RUN apk add --no-cache \
      ca-certificates \
      iproute2 \
      nftables \
      openvpn \
      qbittorrent-nox \
      setpriv \
      tini \
      tzdata \
      wireguard-go \
      wireguard-tools-wg
COPY --from=build /out/sneaky /usr/local/bin/sneaky

ENV PUID=1000 \
    PGID=1000 \
    WEBUI_PORT=8080 \
    TZ=UTC

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
  CMD wget -q -O /dev/null "http://127.0.0.1:${WEBUI_PORT}/vpn/healthz" || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/sneaky"]
