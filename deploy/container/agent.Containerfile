# syntax=docker/dockerfile:1.7

FROM --platform=linux/amd64 docker.io/library/golang:1.26.0-alpine@sha256:7c6a62c80c3f15fb49aae282d7a296149889ebe39b2318f3a299f2759c1ce135 AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION
ARG REVISION
WORKDIR /src

RUN apk add --no-cache ca-certificates \
    && printf '%s' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+-(alpha|beta|rc)([.-][A-Za-z0-9][A-Za-z0-9.-]*)?-[0-9a-f]{7,40}$' \
    && printf '%s' "$REVISION" | grep -Eq '^[0-9a-f]{40}$' \
    && test "$VERSION" != 'v1.0.3'
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -tags netgo,osusergo -ldflags='-s -w -buildid=' \
    -o /out/usr/local/bin/dirextalk-agent ./cmd/dirextalk-agent
RUN install -d -m 0755 /out/etc/ssl/certs \
    && install -d -m 1777 /out/tmp \
    && cp /etc/ssl/certs/ca-certificates.crt /out/etc/ssl/certs/ca-certificates.crt

FROM scratch
ARG VERSION
ARG REVISION
LABEL org.opencontainers.image.title="Dirextalk Agent" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION"
COPY --from=build /out/ /
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
USER 65532:65532
EXPOSE 9443
ENTRYPOINT ["/usr/local/bin/dirextalk-agent"]
CMD ["serve"]
