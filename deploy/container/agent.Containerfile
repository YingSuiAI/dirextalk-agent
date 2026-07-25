# Reproducible Core image. Keep the build input digest-pinned and pass VERSION
# VERSION/REVISION from the release job; no source or dependency is fetched at runtime.
FROM --platform=linux/amd64 docker.io/library/golang:1.26.0-alpine@sha256:7c6a62c80c3f15fb49aae282d7a296149889ebe39b2318f3a299f2759c1ce135 AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags netgo,osusergo -ldflags='-s -w -buildid=' -o /out/usr/local/bin/dirextalk-agent ./cmd/dirextalk-agent
RUN install -d -m 0755 /out/etc/ssl/certs /out/etc/dirextalk-agent /out/var/lib/dirextalk-agent \
    && install -d -m 0700 -o 65532 -g 65532 /out/var/lib/dirextalk-agent/extension-staging /out/var/lib/dirextalk-agent/extension-workspaces \
    && install -d -m 1777 /out/tmp \
    && cp /etc/ssl/certs/ca-certificates.crt /out/etc/ssl/certs/ca-certificates.crt

FROM scratch
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="Dirextalk Agent Core" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION"
COPY --from=build /out/ /
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
USER 65532:65532
WORKDIR /var/lib/dirextalk-agent
EXPOSE 9443
ENTRYPOINT ["/usr/local/bin/dirextalk-agent"]
CMD ["serve"]
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=4 CMD ["/usr/local/bin/dirextalk-agent", "healthcheck"]
