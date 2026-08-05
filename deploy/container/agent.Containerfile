# Reproducible Agent runtime image. Keep the build input digest-pinned and pass
# VERSION/REVISION from the release job; no source or dependency is fetched at
# runtime. Runner services select explicit entrypoints from this same image;
# Compose still supplies their UID, network, mount, and cgroup boundaries.
FROM --platform=linux/amd64 docker.io/library/golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
ARG GOPROXY=https://proxy.golang.org,direct
RUN apk add --no-cache busybox-static ca-certificates
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags netgo,osusergo -ldflags='-s -w -buildid=' -o /out/usr/local/bin/dirextalk-agent ./cmd/dirextalk-agent \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags netgo,osusergo -ldflags='-s -w -buildid=' -o /out/usr/local/bin/dirextalk-extension-runner ./cmd/dirextalk-extension-runner \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags netgo,osusergo -ldflags='-s -w -buildid=' -o /out/usr/local/bin/dirextalk-core-runner ./cmd/dirextalk-core-runner
RUN install -d -m 0755 /out/etc/ssl/certs /out/etc/dirextalk-agent /out/var/lib/dirextalk-agent \
    && install -d -m 0700 -o 65532 -g 65532 /out/var/lib/dirextalk-agent/extension-staging \
    && install -d -m 0770 -o 65531 -g 65532 /out/var/lib/dirextalk-agent/extension-workspaces \
    && install -d -m 0770 -o 65531 -g 65532 /out/run/dirextalk-agent \
    && install -d -m 0700 -o 65531 -g 65531 /out/var/lib/dirextalk-agent/extension-install /out/var/lib/dirextalk-agent/extension-state \
    && install -D -m 0555 -o 65530 -g 65530 /bin/busybox.static /out/usr/local/libexec/dirextalk-core-shell \
    && install -d -m 0700 -o 65530 -g 65530 /out/var/lib/dirextalk-core-runner/installs /out/var/lib/dirextalk-core-runner/workspaces /out/var/lib/dirextalk-core-runner/state \
    && install -d -m 0755 /out/cgroup \
    && install -d -m 1777 /out/tmp \
    && cp /etc/ssl/certs/ca-certificates.crt /out/etc/ssl/certs/ca-certificates.crt

FROM scratch
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="Dirextalk Agent" \
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
