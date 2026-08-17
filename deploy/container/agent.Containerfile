# Reproducible Agent runtime image. Keep the build input digest-pinned and pass
# VERSION/REVISION from the release job; no source or dependency is fetched at
# runtime. Runner services select explicit entrypoints from this same image;
# Compose still supplies their UID, network, mount, and cgroup boundaries.
FROM --platform=linux/amd64 docker.io/library/node:24.18.1-alpine3.23@sha256:ba63d8e0b5d4cbc6db9da12ea77ddb35a4783ad653a092ef115cc383526d4369 AS node_runtime

FROM --platform=linux/amd64 docker.io/library/alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40 AS ssh_runtime
RUN apk add --no-cache openssh-client-default

FROM --platform=linux/amd64 docker.io/library/golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build
WORKDIR /src
ARG GOPROXY=https://proxy.golang.org,direct
ARG VERSION=dev
RUN apk add --no-cache busybox-static ca-certificates
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    AGENT_EXPECT_RELEASE_VERSION="$VERSION" go test -run '^TestInjectedReleaseVersion$' -ldflags="-X github.com/YingSuiAI/dirextalk-agent/internal/buildinfo.ReleaseVersion=$VERSION" ./internal/buildinfo \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags netgo,osusergo -ldflags="-s -w -buildid= -X github.com/YingSuiAI/dirextalk-agent/internal/buildinfo.ReleaseVersion=$VERSION" -o /out/usr/local/bin/dirextalk-agent ./cmd/dirextalk-agent \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags netgo,osusergo -ldflags="-s -w -buildid= -X github.com/YingSuiAI/dirextalk-agent/internal/buildinfo.ReleaseVersion=$VERSION" -o /out/usr/local/bin/dirextalk-extension-runner ./cmd/dirextalk-extension-runner \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags netgo,osusergo -ldflags="-s -w -buildid= -X github.com/YingSuiAI/dirextalk-agent/internal/buildinfo.ReleaseVersion=$VERSION" -o /out/usr/local/bin/dirextalk-core-runner ./cmd/dirextalk-core-runner
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags netgo,osusergo -ldflags="-s -w -buildid= -X github.com/YingSuiAI/dirextalk-agent/internal/buildinfo.ReleaseVersion=$VERSION" -o /out/usr/local/libexec/dirextalk-builtin-mcp ./cmd/dirextalk-builtin-mcp
RUN install -d -m 0755 /out/etc/ssl/certs /out/etc/dirextalk-agent /out/var/lib/dirextalk-agent \
    && install -d -m 0700 -o 65532 -g 65532 /out/var/lib/dirextalk-agent/extension-staging \
    && install -d -m 0770 -o 65531 -g 65532 /out/var/lib/dirextalk-agent/extension-workspaces \
    && install -d -m 0770 -o 65531 -g 65532 /out/run/dirextalk-agent \
    && install -d -m 0700 -o 65531 -g 65531 /out/var/lib/dirextalk-agent/extension-install /out/var/lib/dirextalk-agent/extension-state \
    && install -D -m 0555 -o 65530 -g 65530 /bin/busybox.static /out/usr/local/libexec/dirextalk-core-shell \
    && install -d -m 0700 -o 65530 -g 65530 /out/var/lib/dirextalk-core-runner/installs /out/var/lib/dirextalk-core-runner/workspaces /out/var/lib/dirextalk-core-runner/state \
    && install -d -m 0755 /out/cgroup \
    && install -d -m 1777 /out/tmp \
    && printf '%s\n' 'agent:x:65532:65532:Dirextalk Agent:/var/lib/dirextalk-agent:/sbin/nologin' > /out/etc/passwd \
    && printf '%s\n' 'agent:x:65532:' > /out/etc/group \
    && cp /etc/ssl/certs/ca-certificates.crt /out/etc/ssl/certs/ca-certificates.crt
COPY --from=node_runtime /usr/local/bin/node /out/usr/local/libexec/dirextalk-node-runtime/usr/local/bin/node
COPY --from=node_runtime /usr/local/lib/node_modules/npm /out/usr/local/libexec/dirextalk-node-runtime/usr/local/lib/node_modules/npm
COPY --from=node_runtime /lib/ld-musl-x86_64.so.1 /out/usr/local/libexec/dirextalk-node-runtime/lib/ld-musl-x86_64.so.1
COPY --from=node_runtime /usr/lib/libstdc++.so.6 /out/usr/local/libexec/dirextalk-node-runtime/usr/lib/libstdc++.so.6
COPY --from=node_runtime /usr/lib/libgcc_s.so.1 /out/usr/local/libexec/dirextalk-node-runtime/usr/lib/libgcc_s.so.1
COPY --from=ssh_runtime /usr/bin/ssh /out/usr/bin/ssh
COPY --from=ssh_runtime /lib/ld-musl-x86_64.so.1 /out/lib/ld-musl-x86_64.so.1
COPY --from=ssh_runtime /usr/lib/libcrypto.so.3 /out/usr/lib/libcrypto.so.3
COPY --from=ssh_runtime /usr/lib/libz.so.1 /out/usr/lib/libz.so.1
COPY --from=ssh_runtime /etc/ssh/ssh_config /out/etc/ssh/ssh_config
COPY --from=ssh_runtime /etc/ssh/ssh_config.d /out/etc/ssh/ssh_config.d
RUN chmod -R a-w /out/usr/local/libexec/dirextalk-node-runtime

FROM scratch
ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_TIME=
LABEL org.opencontainers.image.title="Dirextalk Agent" \
      org.opencontainers.image.description="Private single-user Dirextalk Agent runtime" \
      org.opencontainers.image.source="https://github.com/YingSuiAI/dirextalk-agent" \
      org.opencontainers.image.vendor="YingSuiAI" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.created="$BUILD_TIME"
COPY --from=build /out/ /
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
USER 65532:65532
WORKDIR /var/lib/dirextalk-agent
EXPOSE 9443
ENTRYPOINT ["/usr/local/bin/dirextalk-agent"]
CMD ["serve"]
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=4 CMD ["/usr/local/bin/dirextalk-agent", "healthcheck"]
