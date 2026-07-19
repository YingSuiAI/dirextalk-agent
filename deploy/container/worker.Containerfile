ARG GO_BUILD_BASE
FROM --platform=linux/amd64 ${GO_BUILD_BASE} AS build
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
    -o /out/dirextalk-cloud-worker ./cmd/dirextalk-cloud-worker \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -tags netgo,osusergo -ldflags='-s -w -buildid=' \
    -o /out/dirextalk-worker-installer ./cmd/dirextalk-worker-installer \
    && sha256sum /out/dirextalk-cloud-worker | awk '{print $1}' > /out/dirextalk-cloud-worker.sha256 \
    && sha256sum /out/dirextalk-worker-installer | awk '{print $1}' > /out/dirextalk-worker-installer.sha256 \
    && chmod 0555 /out/dirextalk-cloud-worker \
    && chmod 0555 /out/dirextalk-worker-installer \
    && chmod 0444 /out/dirextalk-cloud-worker.sha256 \
    && chmod 0444 /out/dirextalk-worker-installer.sha256

FROM scratch
ARG VERSION
ARG REVISION
LABEL org.opencontainers.image.title="Dirextalk Cloud Worker" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION"
COPY --from=build --chmod=0444 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chmod=0555 /out/dirextalk-cloud-worker /usr/local/bin/dirextalk-cloud-worker
COPY --from=build --chmod=0555 /out/dirextalk-worker-installer /usr/local/bin/dirextalk-worker-installer
COPY --from=build --chmod=0444 /out/dirextalk-cloud-worker.sha256 /usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256
COPY --from=build --chmod=0444 /out/dirextalk-worker-installer.sha256 /usr/local/share/dirextalk-worker/dirextalk-worker-installer.sha256
COPY --chmod=0444 deploy/container/worker-ami/dirextalk-cloud-worker.service /usr/local/share/dirextalk-worker/ami/dirextalk-cloud-worker.service
COPY --chmod=0444 deploy/container/worker-ami/dirextalk-worker-installer.service /usr/local/share/dirextalk-worker/ami/dirextalk-worker-installer.service
COPY --chmod=0444 deploy/container/worker-ami/dirextalk-worker-installer-bootstrap.service /usr/local/share/dirextalk-worker/ami/dirextalk-worker-installer-bootstrap.service
COPY --chmod=0444 deploy/container/worker-ami/dirextalk-worker-installer.socket /usr/local/share/dirextalk-worker/ami/dirextalk-worker-installer.socket
COPY --chmod=0444 deploy/container/worker-ami/dirextalk-worker.sysusers /usr/local/share/dirextalk-worker/ami/dirextalk-worker.sysusers
COPY --chmod=0444 deploy/container/worker-ami/dirextalk-worker.tmpfiles /usr/local/share/dirextalk-worker/ami/dirextalk-worker.tmpfiles
COPY --chmod=0444 deploy/container/worker-ami/dirextalk-installer.tmpfiles /usr/local/share/dirextalk-worker/ami/dirextalk-installer.tmpfiles
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV DIREXTALK_WORKER_BINARY_SHA256_FILE=/usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256
WORKDIR /var/lib/dirextalk-worker
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/dirextalk-cloud-worker"]
