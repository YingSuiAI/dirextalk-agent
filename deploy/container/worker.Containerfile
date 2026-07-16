# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.26.0
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
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
    && sha256sum /out/dirextalk-cloud-worker | awk '{print $1}' > /out/dirextalk-cloud-worker.sha256 \
    && chmod 0555 /out/dirextalk-cloud-worker \
    && chmod 0444 /out/dirextalk-cloud-worker.sha256

FROM scratch
ARG VERSION
ARG REVISION
LABEL org.opencontainers.image.title="Dirextalk Cloud Worker" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION"
COPY --from=build --chmod=0444 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chmod=0555 /out/dirextalk-cloud-worker /usr/local/bin/dirextalk-cloud-worker
COPY --from=build --chmod=0444 /out/dirextalk-cloud-worker.sha256 /usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256
COPY --chmod=0444 deploy/container/worker-ami/dirextalk-cloud-worker.service /usr/local/share/dirextalk-worker/ami/dirextalk-cloud-worker.service
COPY --chmod=0444 deploy/container/worker-ami/dirextalk-worker.sysusers /usr/local/share/dirextalk-worker/ami/dirextalk-worker.sysusers
COPY --chmod=0444 deploy/container/worker-ami/dirextalk-worker.tmpfiles /usr/local/share/dirextalk-worker/ami/dirextalk-worker.tmpfiles
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV DIREXTALK_WORKER_BINARY_SHA256_FILE=/usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256
WORKDIR /var/lib/dirextalk-worker
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/dirextalk-cloud-worker"]
