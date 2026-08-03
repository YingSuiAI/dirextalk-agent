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
RUN mkdir -p /out/pi-runtime \
    && wget -q -T 60 \
        -O /tmp/pi-linux-x64.tar.gz \
        https://github.com/earendil-works/pi/releases/download/v0.83.0/pi-linux-x64.tar.gz \
    && printf '%s  %s\n' \
        b0625eb623197b0afe20c870d21ef2f34481f1504e5777df3f698a66c7636f5f \
        /tmp/pi-linux-x64.tar.gz \
        | sha256sum -c - \
    && tar -xzf /tmp/pi-linux-x64.tar.gz \
        -C /out/pi-runtime \
        --strip-components 1 \
        pi/pi \
        pi/package.json \
        pi/photon_rs_bg.wasm \
        pi/theme/dark.json \
        pi/theme/light.json \
        pi/theme/theme-schema.json \
    && printf '%s  %s\n' \
        c25c16162b62eda32deb0d544bcae5e5d6c6148958e17130e6aed2d115104f1a \
        /out/pi-runtime/pi \
        | sha256sum -c - \
    && printf '%s  %s\n' \
        e02deae1cec07035807436c1864c88342e2f7d49050d03b858a3719f0c7aedbf \
        /out/pi-runtime/package.json \
        | sha256sum -c - \
    && printf '%s  %s\n' \
        10468181565c56004c867f3a4af96f89a0ef5a63a72f2b5fb12c1f1992a3615c \
        /out/pi-runtime/photon_rs_bg.wasm \
        | sha256sum -c - \
    && printf '%s  %s\n' \
        d3e86b44313cc77abb26b3245857290bdec12a2d1f91ec4b8a30ca1d90aea328 \
        /out/pi-runtime/theme/dark.json \
        | sha256sum -c - \
    && printf '%s  %s\n' \
        97321584a745e75113f08dd1b751bc2a70da28f132b242f1ae5c23816c5e10bc \
        /out/pi-runtime/theme/light.json \
        | sha256sum -c - \
    && printf '%s  %s\n' \
        51839872e9cca2ed8804a040b6222a10d0fd5bf6f241b5a4b2824fbb98f3abd1 \
        /out/pi-runtime/theme/theme-schema.json \
        | sha256sum -c - \
    && rm -f /tmp/pi-linux-x64.tar.gz \
    && chmod 0555 /out/pi-runtime/pi \
    && chmod 0444 /out/pi-runtime/package.json \
    && chmod 0444 /out/pi-runtime/photon_rs_bg.wasm \
    && chmod 0444 /out/pi-runtime/theme/*.json
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
    && chmod 0444 /out/dirextalk-worker-installer.sha256 \
    && mkdir -p /out/worker-rootfs-dirs/etc/ssl/certs \
        /out/worker-rootfs-dirs/etc/dirextalk-worker \
        /out/worker-rootfs-dirs/opt/dirextalk-worker/runtime-contexts \
        /out/worker-rootfs-dirs/opt/dirextalk-worker/runtimes/pi/bin \
        /out/worker-rootfs-dirs/opt/dirextalk-worker/runtimes/pi/bin/theme \
        /out/worker-rootfs-dirs/opt/dirextalk-worker/runtimes/pi/extensions \
        /out/worker-rootfs-dirs/usr/local/bin \
        /out/worker-rootfs-dirs/usr/local/share/dirextalk-worker/ami \
        /out/worker-rootfs-dirs/var/lib/dirextalk-worker

FROM scratch
ARG VERSION
ARG REVISION
LABEL org.opencontainers.image.title="Dirextalk Cloud Worker" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION"
COPY --from=build --chmod=0755 /out/worker-rootfs-dirs/ /
COPY --from=build --chmod=0444 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chmod=0555 /out/pi-runtime/pi /opt/dirextalk-worker/runtimes/pi/bin/pi
COPY --from=build --chmod=0444 /out/pi-runtime/package.json /opt/dirextalk-worker/runtimes/pi/bin/package.json
COPY --from=build --chmod=0444 /out/pi-runtime/photon_rs_bg.wasm /opt/dirextalk-worker/runtimes/pi/bin/photon_rs_bg.wasm
COPY --from=build --chmod=0444 /out/pi-runtime/theme/dark.json /opt/dirextalk-worker/runtimes/pi/bin/theme/dark.json
COPY --from=build --chmod=0444 /out/pi-runtime/theme/light.json /opt/dirextalk-worker/runtimes/pi/bin/theme/light.json
COPY --from=build --chmod=0444 /out/pi-runtime/theme/theme-schema.json /opt/dirextalk-worker/runtimes/pi/bin/theme/theme-schema.json
COPY --chmod=0444 deploy/container/pi-worker/dirextalk-result.ts /opt/dirextalk-worker/runtimes/pi/extensions/dirextalk-result.ts
COPY --chmod=0444 deploy/container/pi-worker/runtime-installation.json /etc/dirextalk-worker/runtime-installation.json
COPY --chmod=0444 deploy/container/pi-worker/runtime.env /etc/dirextalk-worker/runtime.env
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
