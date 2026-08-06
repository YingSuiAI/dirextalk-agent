# syntax=docker/dockerfile:1.7
# Official Agent Core v1 Team Pi Worker release. This image contains no AWS
# provisioning, AMI construction, installer, pairing, or maintenance control.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build

ARG VERSION
ARG REVISION
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .

RUN test "$TARGETOS" = linux \
    && test "$TARGETARCH" = amd64 \
    && test -n "$VERSION" \
    && printf '%s' "$REVISION" | grep -Eq '^[0-9a-f]{40}$' \
    && printf '%s  %s\n' \
        39e98a6a8339a48c0b1609ff7aed3c7af0807ee9e2cb4a975b64e46a2e5f94d9 \
        deploy/container/pi-worker/dirextalk-result.ts \
        | sha256sum -c -

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
    && rm -f /tmp/pi-linux-x64.tar.gz

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    install -d -m 0755 \
        /out/usr/local/bin \
        /out/usr/local/share/dirextalk-worker \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -tags netgo,osusergo -ldflags='-s -w -buildid=' \
        -o /out/usr/local/bin/dirextalk-cloud-worker \
        ./cmd/dirextalk-cloud-worker \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -tags netgo,osusergo -ldflags='-s -w -buildid=' -o /out/usr/local/bin/dirextalk-pi-sandbox ./cmd/dirextalk-pi-sandbox \
    && worker_sha="$(sha256sum /out/usr/local/bin/dirextalk-cloud-worker | awk '{print $1}')" \
    && sandbox_sha="$(sha256sum /out/usr/local/bin/dirextalk-pi-sandbox | awk '{print $1}')" \
    && printf '%s  %s\n' "$worker_sha" /out/usr/local/bin/dirextalk-cloud-worker \
        | sha256sum -c - \
    && printf '%s  %s\n' "$worker_sha" /usr/local/bin/dirextalk-cloud-worker \
        > /out/usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256 \
    && printf '%s  %s\n' "$sandbox_sha" /usr/local/bin/dirextalk-pi-sandbox \
        > /out/usr/local/share/dirextalk-worker/dirextalk-pi-sandbox.sha256

RUN install -d -m 0755 \
        /out/etc/ssl/certs \
        /out/opt/dirextalk-worker/runtimes/pi/bin/theme \
        /out/opt/dirextalk-worker/runtimes/pi/extensions \
        /out/usr/lib/sysusers.d \
        /out/usr/lib/tmpfiles.d \
        /out/usr/local/lib/systemd/system \
    && install -m 0444 /etc/ssl/certs/ca-certificates.crt \
        /out/etc/ssl/certs/ca-certificates.crt \
    && install -m 0555 /out/pi-runtime/pi \
        /out/opt/dirextalk-worker/runtimes/pi/bin/pi \
    && install -m 0444 /out/pi-runtime/package.json \
        /out/opt/dirextalk-worker/runtimes/pi/bin/package.json \
    && install -m 0444 /out/pi-runtime/photon_rs_bg.wasm \
        /out/opt/dirextalk-worker/runtimes/pi/bin/photon_rs_bg.wasm \
    && install -m 0444 /out/pi-runtime/theme/dark.json \
        /out/opt/dirextalk-worker/runtimes/pi/bin/theme/dark.json \
    && install -m 0444 /out/pi-runtime/theme/light.json \
        /out/opt/dirextalk-worker/runtimes/pi/bin/theme/light.json \
    && install -m 0444 /out/pi-runtime/theme/theme-schema.json \
        /out/opt/dirextalk-worker/runtimes/pi/bin/theme/theme-schema.json \
    && install -m 0444 deploy/container/pi-worker/dirextalk-result.ts \
        /out/opt/dirextalk-worker/runtimes/pi/extensions/dirextalk-result.ts \
    && install -m 0444 deploy/container/pi-worker/dirextalk-cloud-worker.service \
        /out/usr/local/lib/systemd/system/dirextalk-cloud-worker.service \
    && printf '%s\n' \
        'g dirextalk-worker 65532 -' \
        'u dirextalk-worker 65532:65532 "Dirextalk Team Worker" /var/lib/dirextalk-worker /usr/sbin/nologin' \
        'u dirextalk-pi 65533:65532 "Dirextalk Pi Runtime" /var/lib/dirextalk-worker /usr/sbin/nologin' \
        > /out/usr/lib/sysusers.d/dirextalk-worker.conf \
    && printf '%s\n' \
        'd /var/lib/dirextalk-worker 0770 65532 65532 -' \
        'd /var/lib/dirextalk-worker/receipts 0700 65532 65532 -' \
        'd /var/lib/dirextalk-worker/runtime-state 0770 65532 65532 -' \
        'd /var/lib/dirextalk-worker/tmp 0770 65532 65532 -' \
        'd /var/lib/dirextalk-worker/workspaces 0770 65532 65532 -' \
        'd /run/dirextalk-worker 0700 65532 65532 -' \
        'd /run/dirextalk-worker/secrets 0700 65532 65532 -' \
        > /out/usr/lib/tmpfiles.d/dirextalk-worker.conf \
    && printf '%s\n' \
        '{"version":"0.83.0","archive_digest":"sha256:b0625eb623197b0afe20c870d21ef2f34481f1504e5777df3f698a66c7636f5f","executable_digest":"sha256:c25c16162b62eda32deb0d544bcae5e5d6c6148958e17130e6aed2d115104f1a","package_json_digest":"sha256:e02deae1cec07035807436c1864c88342e2f7d49050d03b858a3719f0c7aedbf","photon_wasm_digest":"sha256:10468181565c56004c867f3a4af96f89a0ef5a63a72f2b5fb12c1f1992a3615c","dark_theme_digest":"sha256:d3e86b44313cc77abb26b3245857290bdec12a2d1f91ec4b8a30ca1d90aea328","light_theme_digest":"sha256:97321584a745e75113f08dd1b751bc2a70da28f132b242f1ae5c23816c5e10bc","theme_schema_digest":"sha256:51839872e9cca2ed8804a040b6222a10d0fd5bf6f241b5a4b2824fbb98f3abd1","result_extension_digest":"sha256:39e98a6a8339a48c0b1609ff7aed3c7af0807ee9e2cb4a975b64e46a2e5f94d9"}' \
        > /out/usr/local/share/dirextalk-worker/pi-runtime-identity.json \
    && chmod 0555 /out/usr/local/bin/dirextalk-cloud-worker /out/usr/local/bin/dirextalk-pi-sandbox \
    && chmod 0444 /out/usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256 \
        /out/usr/local/share/dirextalk-worker/dirextalk-pi-sandbox.sha256 \
        /out/usr/local/share/dirextalk-worker/pi-runtime-identity.json \
        /out/usr/lib/sysusers.d/dirextalk-worker.conf \
        /out/usr/lib/tmpfiles.d/dirextalk-worker.conf \
    && rm -rf /out/pi-runtime

FROM scratch AS rootfs-export
COPY --from=build /out/ /

FROM --platform=linux/amd64 docker.io/library/debian:bookworm-slim@sha256:362e64223cc0da95422b3b13c045186fc0a81250e765d31c025fbddf257f6143
ARG VERSION
ARG REVISION
LABEL org.opencontainers.image.title="Dirextalk Official Team Pi Worker" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      io.dirextalk.agent-core.runtime="official-pi-0.83.0" \
      io.dirextalk.pi.archive-sha256="b0625eb623197b0afe20c870d21ef2f34481f1504e5777df3f698a66c7636f5f" \
      io.dirextalk.pi.executable-sha256="c25c16162b62eda32deb0d544bcae5e5d6c6148958e17130e6aed2d115104f1a" \
      io.dirextalk.pi.result-extension-sha256="39e98a6a8339a48c0b1609ff7aed3c7af0807ee9e2cb4a975b64e46a2e5f94d9"

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        git=1:2.39.5-0+deb12u3 \
        ca-certificates=20230311+deb12u1 \
        libcap2-bin=1:2.66-4+deb12u3+b1 \
    && test -x /bin/bash \
    && test -x /usr/bin/git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/ /

RUN install -d -m 0770 -o 65532 -g 65532 \
        /var/lib/dirextalk-worker \
        /var/lib/dirextalk-worker/runtime-state \
        /var/lib/dirextalk-worker/workspaces \
        /var/lib/dirextalk-worker/tmp \
    && install -d -m 0700 -o 65532 -g 65532 \
        /var/lib/dirextalk-worker/receipts \
        /run/dirextalk-worker/secrets \
    && setcap cap_kill,cap_setgid,cap_setuid=ep /usr/local/bin/dirextalk-cloud-worker \
    && getcap /usr/local/bin/dirextalk-cloud-worker \
        | grep -Fx '/usr/local/bin/dirextalk-cloud-worker cap_kill,cap_setgid,cap_setuid=ep'

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    HOME=/var/lib/dirextalk-worker \
    TMPDIR=/var/lib/dirextalk-worker/tmp \
    DIREXTALK_PI_VERSION=0.83.0 \
    DIREXTALK_PI_EXECUTABLE=/opt/dirextalk-worker/runtimes/pi/bin/pi \
    DIREXTALK_PI_EXECUTABLE_SHA256=c25c16162b62eda32deb0d544bcae5e5d6c6148958e17130e6aed2d115104f1a \
    DIREXTALK_PI_EXTENSION=/opt/dirextalk-worker/runtimes/pi/extensions/dirextalk-result.ts \
    DIREXTALK_PI_EXTENSION_SHA256=39e98a6a8339a48c0b1609ff7aed3c7af0807ee9e2cb4a975b64e46a2e5f94d9 \
    DIREXTALK_PI_STATE_ROOT=/var/lib/dirextalk-worker/runtime-state \
    DIREXTALK_PI_SEARCH_PATH=/usr/bin:/bin \
    DIREXTALK_PI_SANDBOX=/usr/local/bin/dirextalk-pi-sandbox \
    DIREXTALK_PI_SANDBOX_SHA256_FILE=/usr/local/share/dirextalk-worker/dirextalk-pi-sandbox.sha256 \
    DIREXTALK_WORKER_RECEIPT_ROOT=/var/lib/dirextalk-worker/receipts \
    DIREXTALK_WORKER_SECRET_ROOT=/run/dirextalk-worker/secrets \
    DIREXTALK_WORKER_BINARY_SHA256_FILE=/usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256

USER 65532:65532
WORKDIR /var/lib/dirextalk-worker
ENTRYPOINT ["/usr/local/bin/dirextalk-cloud-worker"]
