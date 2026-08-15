ARG GO_BUILD_BASE
FROM --platform=linux/amd64 ${GO_BUILD_BASE} AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG AMI_DIGEST
ARG PI_VERSION=0.83.0
ARG PI_ARCHIVE_SHA256=b0625eb623197b0afe20c870d21ef2f34481f1504e5777df3f698a66c7636f5f
ARG PI_EXECUTABLE_SHA256=c25c16162b62eda32deb0d544bcae5e5d6c6148958e17130e6aed2d115104f1a

WORKDIR /src

RUN apk add --no-cache ca-certificates \
    && printf '%s' "$AMI_DIGEST" | grep -Eq '^[a-f0-9]{64}$' \
    && printf '%s' "$PI_VERSION" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$' \
    && printf '%s' "$PI_ARCHIVE_SHA256" | grep -Eq '^[a-f0-9]{64}$' \
    && printf '%s' "$PI_EXECUTABLE_SHA256" | grep -Eq '^[a-f0-9]{64}$'

RUN mkdir -p /out/pi \
    && wget -q -T 60 \
        -O /tmp/pi-linux-x64.tar.gz \
        "https://github.com/earendil-works/pi/releases/download/v${PI_VERSION}/pi-linux-x64.tar.gz" \
    && printf '%s  %s\n' "$PI_ARCHIVE_SHA256" /tmp/pi-linux-x64.tar.gz | sha256sum -c - \
    && tar -xzf /tmp/pi-linux-x64.tar.gz \
        -C /out/pi \
        --strip-components 1 \
        pi/pi \
        pi/package.json \
        pi/photon_rs_bg.wasm \
        pi/theme/dark.json \
        pi/theme/light.json \
        pi/theme/theme-schema.json \
    && printf '%s  %s\n' "$PI_EXECUTABLE_SHA256" /out/pi/pi | sha256sum -c - \
    && rm -f /tmp/pi-linux-x64.tar.gz \
    && chmod 0551 /out/pi/pi \
    && chmod 0444 /out/pi/package.json /out/pi/photon_rs_bg.wasm /out/pi/theme/*.json

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -buildvcs=false -trimpath -tags netgo,osusergo \
        -ldflags='-s -w -buildid=' \
        -o /out/dirextalk-cloud-worker ./cmd/dirextalk-cloud-worker \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -buildvcs=false -trimpath -tags netgo,osusergo \
        -ldflags='-s -w -buildid=' \
        -o /out/dirextalk-cloud-worker-exec-gate ./cmd/dirextalk-cloud-worker-exec-gate \
    && chmod 0555 /out/dirextalk-cloud-worker /out/dirextalk-cloud-worker-exec-gate

RUN mkdir -p \
        /out/rootfs/usr/local/bin \
        /out/rootfs/usr/local/sbin \
        /out/rootfs/usr/local/lib/dirextalk-cloud-worker/pi/theme \
        /out/rootfs/usr/local/share/dirextalk-cloud-worker \
        /out/rootfs/usr/local/lib/systemd/system \
        /out/rootfs/usr/lib/sysusers.d \
    && install -m 0555 /out/dirextalk-cloud-worker /out/rootfs/usr/local/bin/dirextalk-cloud-worker \
    && install -m 0555 /out/dirextalk-cloud-worker-exec-gate /out/rootfs/usr/local/bin/dirextalk-cloud-worker-exec-gate \
    && install -m 0551 -o 0 -g 65531 /out/pi/pi /out/rootfs/usr/local/lib/dirextalk-cloud-worker/pi/pi \
    && install -m 0444 /out/pi/package.json /out/rootfs/usr/local/lib/dirextalk-cloud-worker/pi/package.json \
    && install -m 0444 /out/pi/photon_rs_bg.wasm /out/rootfs/usr/local/lib/dirextalk-cloud-worker/pi/photon_rs_bg.wasm \
    && install -m 0444 /out/pi/theme/*.json /out/rootfs/usr/local/lib/dirextalk-cloud-worker/pi/theme/

COPY --chmod=0444 deploy/cloud-worker/dirextalk-result.ts /out/rootfs/usr/local/lib/dirextalk-cloud-worker/pi/dirextalk-result.ts
COPY --chmod=0444 deploy/cloud-worker/dirextalk-cloud-worker.service /out/rootfs/usr/local/lib/systemd/system/dirextalk-cloud-worker.service
COPY --chmod=0444 deploy/cloud-worker/dirextalk-cloud-worker-exec-gate.service /out/rootfs/usr/local/lib/systemd/system/dirextalk-cloud-worker-exec-gate.service
COPY --chmod=0444 deploy/cloud-worker/dirextalk-cloud-worker-boot-qualification.service /out/rootfs/usr/local/lib/systemd/system/dirextalk-cloud-worker-boot-qualification.service
COPY --chmod=0444 deploy/cloud-worker/dirextalk-cloud-worker-network.service /out/rootfs/usr/local/lib/systemd/system/dirextalk-cloud-worker-network.service
COPY --chmod=0444 deploy/cloud-worker/dirextalk-cloud-worker.sysusers /out/rootfs/usr/lib/sysusers.d/dirextalk-cloud-worker.conf
COPY --chmod=0555 deploy/cloud-worker/qualify-image.sh /out/rootfs/usr/local/sbin/dirextalk-cloud-worker-qualify
COPY --chmod=0444 deploy/cloud-worker/rootfs-files.allowlist /out/rootfs/usr/local/share/dirextalk-cloud-worker/rootfs-files.allowlist
COPY --chmod=0555 deploy/cloud-worker/render-pi-egress-policy.sh /tmp/render-pi-egress-policy.sh
RUN /tmp/render-pi-egress-policy.sh \
        /out/rootfs/usr/local/share/dirextalk-cloud-worker/pi-egress.nft \
    && rm -f /tmp/render-pi-egress-policy.sh

# The private control-plane CA is deployment input, not a repository fixture.
# BuildKit must provide it as: --secret id=dirextalk_control_plane_ca,src=...
RUN --mount=type=secret,id=dirextalk_control_plane_ca,required=true \
    install -m 0440 -o 0 -g 65531 /run/secrets/dirextalk_control_plane_ca \
        /out/rootfs/usr/local/share/dirextalk-cloud-worker/control-plane-ca.pem \
    && grep -q -- '-----BEGIN CERTIFICATE-----' \
        /out/rootfs/usr/local/share/dirextalk-cloud-worker/control-plane-ca.pem

# The controlled outbound proxy uses a separate private trust root. It must
# never become a trust anchor for the inner model, S3, or WorkerControl TLS.
RUN --mount=type=secret,id=dirextalk_outbound_proxy_ca,required=true \
    install -m 0440 -o 0 -g 65531 /run/secrets/dirextalk_outbound_proxy_ca \
        /out/rootfs/usr/local/share/dirextalk-cloud-worker/outbound-proxy-ca.pem \
    && grep -q -- '-----BEGIN CERTIFICATE-----' \
        /out/rootfs/usr/local/share/dirextalk-cloud-worker/outbound-proxy-ca.pem

RUN DTX_WORKER_DIGEST="$(sha256sum /out/rootfs/usr/local/bin/dirextalk-cloud-worker | awk '{print $1}')" \
    && DTX_EXTENSION_DIGEST="$(sha256sum /out/rootfs/usr/local/lib/dirextalk-cloud-worker/pi/dirextalk-result.ts | awk '{print $1}')" \
    && DTX_HOST_POLICY_DIGEST="$(sha256sum /out/rootfs/usr/local/share/dirextalk-cloud-worker/pi-egress.nft | awk '{print $1}')" \
    && DTX_PROXY_CA_DIGEST="$(sha256sum /out/rootfs/usr/local/share/dirextalk-cloud-worker/outbound-proxy-ca.pem | awk '{print $1}')" \
    && DTX_PI_DESCRIPTOR="$(printf '{"pi_version":"%s","pi_executable":"/usr/local/lib/dirextalk-cloud-worker/pi/pi","pi_executable_sha256":"%s","result_extension":"/usr/local/lib/dirextalk-cloud-worker/pi/dirextalk-result.ts","result_extension_sha256":"%s"}' "$PI_VERSION" "$PI_EXECUTABLE_SHA256" "$DTX_EXTENSION_DIGEST")" \
    && DTX_PI_DIGEST="$(printf '%s' "$DTX_PI_DESCRIPTOR" | sha256sum | awk '{print $1}')" \
    && printf '{"schema_version":"dirextalk.agent.cloud-worker-installation/v1","ami_digest":"%s","worker_digest":"%s","pi_digest":"%s","host_network_policy_sha256":"%s","outbound_proxy_trust_bundle_sha256":"%s","pi_version":"%s","worker_executable":"/usr/local/bin/dirextalk-cloud-worker","pi_executable":"/usr/local/lib/dirextalk-cloud-worker/pi/pi","pi_executable_sha256":"%s","result_extension":"/usr/local/lib/dirextalk-cloud-worker/pi/dirextalk-result.ts","result_extension_sha256":"%s"}' \
        "$AMI_DIGEST" "$DTX_WORKER_DIGEST" "$DTX_PI_DIGEST" "$DTX_HOST_POLICY_DIGEST" "$DTX_PROXY_CA_DIGEST" "$PI_VERSION" "$PI_EXECUTABLE_SHA256" "$DTX_EXTENSION_DIGEST" \
        > /out/rootfs/usr/local/share/dirextalk-cloud-worker/installation.json \
    && chmod 0444 /out/rootfs/usr/local/share/dirextalk-cloud-worker/installation.json

FROM scratch
COPY --from=build /out/rootfs/ /
