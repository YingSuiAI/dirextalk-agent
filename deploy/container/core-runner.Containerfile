# Offline Core Runner: the only executable supplied to workload shells is the
# static BusyBox binary copied into a verified, runner-owned install tree.
FROM --platform=linux/amd64 docker.io/library/golang:1.26.0-alpine@sha256:7c6a62c80c3f15fb49aae282d7a296149889ebe39b2318f3a299f2759c1ce135 AS build
WORKDIR /src
RUN apk add --no-cache busybox-static
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags netgo,osusergo -ldflags='-s -w -buildid=' -o /out/usr/local/bin/dirextalk-core-runner ./cmd/dirextalk-core-runner \
    && install -D -m 0555 -o 65530 -g 65530 /bin/busybox.static /out/usr/local/libexec/dirextalk-core-shell \
    && install -d -m 0700 -o 65530 -g 65530 /out/var/lib/dirextalk-core-runner/installs /out/var/lib/dirextalk-core-runner/workspaces /out/var/lib/dirextalk-core-runner/state
FROM scratch
COPY --from=build /out/ /
USER 65530:65530
WORKDIR /var/lib/dirextalk-core-runner
ENTRYPOINT ["/usr/local/bin/dirextalk-core-runner"]
CMD ["serve"]
