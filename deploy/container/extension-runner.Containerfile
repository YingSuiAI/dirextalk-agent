# The runner is a separate image and UID boundary. It contains no Agent
# command dispatch and never receives the host Docker socket.
FROM --platform=linux/amd64 docker.io/library/golang:1.26.0-alpine@sha256:7c6a62c80c3f15fb49aae282d7a296149889ebe39b2318f3a299f2759c1ce135 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags netgo,osusergo -ldflags='-s -w -buildid=' -o /out/usr/local/bin/dirextalk-extension-runner ./cmd/dirextalk-extension-runner
RUN install -d -m 0770 -o 65531 -g 65532 /out/run/dirextalk-agent \
    && install -d -m 0700 -o 65531 -g 65531 /out/var/lib/dirextalk-agent/extension-install \
    /out/var/lib/dirextalk-agent/extension-workspaces /out/var/lib/dirextalk-agent/extension-state

FROM scratch
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="Dirextalk Extension Runner" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION"
COPY --from=build /out/ /
USER 65531:65531
ENTRYPOINT ["/usr/local/bin/dirextalk-extension-runner"]
CMD ["serve"]
