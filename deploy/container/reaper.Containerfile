ARG GO_BUILD_BASE
ARG REAPER_RUNTIME_BASE
FROM --platform=linux/amd64 ${GO_BUILD_BASE} AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION
ARG REVISION
WORKDIR /src

RUN apk add --no-cache grep \
    && printf '%s' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+-(alpha|beta|rc)([.-][A-Za-z0-9][A-Za-z0-9.-]*)?-[0-9a-f]{7,40}$' \
    && printf '%s' "$REVISION" | grep -Eq '^[0-9a-f]{40}$' \
    && test "$VERSION" != 'v1.0.3'
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -tags lambda.norpc,netgo,osusergo -ldflags='-s -w -buildid=' \
    -o /out/bootstrap ./cmd/dirextalk-aws-reaper

FROM --platform=linux/amd64 ${REAPER_RUNTIME_BASE}
ARG VERSION
ARG REVISION
LABEL org.opencontainers.image.title="Dirextalk AWS Reaper" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION"
COPY --from=build /out/bootstrap /var/task/bootstrap
ENTRYPOINT ["/var/task/bootstrap"]
