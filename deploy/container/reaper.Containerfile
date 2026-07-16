# syntax=docker/dockerfile:1.7

FROM --platform=linux/amd64 docker.io/library/golang:1.26.0-alpine@sha256:7c6a62c80c3f15fb49aae282d7a296149889ebe39b2318f3a299f2759c1ce135 AS build
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

FROM --platform=linux/amd64 public.ecr.aws/lambda/provided:al2023@sha256:f91e5c83528080b2e41d22536d413042e451e67968c7473c4f7e77a627c944bc
ARG VERSION
ARG REVISION
LABEL org.opencontainers.image.title="Dirextalk AWS Reaper" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION"
COPY --from=build /out/bootstrap /var/task/bootstrap
ENTRYPOINT ["/var/task/bootstrap"]
