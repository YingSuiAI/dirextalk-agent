# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.26.0
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -tags lambda.norpc,netgo,osusergo -ldflags='-s -w -buildid=' \
    -o /out/bootstrap ./cmd/dirextalk-aws-reaper

FROM public.ecr.aws/lambda/provided:al2023
COPY --from=build /out/bootstrap /var/task/bootstrap
ENTRYPOINT ["/var/task/bootstrap"]
