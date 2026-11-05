# Copyright 2026 The Agent Substrate Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Builds the provider image without ko: a static binary on the same
# distroless base .ko.yaml pins, at the path ko uses, running as nonroot.
#
#   docker build -t aws-sm-credential-provider .        (or: make image)
#
# The build downloads modules through GOPROXY. On a host that cannot reach the
# Go module proxy, run `go mod vendor` first: when vendor/ is present the
# build uses it and downloads nothing.

ARG GO_IMAGE=public.ecr.aws/docker/library/golang:1.27.3@sha256:0c050feb47802ae436b9030833694a0b80160d08e3b3049ad30bf7c9e724e09d
ARG BASE_IMAGE=gcr.io/distroless/static-debian13:latest@sha256:15f8637509792e05b97d83451b0b6ccfa4abd548f997e406ac1e72c87fe1fa78

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
# The release tag stamped into main.version; empty reports "dev".
ARG VERSION=""
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    if [ ! -f vendor/modules.txt ]; then go mod download; fi && \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/aws-sm-credential-provider ./cmd/aws-sm-credential-provider

FROM ${BASE_IMAGE}
COPY --from=build /out/aws-sm-credential-provider /ko-app/aws-sm-credential-provider
USER 65532:65532
ENTRYPOINT ["/ko-app/aws-sm-credential-provider"]
