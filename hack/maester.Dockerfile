# oathkeeper-maester v0.1.14 + w6d patch (atomic rules-file write, rewrite on NotFound).
FROM --platform=$BUILDPLATFORM golang:1.26 AS builder
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /go/src/app
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o manager main.go

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /go/src/app/manager .
USER 65532:65532
ENTRYPOINT ["/manager"]
