FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY api/ api/
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /site-operator ./cmd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /site-operator /site-operator
USER 65532:65532
ENTRYPOINT ["/site-operator"]
