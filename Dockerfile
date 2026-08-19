FROM golang:1.26-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -buildid=" -o /out/gateway ./cmd/gateway

FROM scratch
COPY --from=build /out/gateway /gateway

USER 65532:65532
EXPOSE 19090 18080
HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
    CMD ["/gateway", "healthcheck"]

ENTRYPOINT ["/gateway"]
