FROM golang:1.24 AS build
WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/e2e-http-server main.go

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/e2e-http-server /e2e-http-server
USER 65532:65532
ENTRYPOINT ["/e2e-http-server"]
