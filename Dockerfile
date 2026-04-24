FROM golang:1.24 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ebpf-firewall ./cmd/ebpf-firewall

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/ebpf-firewall /ebpf-firewall

USER 0:0
ENTRYPOINT ["/ebpf-firewall"]
