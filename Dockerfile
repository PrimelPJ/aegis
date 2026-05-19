# Multi-stage build producing a minimal, non-root image.
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/aegisd ./cmd/aegisd && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/aegis-verify ./cmd/aegis-verify

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/aegisd /aegisd
COPY --from=build /out/aegis-verify /aegis-verify
COPY configs/rules.json /etc/aegis/rules.json
VOLUME ["/data"]
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/aegisd", "-addr", ":8080", "-data", "/data", "-rules", "/etc/aegis/rules.json"]
