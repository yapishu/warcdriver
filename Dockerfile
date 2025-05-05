FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY app/go.mod app/go.sum /src/
RUN go mod download
COPY app/main.go .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/warcdriver ./...
RUN mkdir -p /data && chown -R 1000:1000 /data

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /out/warcdriver /warcdriver
COPY --from=builder --chown=1000:1000 /data /data
USER 1000:1000
EXPOSE 8808
ENTRYPOINT ["/warcdriver"]
