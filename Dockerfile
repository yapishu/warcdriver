FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY app/go.mod app/go.sum /src/
RUN go mod download
COPY app/main.go .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/warcer ./...

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /out/warcer /warcer
COPY --from=setup --chown=1000:1000 /data /data
USER 1000:1000
EXPOSE 8808
ENTRYPOINT ["/warcdrive"]
