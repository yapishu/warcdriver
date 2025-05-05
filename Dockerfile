FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY app/go.mod app/go.sum /src/
RUN go mod download
COPY app/main.go .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/warcdriver ./...

FROM gcr.io/distroless/static
COPY --from=builder /out/warcdriver /warcdriver
RUN mkdir /data
EXPOSE 8808
ENTRYPOINT ["/warcdriver"]
