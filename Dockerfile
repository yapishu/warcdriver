FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY app/go.mod app/go.sum /src/
RUN go mod download
COPY app/main.go .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/warcdriver ./...
ARG USER_ID=1000
ARG GROUP_ID=1000
RUN mkdir -p /data && chown -R ${USER_ID}:${GROUP_ID} /data

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /out/warcdriver /warcdriver
ARG USER_ID=1000
ARG GROUP_ID=1000
COPY --from=builder --chown=${USER_ID}:${GROUP_ID} /data /data
USER ${USER_ID}:${GROUP_ID}
EXPOSE 8808
ENTRYPOINT ["/warcdriver"]