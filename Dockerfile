FROM node:24-alpine AS frontend
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY app/go.mod app/go.sum /src/
RUN go mod download
COPY app/ ./
COPY --from=frontend /frontend/dist ./frontend/dist
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/warcdriver .
RUN mkdir -p /data

FROM gcr.io/distroless/static
COPY --from=builder /out/warcdriver /warcdriver
COPY --from=builder /data /data
EXPOSE 8808
ENTRYPOINT ["/warcdriver"]
