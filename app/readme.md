# WARCdriver Go service

This directory contains the Go archive service.

- `main.go` starts the HTTP server, SQLite store, auth bootstrap, filter engine, and background workers.
- `openapi.yaml` at the repo root is the API source of truth.
- `internal/api/openapi.gen.go` is generated with `oapi-codegen`.
- `browsertrix.go` writes Browsertrix job configs and imports WACZ/WARC output from the worker.
- `frontend/dist/` contains the embedded catalog UI build. Source lives in the repo-level `frontend/` package.

Run checks from this directory:

```bash
go test ./...
go build ./...
```
