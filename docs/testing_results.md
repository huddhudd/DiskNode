# Test Run Summary

This run was executed in the Linux CI container using Go 1.24.5 with the module cache pre-populated.

## Commands

```bash
GOPROXY=off go test ./...
```

## Results

* `saveserver/cmd/integration` – **FAIL**: `TestFullFlow` cannot reach a running nvserver instance on `127.0.0.1:8080`, returning `dial tcp 127.0.0.1:8080: connect: connection refused`.
* `saveserver/nvfiles` – **PASS**
* `saveserver/nvservice/listdata` – **PASS**
* `saveserver/nvservice/server` – **PASS**
* `saveserver/nvservice/storage` – **PASS**

Packages without test files are omitted from the result summary.

> **Note:** The integration suite requires a Windows nvserver configured with `CloudStart.ini` to be running locally before executing `go test ./...`. Without that service the HTTP requests fail immediately, as seen above.
