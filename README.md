# vuln-notes-api

A deliberately vulnerable Go microservice used as a target for CI/CD
security scans. 

## Run

```bash
go run .                                 # listens on :8080 (override with ADDR)
curl -s http://localhost:8080/health
```

## Test

```bash
go test ./...                            # 43 tests
go test ./... -v -run SQLInjection       # only the SQLi demos
```

## Endpoint reference

| Method | Path             | Purpose                       | Built-in vulnerability                    |
| ------ | ---------------- | ----------------------------- | ----------------------------------------- |
| GET    | `/health`        | liveness                      | —                                         |
| POST   | `/register`      | create user                   | MD5 password hashing, no salt             |
| POST   | `/login`         | issue JWT                     | **SQL injection** via username concat     |
| GET    | `/users/{id}`    | fetch user                    | **SQL injection** via path concat         |
| GET    | `/notes?q=`      | list / search notes           | **SQL injection** via `LIKE` concat       |
| POST   | `/notes`         | create note                   | no auth check                             |
| GET    | `/files?path=`   | read file from `/tmp/files`   | **path traversal** (no containment)       |
| GET    | `/exec?cmd=`     | run shell command             | **command injection** (`/bin/sh -c`)      |
| GET    | `/fetch?url=`    | proxy fetch                   | **SSRF** (no allowlist)                   |
| GET    | `/render?msg=`   | render message as HTML        | **reflected XSS**                         |
| GET    | `/redirect?to=`  | redirect                      | **open redirect**                         |
| GET    | `/admin/users`   | list all users                | **broken access control** (no auth)       |
| POST   | `/config`        | upload YAML config            | YAML deser on vulnerable `yaml.v2` v2.2.2 |

## Built-in code-level vulnerabilities

| # | Class                       | Where                            |
| - | --------------------------- | -------------------------------- |
| 1 | SQL injection               | `handlers.go` (`handleLogin`, `handleGetUser`, `handleNotes`) |
| 2 | Command injection           | `handlers.go` (`handleExec`)     |
| 3 | Path traversal              | `handlers.go` + `fs.go`          |
| 4 | SSRF                        | `handlers.go` (`handleFetch`)    |
| 5 | Reflected XSS               | `handlers.go` (`handleRender`)   |
| 6 | Open redirect               | `handlers.go` (`handleRedirect`) |
| 7 | Broken access control       | `handlers.go` (`handleAdminUsers`) |
| 8 | Weak crypto (MD5, no salt)  | `auth.go` (`weakHash`)           |
| 9 | Hardcoded secret            | `auth.go` (`JWTSecret`)          |
| 10 | JWT signing-method not verified | `auth.go` (`parseToken`)    |
| 11 | Verbose error leakage       | `handlers.go` (`writeErr`)       |

## Built-in dependency (SCA) vulnerabilities

Pinned to versions with public CVEs so SCA tools have something to report:

| Package                          | Version           | Example CVE       |
| -------------------------------- | ----------------- | ----------------- |
| `github.com/dgrijalva/jwt-go`    | `v3.2.0`          | CVE-2020-26160    |
| `gopkg.in/yaml.v2`               | `v2.2.2`          | CVE-2019-11254    |

## Running the SQLi demo by hand

```bash
# Login bypass
curl -s -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin'"'"' OR '"'"'1'"'"'='"'"'1'"'"' --","password":"anything"}'
```

## Container build

```dockerfile
FROM golang:1.22 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/vuln-notes-api .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/vuln-notes-api /vuln-notes-api
EXPOSE 8080
ENTRYPOINT ["/vuln-notes-api"]
```
