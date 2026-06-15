# vuln-notes-api

A deliberately vulnerable Go microservice used as a target for Harness CI/CD
security scans (SAST, SCA, STO, DAST). Pure stdlib + an in-memory store, so it
compiles in seconds. **Do not deploy outside an isolated lab.**

## Run

```bash
go run .                                 # listens on :8080 (override with ADDR)
curl -s http://localhost:8080/health
```

## Test

```bash
go test ./...                            # 47 tests, ~250ms
```

## Endpoint reference

| Method | Path              | Purpose                       | Built-in vulnerability                    |
| ------ | ----------------- | ----------------------------- | ----------------------------------------- |
| GET    | `/health`         | liveness                      | —                                         |
| POST   | `/register`       | create user                   | MD5 password hashing, no salt             |
| POST   | `/login`          | issue JWT                     | weak crypto + hardcoded JWT secret        |
| GET    | `/users/{id}`     | fetch user                    | verbose error leakage                     |
| GET    | `/notes?q=`       | list / search notes           | no auth check on create                   |
| POST   | `/notes`          | create note                   | no auth check                             |
| GET    | `/notes/search`   | regex search                  | **ReDoS** (caller controls pattern)       |
| GET    | `/files?path=`    | read file from `/tmp/files`   | **path traversal**                        |
| GET    | `/exec?cmd=`      | run shell command             | **command injection** (`/bin/sh -c`)      |
| GET    | `/fetch?url=`     | proxy fetch                   | **SSRF** (no allowlist)                   |
| GET    | `/render?msg=`    | render message as HTML        | **reflected XSS**                         |
| GET    | `/redirect?to=`   | redirect                      | **open redirect**                         |
| GET    | `/admin/users`    | list all users                | **broken access control** (no auth)       |
| POST   | `/config`         | upload YAML config            | YAML deser on vulnerable `yaml.v2` v2.2.2 |
| GET    | `/csrf`           | issue CSRF token              | **insecure random** (constant seed)       |

## Built-in code-level vulnerabilities

| # | Class                              | Where                          |
| - | ---------------------------------- | ------------------------------ |
| 1 | Command injection                  | `handlers.go` (`handleExec`)   |
| 2 | Path traversal                     | `handlers.go` + `fs.go`        |
| 3 | SSRF                               | `handlers.go` (`handleFetch`)  |
| 4 | Reflected XSS                      | `handlers.go` (`handleRender`) |
| 5 | Open redirect                      | `handlers.go` (`handleRedirect`) |
| 6 | Broken access control              | `handlers.go` (`handleAdminUsers`) |
| 7 | ReDoS                              | `handlers.go` (`handleNotesSearch`) |
| 8 | Weak crypto (MD5, no salt)         | `auth.go` (`weakHash`)         |
| 9 | Hardcoded secret                   | `auth.go` (`JWTSecret`)        |
| 10 | JWT signing-method not verified    | `auth.go` (`parseToken`)      |
| 11 | Verbose error leakage              | `handlers.go` (`writeErr`)    |
| 12 | Insecure random for security token | `handlers.go` (`insecureRNG`) |

## Built-in dependency (SCA) vulnerabilities

| Package                       | Version  | Example CVE     |
| ----------------------------- | -------- | --------------- |
| `github.com/dgrijalva/jwt-go` | `v3.2.0` | CVE-2020-26160  |
| `gopkg.in/yaml.v2`            | `v2.2.2` | CVE-2019-11254  |

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
